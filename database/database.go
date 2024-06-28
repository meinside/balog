package database

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/meinside/ipgeolocation.io-go"

	"github.com/meinside/balog/util"
)

const (
	UnknownLocation = "Unknown"

	SlowQueryThresholdSeconds = 10

	ProjectURL = "https://github.com/meinside/balog"
)

// BanActionLog represents a log of ban action
type BanActionLog struct {
	gorm.Model

	Protocol  string    `gorm:"index:idx_logs_1;index:idx_logs_2"`
	CreatedAt time.Time `gorm:"index:idx_logs_3;index:idx_logs_2"`
	IP        string    `gorm:"index:idx_logs_4"`

	Location *string
}

// Location represents location of an ip
type Location struct {
	gorm.Model

	IP          string `gorm:"unique;index:idx_locations_1"`
	CountryName string `gorm:"index:idx_locations_2"`
}

// Database struct
type Database struct {
	db *gorm.DB
}

// Report represents a report of ban action logs
type Report struct {
	ReferenceDatetime string    `json:"reference_datetime"`
	Last7Days         SubReport `json:"last_7_days"`
	Last30Days        SubReport `json:"last_30_days"`
}

type keyValue struct {
	Key   string
	Value int
}

type keyValues []keyValue

func (kvs *keyValues) Set(key string, value int) {
	for i, kv := range *kvs {
		if kv.Key == key {
			(*kvs)[i].Value = value
			return
		}
	}

	*kvs = append(*kvs, keyValue{
		Key:   key,
		Value: value,
	})
}

func (kvs *keyValues) Get(key string) (value int, exists bool) {
	for _, kv := range *kvs {
		if kv.Key == key {
			return kv.Value, true
		}
	}

	return 0, false
}

func sortKeyValues(kvs keyValues) keyValues {
	sorted := keyValues{}
	for _, kv := range kvs {
		sorted = append(sorted, keyValue{kv.Key, kv.Value})
	}

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Value > sorted[j].Value
	})

	return sorted
}

// SubReport represents a sub report of a Report
type SubReport struct {
	TotalCount     int       `json:"total_count"`
	ProtocolCounts keyValues `json:"protocol_counts"`
	CountryCounts  keyValues `json:"country_counts"`
}

// Open database from given path
func Open(path string) (result *Database, err error) {
	var db *gorm.DB
	if db, err = gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags),
			logger.Config{
				SlowThreshold:             SlowQueryThresholdSeconds * time.Second,
				LogLevel:                  logger.Warn,
				IgnoreRecordNotFoundError: true,
				ParameterizedQueries:      true,
				Colorful:                  false,
			},
		),
	}); err == nil {
		// migrate database
		if err := db.AutoMigrate(&BanActionLog{}, &Location{}); err != nil {
			util.Log("Failed to migrate database: %s", err)
		}

		return &Database{db}, nil
	}

	return nil, err
}

// Close database
func (d *Database) Close() {
	if db, err := d.db.DB(); err == nil {
		db.Close()
	}
}

// SaveBanAction to local database
func (d *Database) SaveBanAction(protocol, ip string) (id uint, err error) {
	bal := BanActionLog{
		Protocol:  protocol,
		CreatedAt: time.Now(),
		IP:        ip,
	}
	res := d.db.Create(&bal)

	return bal.ID, res.Error
}

func (d *Database) UpdateBanActionLocation(id uint, location string) (err error) {
	res := d.db.Model(&BanActionLog{}).Where(id).Update("location", location)

	return res.Error
}

// LookupLocation from local database
func (d *Database) LookupLocation(ip string) (result Location, err error) {
	res := d.db.Limit(1).Where("ip = ?", ip).Find(&result)

	return result, res.Error
}

func (d *Database) UpdateLocation(ip, location string) (err error) {
	res := d.db.Model(&Location{}).Where("ip = ?", ip).Update("country_name", location)

	return res.Error
}

// SaveLocation to local database
func (d *Database) SaveLocation(ip, location string) (id uint, err error) {
	loc := Location{
		IP:          ip,
		CountryName: location,
	}
	res := d.db.Create(&loc)

	return loc.ID, res.Error
}

// generate report data (`offsetDays` in number of days; positive for future, negative for past)
func (d *Database) generateReport(offsetDays int) (result Report, err error) {
	timestamp := time.Now().AddDate(0, 0, offsetDays)

	result = Report{
		ReferenceDatetime: timestamp.Format("2006-01-02 15:04:05"),
		Last7Days: SubReport{
			ProtocolCounts: keyValues{},
			CountryCounts:  keyValues{},
		},
		Last30Days: SubReport{
			ProtocolCounts: keyValues{},
			CountryCounts:  keyValues{},
		},
	}

	var oldCount int

	// last 7 days
	var last7Days []BanActionLog
	if res := d.db.Model(&BanActionLog{}).Where("created_at >= ?", time.Now().AddDate(0, 0, offsetDays-7)).Find(&last7Days); res.Error == nil {
		// total count
		result.Last7Days.TotalCount = len(last7Days)

		for _, log := range last7Days {
			// counts for protocols
			oldCount, _ = result.Last7Days.ProtocolCounts.Get(log.Protocol)
			result.Last7Days.ProtocolCounts.Set(log.Protocol, oldCount+1)

			// counts for countries
			if log.Location != nil {
				oldCount, _ = result.Last7Days.CountryCounts.Get(*log.Location)
				result.Last7Days.CountryCounts.Set(*log.Location, oldCount+1)
			}
		}
	} else {
		return result, res.Error
	}

	// last 30 days
	var last30Days []BanActionLog
	if res := d.db.Model(&BanActionLog{}).Where("created_at >= ?", time.Now().AddDate(0, 0, offsetDays-30)).Find(&last30Days); res.Error == nil {
		result.Last30Days.TotalCount = len(last30Days)

		for _, log := range last30Days {
			// counts for protocols
			oldCount, _ = result.Last30Days.ProtocolCounts.Get(log.Protocol)
			result.Last30Days.ProtocolCounts.Set(log.Protocol, oldCount+1)

			// counts for countries
			if log.Location != nil {
				oldCount, _ = result.Last30Days.CountryCounts.Get(*log.Location)
				result.Last30Days.CountryCounts.Set(*log.Location, oldCount+1)
			}
		}
	} else {
		return result, res.Error
	}

	return result, err
}

// GetReportAsPlain generates report in plain text format.
func (d *Database) GetReportAsPlain(offsetDays int) (result []byte, err error) {
	// generate report text
	var report Report
	if report, err = d.generateReport(offsetDays); err == nil {
		protocols7 := []string{}
		for _, kv := range sortKeyValues(report.Last7Days.ProtocolCounts) {
			protocols7 = append(protocols7, fmt.Sprintf("  %s: %d", kv.Key, kv.Value))
		}
		countries7 := []string{}
		for _, kv := range sortKeyValues(report.Last7Days.CountryCounts) {
			countries7 = append(countries7, fmt.Sprintf("  %s: %d", kv.Key, kv.Value))
		}
		protocols30 := []string{}
		for _, kv := range report.Last30Days.ProtocolCounts {
			protocols30 = append(protocols30, fmt.Sprintf("  %s: %d", kv.Key, kv.Value))
		}
		countries30 := []string{}
		for _, kv := range report.Last30Days.CountryCounts {
			countries30 = append(countries30, fmt.Sprintf("  %s: %d", kv.Key, kv.Value))
		}

		return []byte(fmt.Sprintf(`
Reference datetime: %[1]s

Last 7 days
---
* Total: %[2]d ban action(s)

* Protocols:
%[3]s

* Countries:
%[4]s


Last 30 days:
---
* Total: %[5]d ban action(s)

* Protocols:
%[6]s

* Countries:
%[7]s
`,
			report.ReferenceDatetime,
			report.Last7Days.TotalCount, strings.Join(protocols7, "\n"), strings.Join(countries7, "\n"),
			report.Last30Days.TotalCount, strings.Join(protocols30, "\n"), strings.Join(countries30, "\n"),
		)), nil
	}

	return []byte{}, err
}

// GetReportAsJSON generates report in json format.
func (d *Database) GetReportAsJSON(offsetDays int) (result []byte, err error) {
	var report Report
	if report, err = d.generateReport(offsetDays); err == nil {
		var bytes []byte
		if bytes, err = json.Marshal(report); err == nil {
			return bytes, nil
		}
	}

	return []byte{}, err
}

// GetReportAsTelegraph generates html report for posting to telegra.ph.
func (d *Database) GetReportAsTelegraph(telegraphAccessToken *string, offsetDays int) (result []byte, err error) {
	var report Report
	if report, err = d.generateReport(offsetDays); err == nil {
		// generate report html
		sort.Slice(report.Last7Days.ProtocolCounts, func(i, j int) bool {
			return report.Last7Days.ProtocolCounts[i].Value > report.Last7Days.ProtocolCounts[j].Value
		})
		protocols7 := []string{}
		for _, kv := range sortKeyValues(report.Last7Days.ProtocolCounts) {
			protocols7 = append(protocols7, fmt.Sprintf("• %s: %d", kv.Key, kv.Value))
		}
		countries7 := []string{}
		for _, kv := range sortKeyValues(report.Last7Days.CountryCounts) {
			countries7 = append(countries7, fmt.Sprintf("• %s: %d", kv.Key, kv.Value))
		}
		protocols30 := []string{}
		for _, kv := range sortKeyValues(report.Last30Days.ProtocolCounts) {
			protocols30 = append(protocols30, fmt.Sprintf("• %s: %d", kv.Key, kv.Value))
		}
		countries30 := []string{}
		for _, kv := range sortKeyValues(report.Last30Days.CountryCounts) {
			countries30 = append(countries30, fmt.Sprintf("• %s: %d", kv.Key, kv.Value))
		}

		html := fmt.Sprintf(
			`<h4>Report (reference datetime: %[1]s)</h4>

<p>
<h4>Last 7 days</h4>

<strong>Total</strong> %[2]d ban action(s)

<strong>Protocols</strong>
%[3]s

<strong>Countries</strong>
%[4]s
</p>
<p>
<h4>Last 30 days</h4>

<strong>Total</strong> %[5]d ban action(s)

<strong>Protocols</strong>
%[6]s

<strong>Countries</strong>
%[7]s
</p>

generated by <a href="%[8]s">balog</a>`,
			report.ReferenceDatetime,
			report.Last7Days.TotalCount, strings.Join(protocols7, "\n"), strings.Join(countries7, "\n"),
			report.Last30Days.TotalCount, strings.Join(protocols30, "\n"), strings.Join(countries30, "\n"),
			ProjectURL,
		)

		// debug log
		//util.Log("Telegraph HTML: %s\n", html)

		return []byte(html), err
	}

	return []byte{}, err
}

// ListUnknownIPs returns list of ips where their locations are unknown.
func (d *Database) ListUnknownIPs() (result []Location, err error) {
	res := d.db.Model(&Location{}).Where("country_name = ?", UnknownLocation).Find(&result)

	return result, res.Error
}

// ResolveUnknownIPs lists unknown ips, tries resolving them, and then returns them.
func (d *Database) ResolveUnknownIPs(geolocAPIKey *string) (result []Location, err error) {
	result = []Location{}

	locations, err := d.ListUnknownIPs()
	if err == nil {
		for _, loc := range locations {
			location, err := FetchLocation(geolocAPIKey, loc.IP)
			// FIXME: no error, but location is empty (eg. reserved ips like "127.0.0.1")
			if err == nil && location != "" {
				if err = d.UpdateLocation(loc.IP, location); err == nil {
					loc.CountryName = location
				}
			}

			result = append(result, loc)
		}
	}

	return result, err
}

// PurgeLogs deletes all logs.
func (d *Database) PurgeLogs() (result int64, err error) {
	res := d.db.Delete(&BanActionLog{})

	return res.RowsAffected, res.Error
}

// FetchLocation fetches location from ipgeolocation.io.
func FetchLocation(geolocAPIKey *string, ip string) (location string, err error) {
	if geolocAPIKey != nil {
		client := ipgeolocation.NewClient(*geolocAPIKey)
		var result ipgeolocation.ResponseGeolocation
		if result, err = client.GetGeolocation(ip); err == nil {
			return result.CountryName, nil
		}
	}

	return UnknownLocation, err
}
