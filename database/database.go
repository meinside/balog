package database

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/meinside/ipapi-go"
	"github.com/meinside/telegraph-go"

	"github.com/meinside/balog/util"
)

const (
	UnknownLocation = "Unknown"
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
	Last7Days  SubReport `json:"last_7_days"`
	Last30Days SubReport `json:"last_30_days"`
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
	if db, err = gorm.Open(sqlite.Open(path), &gorm.Config{}); err == nil {
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

// generate report data
func (d *Database) generateReport() (result Report, err error) {
	result = Report{
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
	if res := d.db.Model(&BanActionLog{}).Where("created_at >= ?", time.Now().AddDate(0, 0, -7)).Find(&last7Days); res.Error == nil {
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
	if res := d.db.Model(&BanActionLog{}).Where("created_at >= ?", time.Now().AddDate(0, 0, -30)).Find(&last30Days); res.Error == nil {
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

// GetReportAsPlain generates report in plain text format
func (d *Database) GetReportAsPlain() (result []byte, err error) {
	// generate report text
	var report Report
	if report, err = d.generateReport(); err == nil {
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
Last 7 days
---
* Total: %d ban action(s)

* Protocols:
%s

* Countries:
%s


Last 30 days:
---
* Total: %d ban action(s)

* Protocols:
%s

* Countries:
%s
`,
			report.Last7Days.TotalCount, strings.Join(protocols7, "\n"), strings.Join(countries7, "\n"),
			report.Last30Days.TotalCount, strings.Join(protocols30, "\n"), strings.Join(countries30, "\n"),
		)), nil
	}

	return []byte{}, err
}

// GetReportAsJSON generates report in json format
func (d *Database) GetReportAsJSON() (result []byte, err error) {
	var report Report
	if report, err = d.generateReport(); err == nil {
		var bytes []byte
		if bytes, err = json.Marshal(report); err == nil {
			return bytes, nil
		}
	}

	return []byte{}, err
}

// GetReportAsTelegraph generates report and post it to telegraph
func (d *Database) GetReportAsTelegraph(telegraphAccessToken *string) (result []byte, err error) {
	var report Report
	if report, err = d.generateReport(); err == nil {
		var client *telegraph.Client

		if telegraphAccessToken == nil {
			client, err = telegraph.Create("balog", "Ban Action Logger", "")
			if err == nil {
				util.LogAndExit(0, "Add '%s' to your balog's configuration file with key `telegraph_access_token`", client.AccessToken)
			} else {
				util.LogAndExit(1, "Failed to create telegraph client: %s", err)
			}
		}

		// get hostname
		hostname, _ := os.Hostname()

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

		timestamp := time.Now().Format("2006-01-02 15:04:05")

		html := fmt.Sprintf(
			`<h4>Report: %s</h4>

<p>
<h4>Last 7 days</h4>

<strong>Total</strong> %d ban action(s)

<strong>Protocols</strong>
%s

<strong>Countries</strong>
%s
</p>
<p>
<h4>Last 30 days</h4>

<strong>Total</strong> %d ban action(s)

<strong>Protocols</strong>
%s

<strong>Countries</strong>
%s
</p>

generated by <a href="https://github.com/meinside/balog">balog</a>`,
			timestamp,
			report.Last7Days.TotalCount, strings.Join(protocols7, "\n"), strings.Join(countries7, "\n"),
			report.Last30Days.TotalCount, strings.Join(protocols30, "\n"), strings.Join(countries30, "\n"),
		)

		// debug log
		//util.Log("Telegraph HTML: %s\n", html)

		client, err = telegraph.Load(*telegraphAccessToken)
		if err == nil {
			var title string
			if len(hostname) > 0 {
				title = fmt.Sprintf("(%s) Balog Report: %s", hostname, timestamp)
			} else {
				title = fmt.Sprintf("Balog Report: %s", timestamp)
			}

			var post telegraph.Page
			if post, err = client.CreatePageWithHTML(
				title,
				"balog",
				"",
				html,
				//false,
				true,
			); err == nil {
				return []byte(fmt.Sprintf("https://telegra.ph/%s", post.Path)), nil
			}
		} else {
			util.LogAndExit(1, "Failed to load telegraph client: %s", err)
		}
	}

	return []byte{}, err
}

// ListUnknownIPs returns list of ips where their locations are unknown
func (d *Database) ListUnknownIPs() (result []Location, err error) {
	res := d.db.Model(&Location{}).Where("country_name = ?", UnknownLocation).Find(&result)

	return result, res.Error
}

// ResolveUnknownIPs lists unknown ips, tries resolving them, and then returns them
func (d *Database) ResolveUnknownIPs() (result []Location, err error) {
	result = []Location{}

	locations, err := d.ListUnknownIPs()
	if err == nil {
		for _, loc := range locations {
			location, err := FetchLocation(loc.IP)
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

// PurgeLogs deletes all logs
func (d *Database) PurgeLogs() (result int64, err error) {
	res := d.db.Delete(&BanActionLog{})

	return res.RowsAffected, res.Error
}

// FetchLocation from ipapi.co
func FetchLocation(ip string) (location string, err error) {
	var result ipapi.Response
	if result, err = ipapi.GetLocation(ip); err == nil {
		return result.CountryName, nil
	}

	return UnknownLocation, err
}
