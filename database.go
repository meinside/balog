// database.go

package main

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
)

const (
	unknownLocation = "Unknown"

	slowQueryThresholdSeconds = 10

	projectURL = "https://github.com/meinside/balog"

	googleAIModel = `gemini-2.5-flash`
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
	LastDaysReport1 SubReport `json:"last_days_report1"`
	LastDaysReport2 SubReport `json:"last_days_report2"`

	Insight *string `json:"insight,omitempty"`
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
	FromTo string `json:"from_to"`

	TotalCount int `json:"total_count"`

	ProtocolCounts keyValues `json:"protocol_counts"`
	CountryCounts  keyValues `json:"country_counts"`
}

// OpenDB opens database from given path.
func OpenDB(path string) (result *Database, err error) {
	var db *gorm.DB
	if db, err = gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.New(
			log.New(os.Stdout, "\r\n", log.LstdFlags),
			logger.Config{
				SlowThreshold:             slowQueryThresholdSeconds * time.Second,
				LogLevel:                  logger.Warn,
				IgnoreRecordNotFoundError: true,
				ParameterizedQueries:      true,
				Colorful:                  false,
			},
		),
	}); err == nil {
		// migrate database
		if err := db.AutoMigrate(&BanActionLog{}, &Location{}); err != nil {
			l("Failed to migrate database: %s", err)
		}

		return &Database{db}, nil
	}

	return nil, err
}

// CloseDB closes database.
func (d *Database) CloseDB() {
	if db, err := d.db.DB(); err == nil {
		_ = db.Close()
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
func (d *Database) generateReport(offsetDays, numDaysForReport1, numDaysForReport2 int) (result Report, err error) {
	timestamp := time.Now().AddDate(0, 0, offsetDays)

	result = Report{
		LastDaysReport1: SubReport{
			FromTo: fmt.Sprintf(
				"%s ~ %s",
				timestamp.AddDate(0, 0, -numDaysForReport1).Format("2006-01-02 15:04:05"),
				timestamp.Format("2006-01-02 15:04:05"),
			),
			ProtocolCounts: keyValues{},
			CountryCounts:  keyValues{},
		},
		LastDaysReport2: SubReport{
			FromTo: fmt.Sprintf(
				"%s ~ %s",
				timestamp.AddDate(0, 0, -numDaysForReport2).Format("2006-01-02 15:04:05"),
				timestamp.Format("2006-01-02 15:04:05"),
			),
			ProtocolCounts: keyValues{},
			CountryCounts:  keyValues{},
		},
	}

	var oldCount int

	// last `numDaysForReport1` days
	var lastDaysForReport1 []BanActionLog
	if res := d.db.Model(&BanActionLog{}).Where("created_at >= ?", time.Now().AddDate(0, 0, offsetDays-numDaysForReport1)).Find(&lastDaysForReport1); res.Error == nil {
		// total count
		result.LastDaysReport1.TotalCount = len(lastDaysForReport1)

		for _, log := range lastDaysForReport1 {
			// counts for protocols
			oldCount, _ = result.LastDaysReport1.ProtocolCounts.Get(log.Protocol)
			result.LastDaysReport1.ProtocolCounts.Set(log.Protocol, oldCount+1)

			// counts for countries
			if log.Location != nil {
				oldCount, _ = result.LastDaysReport1.CountryCounts.Get(*log.Location)
				result.LastDaysReport1.CountryCounts.Set(*log.Location, oldCount+1)
			}
		}
	} else {
		return result, res.Error
	}

	// last `numDaysForReport2` days
	var lastDaysForReport2 []BanActionLog
	if res := d.db.Model(&BanActionLog{}).Where("created_at >= ?", time.Now().AddDate(0, 0, offsetDays-numDaysForReport2)).Find(&lastDaysForReport2); res.Error == nil {
		result.LastDaysReport2.TotalCount = len(lastDaysForReport2)

		for _, log := range lastDaysForReport2 {
			// counts for protocols
			oldCount, _ = result.LastDaysReport2.ProtocolCounts.Get(log.Protocol)
			result.LastDaysReport2.ProtocolCounts.Set(log.Protocol, oldCount+1)

			// counts for countries
			if log.Location != nil {
				oldCount, _ = result.LastDaysReport2.CountryCounts.Get(*log.Location)
				result.LastDaysReport2.CountryCounts.Set(*log.Location, oldCount+1)
			}
		}
	} else {
		return result, res.Error
	}

	return result, err
}

// GetReportAsPlain generates report in plain text format.
func (d *Database) GetReportAsPlain(offsetDays, numDaysForReport1, numDaysForReport2 int) (result []byte, err error) {
	// generate report text
	var report Report
	if report, err = d.generateReport(offsetDays, numDaysForReport1, numDaysForReport2); err == nil {
		protocolsForReport1 := []string{}
		for _, kv := range sortKeyValues(report.LastDaysReport1.ProtocolCounts) {
			protocolsForReport1 = append(protocolsForReport1, fmt.Sprintf("  %s: %d", kv.Key, kv.Value))
		}
		countriesForReport1 := []string{}
		for _, kv := range sortKeyValues(report.LastDaysReport1.CountryCounts) {
			countriesForReport1 = append(countriesForReport1, fmt.Sprintf("  %s: %d", kv.Key, kv.Value))
		}
		protocolsForReport2 := []string{}
		for _, kv := range report.LastDaysReport2.ProtocolCounts {
			protocolsForReport2 = append(protocolsForReport2, fmt.Sprintf("  %s: %d", kv.Key, kv.Value))
		}
		countriesForReport2 := []string{}
		for _, kv := range report.LastDaysReport2.CountryCounts {
			countriesForReport2 = append(countriesForReport2, fmt.Sprintf("  %s: %d", kv.Key, kv.Value))
		}

		return fmt.Appendf(nil, `
>>> Generated Report:

> %[1]s (%[2]d days)
* Total: %[3]d ban action(s)

* Protocols:
%[4]s

* Originating Countries:
%[5]s
---

> %[6]s (%[7]d days)
* Total: %[8]d ban action(s)

* Protocols:
%[9]s

* Originating Countries:
%[10]s
---
`,
			report.LastDaysReport1.FromTo, numDaysForReport1, report.LastDaysReport1.TotalCount, strings.Join(protocolsForReport1, "\n"), strings.Join(countriesForReport1, "\n"),
			report.LastDaysReport2.FromTo, numDaysForReport2, report.LastDaysReport2.TotalCount, strings.Join(protocolsForReport2, "\n"), strings.Join(countriesForReport2, "\n"),
		), nil
	}

	return nil, err
}

// GetFinalReportAsPlain generates final report as plain text.
func (d *Database) GetFinalReportAsPlain(report, insight []byte) (result []byte) {
	if insight != nil {
		result = fmt.Appendf(nil, `%[1]s

===
* Generated insights (by %[3]s):

%[2]s`, string(report), string(insight), googleAIModel)
	} else {
		result = report
	}

	return result
}

// GetReportAsJSON generates report in json format.
func (d *Database) GetReportAsJSON(offsetDays, numDaysForReport1, numDaysForReport2 int) (result []byte, err error) {
	var report Report
	if report, err = d.generateReport(offsetDays, numDaysForReport1, numDaysForReport2); err == nil {
		var bytes []byte
		if bytes, err = json.Marshal(report); err == nil {
			return bytes, nil
		}
	}

	return nil, err
}

// GetFinalReportAsJSON generates final report as json.
func (d *Database) GetFinalReportAsJSON(report, insight []byte) (result []byte) {
	if insight != nil {
		var tempReport Report
		if err := json.Unmarshal(report, &tempReport); err == nil {
			str := string(insight)
			tempReport.Insight = &str

			if temp, err := json.Marshal(tempReport); err == nil {
				result = temp
			} else {
				result = report
			}
		}
	} else {
		result = report
	}

	return result
}

// GetReportAsTelegraph generates html report for posting to telegra.ph.
func (d *Database) GetReportAsTelegraph(telegraphAccessToken *string, offsetDays, numDaysForReport1, numDaysForReport2 int) (result []byte, err error) {
	var report Report
	if report, err = d.generateReport(offsetDays, numDaysForReport1, numDaysForReport2); err == nil {
		// generate report html
		sort.Slice(report.LastDaysReport1.ProtocolCounts, func(i, j int) bool {
			return report.LastDaysReport1.ProtocolCounts[i].Value > report.LastDaysReport1.ProtocolCounts[j].Value
		})
		protocolsForReport1 := []string{}
		for _, kv := range sortKeyValues(report.LastDaysReport1.ProtocolCounts) {
			protocolsForReport1 = append(protocolsForReport1, fmt.Sprintf("• %s: %d", kv.Key, kv.Value))
		}
		countriesForReport1 := []string{}
		for _, kv := range sortKeyValues(report.LastDaysReport1.CountryCounts) {
			countriesForReport1 = append(countriesForReport1, fmt.Sprintf("• %s: %d", kv.Key, kv.Value))
		}
		protocolsForReport2 := []string{}
		for _, kv := range sortKeyValues(report.LastDaysReport2.ProtocolCounts) {
			protocolsForReport2 = append(protocolsForReport2, fmt.Sprintf("• %s: %d", kv.Key, kv.Value))
		}
		countriesForReport2 := []string{}
		for _, kv := range sortKeyValues(report.LastDaysReport2.CountryCounts) {
			countriesForReport2 = append(countriesForReport2, fmt.Sprintf("• %s: %d", kv.Key, kv.Value))
		}

		html := fmt.Sprintf(
			`<h3>Generated Report</h3>

<p>
<h4>%[1]s (%[2]d days)</h4>

<strong>Total</strong> %[3]d ban action(s)

<strong>Protocols</strong>
%[4]s

<strong>Originating Countries</strong>
%[5]s
</p>
<p>
<h4>%[6]s (%[7]d days)</h4>

<strong>Total</strong> %[8]d ban action(s)

<strong>Protocols</strong>
%[9]s

<strong>Originating Countries</strong>
%[10]s
</p>

<i>report generated by <a href="%[10]s">balog</a></i>`,
			report.LastDaysReport1.FromTo, numDaysForReport1, report.LastDaysReport1.TotalCount, strings.Join(protocolsForReport1, "\n"), strings.Join(countriesForReport1, "\n"),
			report.LastDaysReport2.FromTo, numDaysForReport2, report.LastDaysReport2.TotalCount, strings.Join(protocolsForReport2, "\n"), strings.Join(countriesForReport2, "\n"),
			projectURL,
		)

		// debug log
		// l("Telegraph HTML: %s\n", html)

		return []byte(html), err
	}

	return nil, err
}

// GetFinalReportAsTelegraph generates final report for telegra.ph.
func (d *Database) GetFinalReportAsTelegraph(report, insight []byte) (result []byte) {
	if insight != nil {
		result = fmt.Appendf(nil, `%[1]s

<p>
<h4>Insights</h4>

%[2]s
</p>

<i>insights generated by <strong>%[3]s</strong></i>`, string(report), string(insight), googleAIModel)
	} else {
		result = report
	}

	return result
}

// ListUnknownIPs returns list of ips where their locations are unknown.
func (d *Database) ListUnknownIPs() (result []Location, err error) {
	res := d.db.Model(&Location{}).Where("country_name = ?", unknownLocation).Find(&result)

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

	return unknownLocation, err
}
