package cmdline

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"

	"github.com/meinside/balog/database"
	"github.com/meinside/balog/util"
)

const (
	configFilepath    = ".config/balog.json"
	defaultDBFilepath = ".config/balog.db"
)

const (
	paramAction   = "action"
	paramIP       = "ip"
	paramProtocol = "protocol"
	paramFormat   = "format"
	paramJob      = "job"
)

type action string

const (
	actionSave        action = "save"
	actionReport      action = "report"
	actionMaintenance action = "maintenance"
)

type reportFormat string

const (
	reportFormatPlain     reportFormat = "plain"
	reportFormatJSON      reportFormat = "json"
	reportFormatTelegraph reportFormat = "telegraph"
)

type maintenanceJob string

const (
	maintenanceJobListUnknownIPs    maintenanceJob = "list_unknown_ips"
	maintenanceJobResolveUnknownIPs maintenanceJob = "resolve_unknown_ips"
	maintenanceJobPurgeLogs         maintenanceJob = "purge_logs"
)

// config
type config struct {
	DBFilepath *string `json:"db_filepath,omitempty"`

	TelegraphAccessToken *string `json:"telegraph_access_token,omitempty"`
}

func init() {
	flag.Usage = ShowUsage
}

// ShowUsage prints usage
func ShowUsage() {
	util.LogAndExit(0, `Usage of %[1]s:

# save a ban action
$ %[1]s -action save -ip <ip> -protocol <name>

# generate a report (format = plain, json, telegraph)
$ %[1]s -action report -format <format>

# perform maintenance (job = list_unknown_ips, resolve_unknown_ips, purge_logs)
$ %[1]s -action maintenance -job <job>
`, os.Args[0])
}

// ProcessArgs processes command line arguments
func ProcessArgs(args []string) {
	if config, err := loadConfig(); err == nil {
		if config.DBFilepath == nil {
			homedir, _ := os.UserHomeDir()
			fallbackDBFilepath := filepath.Join(homedir, defaultDBFilepath)

			util.Log("`db_filepath` is missing in config file, using default: '%s'", fallbackDBFilepath)

			config.DBFilepath = &fallbackDBFilepath
		}

		db, err := database.Open(*config.DBFilepath)
		if err != nil {
			util.LogAndExit(1, "Failed to open database: %s", err)
		}

		// parse params
		var action *string = flag.String(paramAction, "", "Action to perform")
		var ip *string = flag.String(paramIP, "", "IP address of the ban action")
		var protocol *string = flag.String(paramProtocol, "", "Protocol of the ban action")
		var format *string = flag.String(paramFormat, "", "Output format of the report")
		var job *string = flag.String(paramJob, "", "Maintenance job to perform")
		flag.Parse()

		switch *action {
		case string(actionSave):
			checkArg(ip, actionSave)
			checkArg(protocol, actionSave)
			processSave(db, protocol, ip)
		case string(actionReport):
			checkArg(format, actionReport)
			processReport(db, format, config.TelegraphAccessToken)
		case string(actionMaintenance):
			checkArg(job, actionMaintenance)
			processMaintenance(db, job)
		default:
			util.Log("Unknown action was given: '%s'", *action)
			ShowUsage()
		}

	} else {
		util.LogAndExit(1, "Failed to load config: %s", err)
	}
}

// check argument's existence and exit program if it's missing
func checkArg(arg *string, action action) {
	if len(*arg) <= 0 {
		util.Log("Parameter `%s` is required for action '%s'", *arg, action)
		ShowUsage()
	}
}

// loadConfig loads config, if it doesn't exist, create it
func loadConfig() (cfg config, err error) {
	var homedir string
	homedir, err = os.UserHomeDir()
	if err == nil {
		confFilepath := filepath.Join(homedir, configFilepath)

		if _, err = os.Stat(confFilepath); err == nil {
			// read config file
			var bytes []byte
			if bytes, err = os.ReadFile(confFilepath); err == nil {
				if err = json.Unmarshal(bytes, &cfg); err == nil {
					return cfg, nil
				}
			}
		} else if os.IsNotExist(err) {
			// create a default config file
			var file *os.File
			if file, err = os.Create(confFilepath); err == nil {
				defer file.Close()

				dbFilepath := filepath.Join(homedir, defaultDBFilepath)
				cfg = config{
					DBFilepath: &dbFilepath,
				}

				// write default config
				var bytes []byte
				if bytes, err = json.Marshal(cfg); err == nil {
					if _, err = file.Write(bytes); err == nil {
						util.Log("Created default config file: '%s'", confFilepath)
					}
					return cfg, nil
				}
			}
		}
	}
	return cfg, err
}

func processSave(db *database.Database, protocol, ip *string) {
	// save,
	if id, err := db.SaveBanAction(*protocol, *ip); err != nil {
		util.LogAndExit(1, "Failed to save ban action: %s", err)
	} else {
		// then resolve its geo location
		if cached, err := db.LookupLocation(*ip); err == nil {
			var fetched string
			var err error
			// if there is no cache for it, fetch it from ipapi.co,
			if cached.ID == 0 {
				fetched, err = database.FetchLocation(*ip)
				if err != nil {
					util.Log("Failed to fetch location: %s", err)
				}

				if fetched == "" {
					fetched = database.UnknownLocation
				}

				// and save to cache
				if _, err = db.SaveLocation(*ip, fetched); err != nil {
					util.Log("Failed to save location for '%s': %s", *ip, err)
				}
			} else {
				fetched = cached.CountryName
			}

			// and update the ban action's location
			if err = db.UpdateBanActionLocation(id, fetched); err != nil {
				util.Log("Failed to update location of ban action '%d': %s", id, err)
			}
		} else {
			util.Log("Failed to lookup location of '%s': %s", *ip, err)
		}
	}
}

func processReport(db *database.Database, format *string, telegraphAccessToken *string) {
	var err error
	var bytes []byte

	switch *format {
	case string(reportFormatPlain):
		bytes, err = db.GetReportAsPlain()
	case string(reportFormatJSON):
		bytes, err = db.GetReportAsJSON()
	case string(reportFormatTelegraph):
		bytes, err = db.GetReportAsTelegraph(telegraphAccessToken)
	default:
		util.Log("Unknown format was given: '%s'", *format)
		ShowUsage()
	}

	if err != nil {
		util.LogAndExit(1, "Failed to generate report: %s", err)
	} else {
		os.Stdout.Write(bytes)
		os.Stdout.Write([]byte("\n"))
	}
}

func processMaintenance(db *database.Database, job *string) {
	switch *job {
	case string(maintenanceJobListUnknownIPs):
		if ips, err := db.ListUnknownIPs(); err == nil {
			unknowns := []string{}
			for _, ip := range ips {
				unknowns = append(unknowns, ip.IP)
			}
			util.LogAndExit(0, `Unknown IPs:

%s`, strings.Join(unknowns, "\n"))
		} else {
			util.LogAndExit(1, "Failed to list unknown IPs: %s", err)
		}
	case string(maintenanceJobResolveUnknownIPs):
		if ips, err := db.ResolveUnknownIPs(); err == nil {
			resolved := []database.Location{}
			unresolved := []database.Location{}
			for _, ip := range ips {
				if ip.CountryName != database.UnknownLocation {
					resolved = append(resolved, ip)
				} else {
					unresolved = append(unresolved, ip)
				}
			}
			util.LogAndExit(0, `Newly resolved IPs: %d 
Still unresolved: %d`, len(resolved), len(unresolved))
		} else {
			util.LogAndExit(1, "Failed to resolve unknown IPs: %s", err)
		}
	case string(maintenanceJobPurgeLogs):
		if numPurged, err := db.PurgeLogs(); err == nil {
			util.LogAndExit(0, "Purged %d logs.", numPurged)
		} else {
			util.LogAndExit(1, "Failed to purge logs: %s", err)
		}
	default:
		util.Log("Unknown job was given: '%s'", *job)
		ShowUsage()
	}
}
