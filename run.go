package main

import (
	"encoding/json"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/meinside/balog/database"
	"github.com/meinside/balog/util"
	"github.com/meinside/infisical-go"
	"github.com/meinside/infisical-go/helper"

	"github.com/meinside/version-go"
)

const (
	applicationName = "balog"

	fallbackConfigDir = ".config/" + applicationName

	defaultConfigFilename = "config.json"
	defaultDBFilename     = "database.db"
)

const (
	paramConfig   = "config"
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

	// Telegraph and IPGeolocation tokens & keys
	TelegraphAccessToken *string `json:"telegraph_access_token,omitempty"`
	IPGeolocationAPIKey  *string `json:"ipgeolocation_api_key,omitempty"`

	// or Infisical settings
	Infisical *struct {
		// NOTE: When the workspace's E2EE setting is enabled, APIKey is essential for decryption
		E2EE   bool    `json:"e2ee,omitempty"`
		APIKey *string `json:"api_key,omitempty"`

		WorkspaceID string               `json:"workspace_id"`
		Token       string               `json:"token"`
		Environment string               `json:"environment"`
		SecretType  infisical.SecretType `json:"secret_type"`

		TelegraphAccessTokenKeyPath string  `json:"telegraph_access_token_key_path"`
		IPGeolocationAPIKeyKeyPath  *string `json:"ipgeolocation_api_key_key_path,omitempty"`
	} `json:"infisical,omitempty"`
}

func init() {
	flag.Usage = showUsage
}

// showUsage prints usage
func showUsage() {
	util.LogAndExit(0, `Usage of %[1]s %[4]s:

# save a ban action
$ %[1]s -action save -ip <ip> -protocol <name>

# generate a report (format = plain, json, telegraph)
$ %[1]s -action report -format <format>

# perform maintenance (job = list_unknown_ips, resolve_unknown_ips, purge_logs)
$ %[1]s -action maintenance -job <job>

# for loading config file from a location you want (default: $XDG_CONFIG_HOME/%[2]s/%[3]s)
$ %[1]s -config <config_filepath> ...
`, filepath.Base(os.Args[0]), applicationName, defaultConfigFilename, version.Minimum())
}

// run processes command line arguments
func run(args []string) {
	// parse params
	var configFilepath *string = flag.String(paramConfig, "", "Config filepath")
	var action *string = flag.String(paramAction, "", "Action to perform")
	var ip *string = flag.String(paramIP, "", "IP address of the ban action")
	var protocol *string = flag.String(paramProtocol, "", "Protocol of the ban action")
	var format *string = flag.String(paramFormat, "", "Output format of the report")
	var job *string = flag.String(paramJob, "", "Maintenance job to perform")
	flag.Parse()

	if config, err := loadConfig(configFilepath); err == nil {
		if config.DBFilepath == nil {
			// https://xdgbasedirectoryspecification.com
			configDir := os.Getenv("XDG_CONFIG_HOME")

			// If the value of the environment variable is unset, empty, or not an absolute path, use the default
			if configDir == "" || configDir[0:1] != "/" {
				homedir, _ := os.UserHomeDir()
				fallbackDBFilepath := filepath.Join(homedir, fallbackConfigDir, defaultDBFilename)

				util.Log("`db_filepath` is missing in config file, using default: '%s'", fallbackDBFilepath)

				config.DBFilepath = &fallbackDBFilepath
			} else {
				*config.DBFilepath = filepath.Join(configDir, applicationName, defaultDBFilename)
			}
		}

		db, err := database.Open(*config.DBFilepath)
		if err != nil {
			util.LogAndExit(1, "Failed to open database: %s", err)
		}

		switch *action {
		case string(actionSave):
			checkArg(ip, paramIP, actionSave)
			checkArg(protocol, paramProtocol, actionSave)
			processSave(db, protocol, ip, config.IPGeolocationAPIKey)
		case string(actionReport):
			checkArg(format, paramFormat, actionReport)
			processReport(db, format, config.TelegraphAccessToken)
		case string(actionMaintenance):
			checkArg(job, paramJob, actionMaintenance)
			processMaintenance(db, job, config.IPGeolocationAPIKey)
		default:
			util.Log("Unknown action was given: '%s'", *action)
			showUsage()
		}

	} else {
		util.LogAndExit(1, "Failed to load config: %s", err)
	}
}

// check argument's existence and exit program if it's missing
func checkArg(arg *string, expectedArg, action action) {
	if len(*arg) <= 0 {
		util.Log("Parameter `-%s` is required for action '%s'.", expectedArg, action)
		showUsage()
	}
}

// loadConfig loads config, if it doesn't exist, create it
func loadConfig(customConfigFilepath *string) (cfg config, err error) {
	var configFilepath string
	if customConfigFilepath == nil || len(*customConfigFilepath) <= 0 {
		// https://xdgbasedirectoryspecification.com
		configDir := os.Getenv("XDG_CONFIG_HOME")

		// If the value of the environment variable is unset, empty, or not an absolute path, use the default
		if configDir == "" || configDir[0:1] != "/" {
			var homedir string
			homedir, err = os.UserHomeDir()
			if err == nil {
				configFilepath = filepath.Join(homedir, fallbackConfigDir, defaultConfigFilename)
			} else {
				return cfg, err
			}
		} else {
			configFilepath = filepath.Join(configDir, applicationName, defaultConfigFilename)
		}
	} else {
		configFilepath = *customConfigFilepath
	}

	if _, err = os.Stat(configFilepath); err == nil {
		// read config file
		var bytes []byte
		if bytes, err = os.ReadFile(configFilepath); err == nil {
			if err = json.Unmarshal(bytes, &cfg); err == nil {
				// read access token from infisical
				if cfg.TelegraphAccessToken == nil && cfg.Infisical != nil {
					var accessToken string

					if cfg.Infisical.E2EE && cfg.Infisical.APIKey != nil {
						accessToken, err = helper.E2EEValue(
							*cfg.Infisical.APIKey,
							cfg.Infisical.WorkspaceID,
							cfg.Infisical.Token,
							cfg.Infisical.Environment,
							cfg.Infisical.SecretType,
							cfg.Infisical.TelegraphAccessTokenKeyPath,
						)
					} else {
						accessToken, err = helper.Value(
							cfg.Infisical.WorkspaceID,
							cfg.Infisical.Token,
							cfg.Infisical.Environment,
							cfg.Infisical.SecretType,
							cfg.Infisical.TelegraphAccessTokenKeyPath,
						)
					}
					cfg.TelegraphAccessToken = &accessToken
				}
				// read api key from infisical
				if cfg.IPGeolocationAPIKey == nil && cfg.Infisical != nil && cfg.Infisical.IPGeolocationAPIKeyKeyPath != nil {
					var apiKey string

					if cfg.Infisical.E2EE && cfg.Infisical.APIKey != nil {
						apiKey, err = helper.E2EEValue(
							*cfg.Infisical.APIKey,
							cfg.Infisical.WorkspaceID,
							cfg.Infisical.Token,
							cfg.Infisical.Environment,
							cfg.Infisical.SecretType,
							*cfg.Infisical.IPGeolocationAPIKeyKeyPath,
						)
					} else {
						apiKey, err = helper.Value(
							cfg.Infisical.WorkspaceID,
							cfg.Infisical.Token,
							cfg.Infisical.Environment,
							cfg.Infisical.SecretType,
							*cfg.Infisical.IPGeolocationAPIKeyKeyPath,
						)
					}
					cfg.IPGeolocationAPIKey = &apiKey
				}

				return cfg, err
			}
		}
	} else if os.IsNotExist(err) {
		// create a config directory recursively
		configDirpath := filepath.Dir(configFilepath)
		if err := os.MkdirAll(configDirpath, fs.ModePerm); err != nil {
			util.Log("Failed to create config directory '%s': %s", configDirpath, err)
		}

		// create a default config file
		var file *os.File
		if file, err = os.Create(configFilepath); err == nil {
			defer file.Close()

			dbDirpath := filepath.Dir(configFilepath)
			dbFilepath := filepath.Join(dbDirpath, defaultDBFilename)
			cfg = config{
				DBFilepath: &dbFilepath,
			}

			// write default config
			var bytes []byte
			if bytes, err = json.Marshal(cfg); err == nil {
				if _, err = file.Write(bytes); err == nil {
					util.Log("Created default config file: '%s'", configFilepath)
				}
				return cfg, nil
			}
		}
	}

	return cfg, err
}

func processSave(db *database.Database, protocol, ip, geolocAPIKey *string) {
	// save,
	if id, err := db.SaveBanAction(*protocol, *ip); err != nil {
		util.LogAndExit(1, "Failed to save ban action: %s", err)
	} else {
		// then resolve its geo location
		if cached, err := db.LookupLocation(*ip); err == nil {
			var fetched string
			var err error
			// if there is no cache for it, fetch it from ipgeolocation.io,
			if cached.ID == 0 {
				fetched, err = database.FetchLocation(geolocAPIKey, *ip)
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
		showUsage()
	}

	if err != nil {
		util.LogAndExit(1, "Failed to generate report: %s", err)
	} else {
		os.Stdout.Write(bytes)
		os.Stdout.Write([]byte("\n"))
	}
}

func processMaintenance(db *database.Database, job, geolocAPIKey *string) {
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
		if ips, err := db.ResolveUnknownIPs(geolocAPIKey); err == nil {
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
		showUsage()
	}
}
