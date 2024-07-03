package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	// google ai
	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"

	// hujson
	"github.com/tailscale/hujson"

	// my libraries
	"github.com/meinside/infisical-go"
	"github.com/meinside/infisical-go/helper"
	"github.com/meinside/telegraph-go"
	"github.com/meinside/version-go"

	"github.com/meinside/balog/database"
	"github.com/meinside/balog/util"
)

const (
	applicationName = "balog"

	fallbackConfigDir = ".config/" + applicationName

	defaultConfigFilename = "config.json"
	defaultDBFilename     = "database.db"

	// number of days for reporting
	numDaysForReport1           = 7  // last 7 days
	numDaysForReport2           = 30 // last 30 days
	numDaysBeforeForOlderReport = 7  // older report = 7 days before
)

const (
	systemInstructionForInsightGeneration = `You are a chatbot which analyzes fail2ban ban action logs and IP-based geolocation data to generate insights for the user. Offer system or security insights based on the analysis. Highlight and explain any unusual patterns or noteworthy findings. Your response must be in plain text, so do not try to emphasize words with markdown characters.`
)

// param names
const (
	paramConfig   = "config"
	paramAction   = "action"
	paramIP       = "ip"
	paramProtocol = "protocol"
	paramFormat   = "format"
	paramJob      = "job"
)

type action string

// action names
const (
	actionSave        action = "save"
	actionReport      action = "report"
	actionMaintenance action = "maintenance"
)

type reportFormat string

// report formats
const (
	reportFormatPlain     reportFormat = "plain"
	reportFormatJSON      reportFormat = "json"
	reportFormatTelegraph reportFormat = "telegraph"
)

type maintenanceJob string

// maintenance jobs
const (
	maintenanceJobListUnknownIPs    maintenanceJob = "list_unknown_ips"
	maintenanceJobResolveUnknownIPs maintenanceJob = "resolve_unknown_ips"
	maintenanceJobPurgeLogs         maintenanceJob = "purge_logs"
)

// config struct
type config struct {
	DBFilepath *string `json:"db_filepath,omitempty"`

	// API tokens and keys
	TelegraphAccessToken *string `json:"telegraph_access_token,omitempty"`
	IPGeolocationAPIKey  *string `json:"ipgeolocation_api_key,omitempty"`
	GoogleAIAPIKey       *string `json:"google_ai_api_key,omitempty"`

	// or Infisical settings
	Infisical *struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`

		WorkspaceID string               `json:"workspace_id"`
		Environment string               `json:"environment"`
		SecretType  infisical.SecretType `json:"secret_type"`

		// Infisical key paths of API tokens and keys
		TelegraphAccessTokenKeyPath string  `json:"telegraph_access_token_key_path"`
		IPGeolocationAPIKeyKeyPath  *string `json:"ipgeolocation_api_key_key_path,omitempty"`
		GoogleAIAPIKeyKeyPath       *string `json:"google_ai_api_key_key_path,omitempty"`
	} `json:"infisical,omitempty"`
}

// standardize given JSON (JWCC) bytes
func standardizeJSON(b []byte) ([]byte, error) {
	ast, err := hujson.Parse(b)
	if err != nil {
		return b, err
	}
	ast.Standardize()

	return ast.Pack(), nil
}

// get telegraph access token, retrieve it from infisicial if needed
func (c *config) GetTelegraphAccessToken() *string {
	// read access token from infisical
	if c.TelegraphAccessToken == nil && c.Infisical != nil {
		var accessToken string

		var err error
		accessToken, err = helper.Value(
			c.Infisical.ClientID,
			c.Infisical.ClientSecret,
			c.Infisical.WorkspaceID,
			c.Infisical.Environment,
			c.Infisical.SecretType,
			c.Infisical.TelegraphAccessTokenKeyPath,
		)

		if err != nil {
			util.Log("Failed to retrieve telegraph access token from infisical: %s", err)
		}

		c.TelegraphAccessToken = &accessToken
	}

	return c.TelegraphAccessToken
}

// get ipgeolocation api key, retrieve it from infisical if needed
func (c *config) GetIPGeolocationAPIKey() *string {
	// read api key from infisical
	if c.IPGeolocationAPIKey == nil && c.Infisical != nil && c.Infisical.IPGeolocationAPIKeyKeyPath != nil {
		var apiKey string

		var err error
		apiKey, err = helper.Value(
			c.Infisical.ClientID,
			c.Infisical.ClientSecret,
			c.Infisical.WorkspaceID,
			c.Infisical.Environment,
			c.Infisical.SecretType,
			*c.Infisical.IPGeolocationAPIKeyKeyPath,
		)

		if err != nil {
			util.Log("Failed to retrieve ipgeolocation api key from infisical: %s", err)
		}

		c.IPGeolocationAPIKey = &apiKey
	}

	return c.IPGeolocationAPIKey
}

// get google ai api key, retrieve it from infisical if needed
func (c *config) GetGoogleAIAPIKey() *string {
	// read api key from infisical
	if c.GoogleAIAPIKey == nil && c.Infisical != nil && c.Infisical.GoogleAIAPIKeyKeyPath != nil {
		var apiKey string

		var err error
		apiKey, err = helper.Value(
			c.Infisical.ClientID,
			c.Infisical.ClientSecret,
			c.Infisical.WorkspaceID,
			c.Infisical.Environment,
			c.Infisical.SecretType,
			*c.Infisical.GoogleAIAPIKeyKeyPath,
		)

		if err != nil {
			util.Log("Failed to retrieve google ai api key from infisical: %s", err)
		}

		c.GoogleAIAPIKey = &apiKey
	}

	return c.GoogleAIAPIKey
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
func run(_ []string) {
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
			processSave(db, protocol, ip, config.GetIPGeolocationAPIKey())
		case string(actionReport):
			checkArg(format, paramFormat, actionReport)
			processReport(db, format, config.GetTelegraphAccessToken(), config.GetGoogleAIAPIKey(), 0)
		case string(actionMaintenance):
			checkArg(job, paramJob, actionMaintenance)
			processMaintenance(db, job, config.GetIPGeolocationAPIKey())
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
			if bytes, err = standardizeJSON(bytes); err == nil {
				if err = json.Unmarshal(bytes, &cfg); err == nil {
					return cfg, err
				}
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

// process save job
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

// process report job
func processReport(db *database.Database, format *string, telegraphAccessToken, googleAIAPIKey *string, offsetDays int) {
	var err error
	var recent, older, insight, report []byte

	switch *format {
	case string(reportFormatPlain):
		recent, err = db.GetReportAsPlain(offsetDays, numDaysForReport1, numDaysForReport2)

		// generate some insights from older/recent reports with google ai model
		if googleAIAPIKey != nil {
			if older, _ = db.GetReportAsPlain(offsetDays-numDaysBeforeForOlderReport, numDaysForReport1, numDaysForReport2); older != nil {
				if insight, err = generateInsight(googleAIAPIKey, older, recent); err != nil {
					util.Log("Failed to generate insights: %s", err)
				}
			}
		}

		// final report
		report = db.GetFinalReportAsPlain(recent, insight)
	case string(reportFormatJSON):
		recent, err = db.GetReportAsJSON(offsetDays, numDaysForReport1, numDaysForReport2)

		// generate some insights from older/recent reports with google ai model
		if googleAIAPIKey != nil {
			if older, _ = db.GetReportAsJSON(offsetDays-numDaysBeforeForOlderReport, numDaysForReport1, numDaysForReport2); older != nil {
				if insight, err = generateInsight(googleAIAPIKey, older, recent); err != nil {
					util.Log("Failed to generate insights: %s", err)
				}
			}
		}

		// final report
		report = db.GetFinalReportAsJSON(recent, insight)
	case string(reportFormatTelegraph):
		var client *telegraph.Client
		if telegraphAccessToken == nil {
			if client, err = telegraph.Create("balog", "Ban Action Logger", ""); err == nil { // NOTE: generate a new access token
				util.LogAndExit(0, "Add '%s' to your balog's configuration file with key `telegraph_access_token`", client.AccessToken)
			} else {
				util.LogAndExit(1, "Failed to create telegraph client: %s", err)
			}
		} else {
			if client, err = telegraph.Load(*telegraphAccessToken); err != nil {
				util.LogAndExit(1, "Failed to load telegraph client: %s", err)
			}
		}

		if recent, err = db.GetReportAsTelegraph(telegraphAccessToken, offsetDays, numDaysForReport1, numDaysForReport2); err == nil {
			// generate some insights from older/recent reports with google ai model
			if googleAIAPIKey != nil {
				if older, _ = db.GetReportAsJSON(offsetDays-numDaysBeforeForOlderReport, numDaysForReport1, numDaysForReport2); older != nil {
					if insight, err = generateInsight(googleAIAPIKey, older, recent); err != nil {
						util.Log("Failed to generate insights: %s", err)
					}
				}
			}

			// final report
			report = db.GetFinalReportAsTelegraph(recent, insight)

			var url string
			if url, err = postToTelegraphAndReturnURL(client, report, offsetDays); err == nil {
				report = []byte(url)
			}
		}
	default:
		util.Log("Unknown format was given: '%s'", *format)
		showUsage()
	}

	if err != nil {
		util.LogAndExit(1, "Failed to generate report: %s", err)
	} else {
		os.Stdout.Write(report)
		os.Stdout.Write([]byte("\n"))
	}
}

// post given html page to telegra.ph and return the generated URL
func postToTelegraphAndReturnURL(client *telegraph.Client, bytes []byte, offsetDays int) (url string, err error) {
	var title string
	hostname, _ := os.Hostname()
	timestamp := time.Now().AddDate(0, 0, -offsetDays).Format("2006-01-02 15:04:05")
	if len(hostname) > 0 {
		title = fmt.Sprintf("[%s] Balog Report: %s", hostname, timestamp)
	} else {
		title = fmt.Sprintf("Balog Report: %s", timestamp)
	}

	var post telegraph.Page
	if post, err = client.CreatePageWithHTML(
		title,
		fmt.Sprintf("balog (%s)", hostname),
		database.ProjectURL,
		string(bytes),
		true,
	); err == nil {
		return fmt.Sprintf("https://telegra.ph/%s", post.Path), nil
	}

	return "", err
}

// process maintenance job
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

// generate insights with google api model
func generateInsight(googleAIAPIKey *string, olderReport, recentReport []byte) (insight []byte, err error) {
	generated := ""

	ctx := context.TODO()

	var client *genai.Client
	if client, err = genai.NewClient(ctx, option.WithAPIKey(*googleAIAPIKey)); err == nil {
		model := client.GenerativeModel(database.GoogleAIModel)

		// set system instruction
		model.SystemInstruction = &genai.Content{
			Role: "model",
			Parts: []genai.Part{
				genai.Text(systemInstructionForInsightGeneration),
			},
		}

		prompt := fmt.Sprintf(`Following are summarized reports of ban action logs and the geolocations of the logs.
Analyze these reports and offer system or security insights based on the analysis.
Highlight and explain any unusual patterns or noteworthy findings.

<older_report>
%[1]s
</older_report>

<recent_report>
%[2]s
</recent_report>`, string(olderReport), string(recentReport))

		session := model.StartChat()
		session.History = []*genai.Content{}

		// set prompt
		parts := []genai.Part{
			genai.Text(prompt),
		}

		var res *genai.GenerateContentResponse
		if res, err = session.SendMessage(ctx, parts...); err == nil {
			if len(res.Candidates) > 0 {
				parts := res.Candidates[0].Content.Parts

				for _, part := range parts {
					if text, ok := part.(genai.Text); ok {
						generated += string(text) + "\n"
					} else if data, ok := part.(genai.Blob); ok {
						generated += fmt.Sprintf("%d byte(s) of %s\n", len(data.Data), data.MIMEType)
					} else {
						err = fmt.Errorf("unsupported type of part returned from Gemini API: %+v", part)
					}
				}
			} else {
				err = fmt.Errorf("no candidate returned from Gemini API")
			}
		}
	}

	defer client.Close()

	return []byte(generated), err
}
