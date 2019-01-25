package main

import (
	stdLog "log"
	"net/url"
	"os"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stellar/go/network"
	horizon "github.com/stellar/go/services/horizon/internal"
	"github.com/stellar/go/services/horizon/internal/db2/schema"
	apkg "github.com/stellar/go/support/app"
	"github.com/stellar/go/support/log"
	"github.com/stellar/go/support/strutils"
	"github.com/throttled/throttled"
)

var app *horizon.App
var config horizon.Config
var c horizon.Config

var rootCmd *cobra.Command

type flagType func(name string, value interface{}, usage string) interface{}

var (
	stringFlag flagType = func(name string, value interface{}, usage string) interface{} {
		return rootCmd.PersistentFlags().String(name, value.(string), usage)
	}
	intFlag flagType = func(name string, value interface{}, usage string) interface{} {
		return rootCmd.PersistentFlags().Int(name, value.(int), usage)
	}
	uintFlag flagType = func(name string, value interface{}, usage string) interface{} {
		return rootCmd.PersistentFlags().Uint(name, value.(uint), usage)
	}
	boolFlag flagType = func(name string, value interface{}, usage string) interface{} {
		return rootCmd.PersistentFlags().Bool(name, value.(bool), usage)
	}
)

type configOption struct {
	name        string
	envVar      string
	flagType    flagType
	flagDefault interface{}
	required    bool
	usage       string
	validator   func(*configOption)
	configKey   interface{}
}

func (co *configOption) require() error {
	stdLog.Print(co.name, " ", co.required, " ", viper.GetString(co.name))
	if co.required == true && viper.GetString(co.name) == "" {
		stdLog.Fatalf("Invalid config: %s is blank. Please specify --%s on the command line or set the %s environment variable.", co.name, co.name, co.envVar)
	}
	return nil
}

func (co *configOption) validateAndSet(c *horizon.Config) error {
	if co.validator != nil {
		co.validator(co)
	} else if co.configKey != nil {
		co.setValue()
	}
	return nil
}

func (co *configOption) setValue() {
	// c.Port = viper.GetInt("port")
	if co.configKey != nil {
		switch co.flagDefault.(type) {
		case string:
			*(co.configKey.(*string)) = viper.GetString(co.name)
		case int:
			*(co.configKey.(*int)) = viper.GetInt(co.name)
		case bool:
			*(co.configKey.(*bool)) = viper.GetBool(co.name)
			// TODO: case uint, case duration
		}
	}
}

func inSeconds(nSeconds int) time.Duration {
	return time.Duration(nSeconds) * time.Second
}

func validateDuration(co *configOption) {
	*(co.configKey.(*time.Duration)) = inSeconds(viper.GetInt(co.name))
}

func validateURL(co *configOption) {
	friendbotURLString := viper.GetString(co.name)
	if friendbotURLString != "" {
		friendbotURL, err := url.Parse(friendbotURLString)
		if err != nil {
			stdLog.Fatalf("Unable to parse URL: %s/%v", friendbotURLString, err)
		}
		*(co.configKey.(*url.URL)) = *friendbotURL
	}
}

func validateLogLevel(co *configOption) {
	ll, err := logrus.ParseLevel(viper.GetString("log-level"))
	if err != nil {
		stdLog.Fatalf("Could not parse log-level: %v", viper.GetString("log-level"))
	}
	log.DefaultLogger.Level = ll
	*(co.configKey.(*logrus.Level)) = ll
}

// TODO: Fix capitalisation on usage string
// TODO: Add flag defaults for all, remove flagType
// TODO: Write func to choose between flagTypes based on flagDefault
// TODO: Test all options
// TODO: Verify uints work as expected (pretty sure they need validators adding)
var configOpts = []configOption{
	configOption{name: "port", configKey: &c.Port, flagType: intFlag, flagDefault: 8000, usage: "tcp port to listen on for http requests"},
	configOption{name: "stellar-core-db-url", envVar: "STELLAR_CORE_DATABASE_URL", configKey: &c.StellarCoreDatabaseURL, flagType: stringFlag, flagDefault: "", required: true, usage: "stellar-core postgres database to connect with"},
	configOption{name: "db-url", envVar: "DATABASE_URL", configKey: &c.DatabaseURL, flagType: stringFlag, flagDefault: "", required: true, usage: "horizon postgres database to connect with"},
	configOption{name: "stellar-core-url", configKey: &c.StellarCoreURL, flagType: stringFlag, flagDefault: "", required: true, usage: "stellar-core to connect with (for http commands)"},
	configOption{name: "max-db-connections", configKey: &c.MaxDBConnections, flagType: intFlag, flagDefault: 20, usage: "max db connections (per DB), may need to be increased when responses are slow but DB CPU is normal"},
	configOption{name: "sse-update-frequency", configKey: &c.SSEUpdateFrequency, flagType: intFlag, flagDefault: 5, validator: validateDuration, usage: "defines how often streams should check if there's a new ledger (in seconds), may need to increase in case of big number of streams"},
	configOption{name: "connection-timeout", configKey: &c.ConnectionTimeout, flagType: intFlag, flagDefault: 55, validator: validateDuration, usage: "defines the timeout of connection after which 504 response will be sent or stream will be closed, if Horizon is behind a load balancer with idle connection timeout, this should be set to a few seconds less that idle timeout"},
	// configOption{name: "per-hour-rate-limit", flagType: intFlag, flagDefault: 3600, usage: "max count of requests allowed in a one hour period, by remote ip address"},
	configOption{name: "rate-limit-redis-key", configKey: &c.RateLimitRedisKey, flagType: stringFlag, flagDefault: "", usage: "redis key for storing rate limit data, useful when deploying a cluster of Horizons, ignored when redis-url is empty"},
	configOption{name: "redis-url", configKey: &c.RedisURL, flagType: stringFlag, flagDefault: "", usage: "redis to connect with, for rate limiting"},
	configOption{name: "friendbot-url", configKey: &c.FriendbotURL, flagType: stringFlag, flagDefault: "", validator: validateURL, usage: "friendbot service to redirect to"},
	configOption{name: "log-level", configKey: &c.LogLevel, flagType: stringFlag, flagDefault: "info", usage: "Minimum log severity (debug, info, warn, error) to log", validator: validateLogLevel},
	// configOption{name: "log-file", flagType: stringFlag, usage: "Name of the file where logs will be saved (leave empty to send logs to stdout)"},
	configOption{name: "sentry-dsn", configKey: &c.SentryDSN, flagType: stringFlag, flagDefault: "", usage: "Sentry URL to which panics and errors should be reported"},
	configOption{name: "loggly-token", configKey: &c.LogglyToken, flagType: stringFlag, flagDefault: "", usage: "Loggly token, used to configure log forwarding to loggly"},
	configOption{name: "loggly-tag", configKey: &c.LogglyTag, flagType: stringFlag, flagDefault: "horizon", usage: "Tag to be added to every loggly log event"},
	// configOption{name: "tls-cert", configKey: &c.TLSCert, flagType: stringFlag, usage: "The TLS certificate file to use for securing connections to horizon"},
	// configOption{name: "tls-key", configKey: &c.TLSKey, flagType: stringFlag, usage: "The TLS private key file to use for securing connections to horizon"},
	configOption{name: "ingest", configKey: &c.Ingest, flagType: boolFlag, flagDefault: false, usage: "causes this horizon process to ingest data from stellar-core into horizon's db"},
	configOption{name: "network-passphrase", configKey: &c.NetworkPassphrase, flagType: stringFlag, flagDefault: network.TestNetworkPassphrase, required: true, usage: "Override the network passphrase"},
	configOption{name: "history-retention-count", configKey: &c.HistoryRetentionCount, flagType: uintFlag, flagDefault: uint(0), usage: "the minimum number of ledgers to maintain within horizon's history tables.  0 signifies an unlimited number of ledgers will be retained"},
	configOption{name: "history-stale-threshold", configKey: &c.StaleThreshold, flagType: uintFlag, flagDefault: uint(0), usage: "the maximum number of ledgers the history db is allowed to be out of date from the connected stellar-core db before horizon considers history stale"},
	configOption{name: "skip-cursor-update", configKey: &c.SkipCursorUpdate, flagType: boolFlag, flagDefault: false, usage: "causes the ingester to skip reporting the last imported ledger state to stellar-core"},
	configOption{name: "enable-asset-stats", configKey: &c.EnableAssetStats, flagType: boolFlag, flagDefault: false, usage: "enables asset stats during the ingestion and expose `/assets` endpoint,  Enabling it has a negative impact on CPU"},
	configOption{name: "max-path-length", configKey: &c.MaxPathLength, flagType: uintFlag, flagDefault: uint(4), usage: "the maximum number of assets on the path in `/paths` endpoint"},
}

func main() {
	rootCmd.Execute()
}

func init() {
	viper.SetDefault("port", 8000)
	viper.SetDefault("history-retention-count", 0)

	rootCmd = &cobra.Command{
		Use:   "horizon",
		Short: "client-facing api server for the stellar network",
		Long:  "client-facing api server for the stellar network",
		Run: func(cmd *cobra.Command, args []string) {
			initApp(cmd, args)
			app.Serve()
		},
	}

	for i := range configOpts {
		co := &configOpts[i]

		// Bind the command line and environment variable name
		if co.envVar == "" {
			co.envVar = strutils.KebabToConstantCase(co.name)
			viper.BindEnv(co.name, co.envVar)
		}

		// Assume any unset flag default is the empty string
		if co.flagDefault == nil {
			co.flagDefault = ""
		}

		// Initialise the persistent flags
		co.flagType(co.name, co.flagDefault, co.usage)
	}

	rootCmd.AddCommand(dbCmd)

	viper.BindPFlags(rootCmd.PersistentFlags())
}

func initApp(cmd *cobra.Command, args []string) *horizon.App {
	initConfig()

	var err error
	app, err = horizon.NewApp(config)

	if err != nil {
		stdLog.Fatal(err.Error())
	}

	return app
}

func initConfig() {
	// Check all required args were provided
	for i := range configOpts {
		co := &configOpts[i]
		co.require()
	}

	migrationsToApplyUp := schema.GetMigrationsUp(viper.GetString("db-url"))
	if len(migrationsToApplyUp) > 0 {
		stdLog.Printf(`There are %v migrations to apply in the "up" direction.`, len(migrationsToApplyUp))
		stdLog.Printf("The necessary migrations are: %v", migrationsToApplyUp)
		stdLog.Printf("A database migration is required to run this version (%v) of Horizon. Run \"horizon db migrate up\" to update your DB. Consult the Changelog (https://github.com/stellar/horizon/blob/master/CHANGELOG.md) for more information.", apkg.Version())
		os.Exit(1)
	}

	nMigrationsDown := schema.GetNumMigrationsDown(viper.GetString("db-url"))
	if nMigrationsDown > 0 {
		stdLog.Printf("A database migration DOWN to an earlier version of the schema is required to run this version (%v) of Horizon. Consult the Changelog (https://github.com/stellar/horizon/blob/master/CHANGELOG.md) for more information.", apkg.Version())
		stdLog.Printf("In order to migrate the database DOWN, using the HIGHEST version number of Horizon you have installed (not this binary), run \"horizon db migrate down %v\".", nMigrationsDown)
		os.Exit(1)
	}

	// Run validation checks
	for i := range configOpts {
		co := &configOpts[i]
		co.validateAndSet(&c)
	}
	// Validate log level
	ll, err := logrus.ParseLevel(viper.GetString("log-level"))
	if err != nil {
		stdLog.Fatalf("Could not parse log-level: %v", viper.GetString("log-level"))
	}
	log.DefaultLogger.Level = ll

	// For testing purposes only
	//stdLog.Fatal(configOpts)
	stdLog.Fatal(c)
	// stdLog.Fatal("Died here")

	// Write to a log file, if a file name was provided
	lf := viper.GetString("log-file")
	if lf != "" {
		logFile, err := os.OpenFile(lf, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			log.DefaultLogger.Logger.Out = logFile
		} else {
			stdLog.Fatal("Failed to log to file")
		}
	}

	// Ensure that both a TLS cert and key are provided, if either is provided
	cert, key := viper.GetString("tls-cert"), viper.GetString("tls-key")
	switch {
	case cert != "" && key == "":
		stdLog.Fatal("Invalid TLS config: key not configured")
	case cert == "" && key != "":
		stdLog.Fatal("Invalid TLS config: cert not configured")
	}

	// Validate the friendbotURL is a URL, if it was provided
	var friendbotURL *url.URL
	friendbotURLString := viper.GetString("friendbot-url")
	if friendbotURLString != "" {
		friendbotURL, err = url.Parse(friendbotURLString)
		if err != nil {
			stdLog.Fatalf("Unable to parse URL: %s/%v", friendbotURLString, err)
		}
	}

	// Set rate and burst limiting if provided
	var rateLimit *throttled.RateQuota = nil
	perHourRateLimit := viper.GetInt("per-hour-rate-limit")
	if perHourRateLimit != 0 {
		rateLimit = &throttled.RateQuota{
			MaxRate:  throttled.PerHour(perHourRateLimit),
			MaxBurst: 100,
		}
	}

	config = horizon.Config{
		DatabaseURL:            viper.GetString("db-url"),
		StellarCoreDatabaseURL: viper.GetString("stellar-core-db-url"),
		StellarCoreURL:         viper.GetString("stellar-core-url"),
		Port:                   viper.GetInt("port"),
		MaxDBConnections:       viper.GetInt("max-db-connections"),
		SSEUpdateFrequency:     time.Duration(viper.GetInt("sse-update-frequency")) * time.Second,
		ConnectionTimeout:      time.Duration(viper.GetInt("connection-timeout")) * time.Second,
		RateLimit:              rateLimit,
		RateLimitRedisKey:      viper.GetString("rate-limit-redis-key"),
		RedisURL:               viper.GetString("redis-url"),
		FriendbotURL:           friendbotURL,
		LogLevel:               ll,
		LogFile:                lf,
		MaxPathLength:          uint(viper.GetInt("max-path-length")),
		NetworkPassphrase:      viper.GetString("network-passphrase"),
		SentryDSN:              viper.GetString("sentry-dsn"),
		LogglyToken:            viper.GetString("loggly-token"),
		LogglyTag:              viper.GetString("loggly-tag"),
		TLSCert:                cert,
		TLSKey:                 key,
		Ingest:                 viper.GetBool("ingest"),
		HistoryRetentionCount:  uint(viper.GetInt("history-retention-count")),
		StaleThreshold:         uint(viper.GetInt("history-stale-threshold")),
		SkipCursorUpdate:       viper.GetBool("skip-cursor-update"),
		EnableAssetStats:       viper.GetBool("enable-asset-stats"),
	}
}
