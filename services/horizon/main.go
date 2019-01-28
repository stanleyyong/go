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
var c, config horizon.Config
var rootCmd *cobra.Command

// flagType implements a generic interface for the different command line flags,
// allowing them to be configured in a uniform way.
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

// configOption is a complete description of the configuration of a command line option
type configOption struct {
	name           string              // e.g. "db-url"
	envVar         string              // e.g. "DATABASE_URL". Defaults to uppercase/underscore representation of name
	flagDefault    interface{}         // A default if no option is provided. Set to "" if no default
	required       bool                // Whether this option must be set for Horizon to run
	usage          string              // Help text
	customSetValue func(*configOption) // Optional function for custom validation/transformation
	configKey      interface{}         // Pointer to the final key in the horizon.Config struct
}

// require checks that a required string configuration option is not empty, raising a user error if it is.
func (co *configOption) require() {
	if co.required == true && viper.GetString(co.name) == "" {
		stdLog.Fatalf("Invalid config: %s is blank. Please specify --%s on the command line or set the %s environment variable.", co.name, co.name, co.envVar)
	}
}

// setValue sets a value in the global config, using a custom function, if one was provided.
func (co *configOption) setValue() {
	// Use a custom setting function, if one is provided
	if co.customSetValue != nil {
		co.customSetValue(co)
		// Otherwise, just set the provided arg directly
	} else if co.configKey != nil {
		co.setSimpleValue()
	}
}

// setSimpleValue sets the value of a configOption's configKey, based on the configOption's default type.
func (co *configOption) setSimpleValue() {
	if co.configKey != nil {
		switch co.flagDefault.(type) {
		case string:
			*(co.configKey.(*string)) = viper.GetString(co.name)
		case int:
			*(co.configKey.(*int)) = viper.GetInt(co.name)
		case bool:
			*(co.configKey.(*bool)) = viper.GetBool(co.name)
		case uint:
			*(co.configKey.(*uint)) = uint(viper.GetInt(co.name))
		}
	}
}

// setFlag sets the correct pFlag type, based on the configOption's default type.
func (co *configOption) setFlag() {
	switch co.flagDefault.(type) {
	case string:
		stringFlag(co.name, co.flagDefault, co.usage)
	case int:
		intFlag(co.name, co.flagDefault, co.usage)
	case bool:
		boolFlag(co.name, co.flagDefault, co.usage)
	case uint:
		uintFlag(co.name, co.flagDefault, co.usage)
	}
}

// setDuration converts a command line int to a duration, and stores it in the final config.
func setDuration(co *configOption) {
	*(co.configKey.(*time.Duration)) = time.Duration(viper.GetInt(co.name)) * time.Second
}

// setURL converts a command line string to a URL, and stores it in the final config.
func setURL(co *configOption) {
	urlString := viper.GetString(co.name)
	if urlString != "" {
		urlType, err := url.Parse(urlString)
		if err != nil {
			stdLog.Fatalf("Unable to parse URL: %s/%v", urlString, err)
		}
		*(co.configKey.(**url.URL)) = urlType
	}
}

// setLogLevel validates and sets the log level in the final config.
func setLogLevel(co *configOption) {
	ll, err := logrus.ParseLevel(viper.GetString(co.name))
	if err != nil {
		stdLog.Fatalf("Could not parse log-level: %v", viper.GetString(co.name))
	}
	*(co.configKey.(*logrus.Level)) = ll
}

// setRateLimit converts a command line rate limit, and sets rate and burst limiting in the final config.
func setRateLimit(co *configOption) {
	var rateLimit *throttled.RateQuota = nil
	perHourRateLimit := viper.GetInt(co.name)
	if perHourRateLimit != 0 {
		rateLimit = &throttled.RateQuota{
			MaxRate:  throttled.PerHour(perHourRateLimit),
			MaxBurst: 100,
		}
		*(co.configKey.(**throttled.RateQuota)) = rateLimit
	}
}

// validateBothOrNeither ensures that both options are provided, if either is provided
func validateBothOrNeither(option1, option2 string) {
	arg1, arg2 := viper.GetString(option1), viper.GetString(option2)
	switch {
	case arg1 != "" && arg2 == "":
		stdLog.Fatalf("Invalid config: %s=%s, but %s is not configured", option1, arg1, option2)
	case arg1 == "" && arg2 != "":
		stdLog.Fatalf("Invalid config: %s=%s, but %s is not configured", option2, arg2, option1)
	}
}

// checkMigrations looks for necessary database migrations and fails with a descriptive error if migrations are needed
func checkMigrations() {
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
}

// configOpts defines the complete flag configuration for horizon. Add a new line here to connect a new field in the horizon.Config struct
var configOpts = []*configOption{
	&configOption{
		name:        "db-url",
		envVar:      "DATABASE_URL",
		configKey:   &c.DatabaseURL,
		flagDefault: "",
		required:    true,
		usage:       "horizon postgres database to connect with",
	},
	&configOption{
		name:        "stellar-core-db-url",
		envVar:      "STELLAR_CORE_DATABASE_URL",
		configKey:   &c.StellarCoreDatabaseURL,
		flagDefault: "",
		required:    true,
		usage:       "stellar-core postgres database to connect with",
	},
	&configOption{
		name:        "stellar-core-url",
		configKey:   &c.StellarCoreURL,
		flagDefault: "",
		required:    true,
		usage:       "stellar-core to connect with (for http commands)",
	},
	&configOption{
		name:        "port",
		configKey:   &c.Port,
		flagDefault: uint(8000),
		usage:       "tcp port to listen on for http requests",
	},
	&configOption{
		name:        "max-db-connections",
		configKey:   &c.MaxDBConnections,
		flagDefault: int(20),
		usage:       "max db connections (per DB), may need to be increased when responses are slow but DB CPU is normal",
	},
	&configOption{
		name:           "sse-update-frequency",
		configKey:      &c.SSEUpdateFrequency,
		flagDefault:    5,
		customSetValue: setDuration,
		usage:          "defines how often streams should check if there's a new ledger (in seconds), may need to increase in case of big number of streams",
	},
	&configOption{
		name:           "connection-timeout",
		configKey:      &c.ConnectionTimeout,
		flagDefault:    55,
		customSetValue: setDuration,
		usage:          "defines the timeout of connection after which 504 response will be sent or stream will be closed, if Horizon is behind a load balancer with idle connection timeout, this should be set to a few seconds less that idle timeout",
	},
	&configOption{
		name:           "per-hour-rate-limit",
		configKey:      &c.RateLimit,
		flagDefault:    3600,
		customSetValue: setRateLimit,
		usage:          "max count of requests allowed in a one hour period, by remote ip address",
	},
	&configOption{
		name:        "rate-limit-redis-key",
		configKey:   &c.RateLimitRedisKey,
		flagDefault: "",
		usage:       "redis key for storing rate limit data, useful when deploying a cluster of Horizons, ignored when redis-url is empty",
	},
	&configOption{
		name:        "redis-url",
		configKey:   &c.RedisURL,
		flagDefault: "",
		usage:       "redis to connect with, for rate limiting",
	},
	&configOption{
		name:           "friendbot-url",
		configKey:      &c.FriendbotURL,
		flagDefault:    "",
		customSetValue: setURL,
		usage:          "friendbot service to redirect to",
	},
	&configOption{
		name:           "log-level",
		configKey:      &c.LogLevel,
		flagDefault:    "info",
		customSetValue: setLogLevel,
		usage:          "minimum log severity (debug, info, warn, error) to log",
	},
	&configOption{
		name:        "log-file",
		configKey:   &c.LogFile,
		flagDefault: "",
		usage:       "name of the file where logs will be saved (leave empty to send logs to stdout)",
	},
	&configOption{
		name:        "max-path-length",
		configKey:   &c.MaxPathLength,
		flagDefault: uint(4),
		usage:       "the maximum number of assets on the path in `/paths` endpoint",
	},
	&configOption{
		name:        "network-passphrase",
		configKey:   &c.NetworkPassphrase,
		flagDefault: network.TestNetworkPassphrase,
		required:    true,
		usage:       "Override the network passphrase",
	},
	&configOption{
		name:        "sentry-dsn",
		configKey:   &c.SentryDSN,
		flagDefault: "",
		usage:       "Sentry URL to which panics and errors should be reported",
	},
	&configOption{
		name:        "loggly-token",
		configKey:   &c.LogglyToken,
		flagDefault: "",
		usage:       "Loggly token, used to configure log forwarding to loggly",
	},
	&configOption{
		name:        "loggly-tag",
		configKey:   &c.LogglyTag,
		flagDefault: "horizon",
		usage:       "Tag to be added to every loggly log event",
	},
	&configOption{
		name:        "tls-cert",
		configKey:   &c.TLSCert,
		flagDefault: "",
		usage:       "TLS certificate file to use for securing connections to horizon",
	},
	&configOption{
		name:        "tls-key",
		configKey:   &c.TLSKey,
		flagDefault: "",
		usage:       "TLS private key file to use for securing connections to horizon",
	},
	&configOption{
		name:        "ingest",
		configKey:   &c.Ingest,
		flagDefault: false,
		usage:       "causes this horizon process to ingest data from stellar-core into horizon's db",
	},
	&configOption{
		name:        "history-retention-count",
		configKey:   &c.HistoryRetentionCount,
		flagDefault: uint(0),
		usage:       "the minimum number of ledgers to maintain within horizon's history tables.  0 signifies an unlimited number of ledgers will be retained",
	},
	&configOption{
		name:        "history-stale-threshold",
		configKey:   &c.StaleThreshold,
		flagDefault: uint(0),
		usage:       "the maximum number of ledgers the history db is allowed to be out of date from the connected stellar-core db before horizon considers history stale",
	},
	&configOption{
		name:        "skip-cursor-update",
		configKey:   &c.SkipCursorUpdate,
		flagDefault: false,
		usage:       "causes the ingester to skip reporting the last imported ledger state to stellar-core",
	},
	&configOption{
		name:        "enable-asset-stats",
		configKey:   &c.EnableAssetStats,
		flagDefault: false,
		usage:       "enables asset stats during the ingestion and expose `/assets` endpoint, Enabling it has a negative impact on CPU",
	},
}

func main() {
	rootCmd.Execute()
}

func init() {
	rootCmd = &cobra.Command{
		Use:   "horizon",
		Short: "client-facing api server for the stellar network",
		Long:  "client-facing api server for the stellar network",
		Run: func(cmd *cobra.Command, args []string) {
			initApp(cmd, args)
			app.Serve()
		},
	}

	for _, co := range configOpts {

		// Bind the command line and environment variable name
		// Unless overriden, default to a transform like tls-key -> TLS_KEY
		if co.envVar == "" {
			co.envVar = strutils.KebabToConstantCase(co.name)
		}
		viper.BindEnv(co.name, co.envVar)
		// Initialise the persistent flags
		co.setFlag()
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
	// Check all required args were provided - needed for migrations check
	for _, co := range configOpts {
		co.require()
	}

	// Migrations should be checked as early as possible
	checkMigrations()

	// Initialise and validate the global configuration
	for _, co := range configOpts {
		co.setValue()
	}
	// Validate options that should be provided together
	validateBothOrNeither("tls-cert", "tls-key")
	validateBothOrNeither("loggly-token", "loggly-tag")
	validateBothOrNeither("rate-limit-redis-key", "redis-url")

	// Configure log file
	if c.LogFile != "" {
		logFile, err := os.OpenFile(c.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			log.DefaultLogger.Logger.Out = logFile
		} else {
			stdLog.Fatalf("Failed to open file to log: %s", err)
		}
	}

	// Configure log level
	log.DefaultLogger.Level = c.LogLevel

	config = c
	stdLog.Fatal(config)
}
