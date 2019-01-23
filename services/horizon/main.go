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

var rootCmd *cobra.Command

func main() {
	// out := strutils.KebabToConstantCase("per-hour-rate-limit")
	// stdLog.Fatal(out)
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

	type flagType func(name string, value interface{}, usage string) interface{}
	var (
		stringFlag flagType = func(name string, value interface{}, usage string) interface{} {
			return rootCmd.PersistentFlags().String(name, value.(string), usage)
		}
		intFlag flagType = func(name string, value interface{}, usage string) interface{} {
			return rootCmd.PersistentFlags().Int(name, value.(int), usage)
		}
		boolFlag flagType = func(name string, value interface{}, usage string) interface{} {
			return rootCmd.PersistentFlags().Bool(name, value.(bool), usage)
		}
	)

	type ericConfig struct {
		name        string
		envVar      string
		flagType    flagType
		flagDefault interface{}
		usage       string
	}

	configOpts := []ericConfig{
		ericConfig{name: "port", flagType: intFlag, flagDefault: 8000, usage: "tcp port to listen on for http requests"},
		ericConfig{name: "stellar-core-db-url", envVar: "STELLAR_CORE_DATABASE_URL", flagType: stringFlag, usage: "stellar-core postgres database to connect with"},
		ericConfig{name: "db-url", envVar: "DATABASE_URL", flagType: stringFlag, usage: "horizon postgres database to connect with"},
		ericConfig{name: "stellar-core-url", flagType: stringFlag, usage: "stellar-core to connect with (for http commands)"},
		ericConfig{name: "max-db-connections", flagType: intFlag, flagDefault: 20, usage: "max db connections (per DB), may need to be increased when responses are slow but DB CPU is normal"},
		ericConfig{name: "sse-update-frequency", flagType: intFlag, flagDefault: 5}, usage: "defines how often streams should check if there's a new ledger (in seconds), may need to increase in case of big number of streams"},
		ericConfig{name: "connection-timeout", flagType: intFlag, flagDefault: 55, usage: "defines the timeout of connection after which 504 response will be sent or stream will be closed, if Horizon is behind a load balancer with idle connection timeout, this should be set to a few seconds less that idle timeout"},
		ericConfig{name: "per-hour-rate-limit", flagType: intFlag, flagDefault: 3600, usage: "max count of requests allowed in a one hour period, by remote ip address"},
		ericConfig{name: "rate-limit-redis-key", flagType: stringFlag, usage: "redis key for storing rate limit data, useful when deploying a cluster of Horizons, ignored when redis-url is empty"},
		ericConfig{name: "redis-url", flagType: stringFlag, usage: "redis to connect with, for rate limiting"},
		// ericConfig{name: "ruby-horizon-url", flagType: 
	},

		// ericConfig{name: "friendbot-url"},
		// ericConfig{name: "log-level"},
		// ericConfig{name: "log-file"},
		// ericConfig{name: "sentry-dsn"},
		// ericConfig{name: "loggly-token"},
		// ericConfig{name: "loggly-tag"},
		// ericConfig{name: "tls-cert"},
		// ericConfig{name: "tls-key"},
		ericConfig{name: "ingest", flagType: boolFlag, flagDefault: false, usage: "causes this horizon process to ingest data from stellar-core into horizon's db"},
		// ericConfig{name: "network-passphrase"},
		// ericConfig{name: "history-retention-count"},
		// ericConfig{name: "history-stale-threshold"},
		// ericConfig{name: "skip-cursor-update"},
		// ericConfig{name: "enable-asset-stats"},
		// ericConfig{name: "max-path-length"},
	}

	for i := range configOpts {
		ec := &configOpts[i]

		if ec.envVar == "" {
			ec.envVar = strutils.KebabToConstantCase(ec.name)
			viper.BindEnv(ec.name, ec.envVar)
		}

		if ec.flagType == nil {
			stdLog.Fatal("Missing flagType in definition of config option ", ec.name)
		}

		if ec.flagDefault == nil {
			ec.flagDefault = ""
		}
		ec.flagType(ec.name, ec.flagDefault, ec.usage)
	}

	// For testing purposes only
	stdLog.Fatal(configOpts)

	// Configure flag types
	rootCmd.PersistentFlags().String(
		"friendbot-url",
		"",
		"friendbot service to redirect to",
	)

	rootCmd.PersistentFlags().String(
		"log-level",
		"info",
		"Minimum log severity (debug, info, warn, error) to log",
	)

	rootCmd.PersistentFlags().String(
		"log-file",
		"",
		"Name of the file where logs will be saved (leave empty to send logs to stdout)",
	)

	rootCmd.PersistentFlags().String(
		"sentry-dsn",
		"",
		"Sentry URL to which panics and errors should be reported",
	)

	rootCmd.PersistentFlags().String(
		"loggly-token",
		"",
		"Loggly token, used to configure log forwarding to loggly",
	)

	rootCmd.PersistentFlags().String(
		"loggly-tag",
		"horizon",
		"Tag to be added to every loggly log event",
	)

	rootCmd.PersistentFlags().String(
		"tls-cert",
		"",
		"The TLS certificate file to use for securing connections to horizon",
	)

	rootCmd.PersistentFlags().String(
		"tls-key",
		"",
		"The TLS private key file to use for securing connections to horizon",
	)

	rootCmd.PersistentFlags().Bool(
		"ingest",
		false,
		"causes this horizon process to ingest data from stellar-core into horizon's db",
	)

	rootCmd.PersistentFlags().String(
		"network-passphrase",
		network.TestNetworkPassphrase,
		"Override the network passphrase",
	)

	rootCmd.PersistentFlags().Uint(
		"history-retention-count",
		0,
		"the minimum number of ledgers to maintain within horizon's history tables.  0 signifies an unlimited number of ledgers will be retained",
	)

	rootCmd.PersistentFlags().Uint(
		"history-stale-threshold",
		0,
		"the maximum number of ledgers the history db is allowed to be out of date from the connected stellar-core db before horizon considers history stale",
	)

	rootCmd.PersistentFlags().Bool(
		"enable-asset-stats",
		false,
		"enables asset stats during the ingestion and expose `/assets` endpoint,  Enabling it has a negative impact on CPU",
	)

	rootCmd.PersistentFlags().Uint(
		"max-path-length",
		4,
		"the maximum number of assets on the path in `/paths` endpoint",
	)

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
	if viper.GetString("db-url") == "" {
		stdLog.Fatal("Invalid config: db-url is blank.  Please specify --db-url on the command line or set the DATABASE_URL environment variable.")
	}

	if viper.GetString("stellar-core-db-url") == "" {
		stdLog.Fatal("Invalid config: stellar-core-db-url is blank.  Please specify --stellar-core-db-url on the command line or set the STELLAR_CORE_DATABASE_URL environment variable.")
	}

	if viper.GetString("stellar-core-url") == "" {
		stdLog.Fatal("Invalid config: stellar-core-url is blank.  Please specify --stellar-core-url on the command line or set the STELLAR_CORE_URL environment variable.")
	}

	if viper.GetString("network-passphrase") == "" {
		stdLog.Fatal("Invalid config: network-passphrase is blank.  Please specify --network-passphrase on the command line or set the NETWORK_PASSPHRASE environment variable.")
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

	ll, err := logrus.ParseLevel(viper.GetString("log-level"))

	if err != nil {
		stdLog.Fatalf("Could not parse log-level: %v", viper.GetString("log-level"))
	}

	log.DefaultLogger.Level = ll

	lf := viper.GetString("log-file")
	if lf != "" {
		logFile, err := os.OpenFile(lf, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err == nil {
			log.DefaultLogger.Logger.Out = logFile
		} else {
			stdLog.Fatal("Failed to log to file")
		}
	}

	cert, key := viper.GetString("tls-cert"), viper.GetString("tls-key")

	switch {
	case cert != "" && key == "":
		stdLog.Fatal("Invalid TLS config: key not configured")
	case cert == "" && key != "":
		stdLog.Fatal("Invalid TLS config: cert not configured")
	}

	var friendbotURL *url.URL
	friendbotURLString := viper.GetString("friendbot-url")
	if friendbotURLString != "" {
		friendbotURL, err = url.Parse(friendbotURLString)
		if err != nil {
			stdLog.Fatalf("Unable to parse URL: %s/%v", friendbotURLString, err)
		}
	}

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
