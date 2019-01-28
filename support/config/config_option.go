package config

import (
	stdLog "log"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stellar/go/support/strutils"
	"github.com/throttled/throttled"
)

// flagType implements a generic interface for the different command line flags,
// allowing them to be configured in a uniform way.
type flagType func(name string, value interface{}, usage string, rootCmd *cobra.Command) interface{}

var (
	stringFlag flagType = func(name string, value interface{}, usage string, rootCmd *cobra.Command) interface{} {
		return rootCmd.PersistentFlags().String(name, value.(string), usage)
	}
	intFlag flagType = func(name string, value interface{}, usage string, rootCmd *cobra.Command) interface{} {
		return rootCmd.PersistentFlags().Int(name, value.(int), usage)
	}
	uintFlag flagType = func(name string, value interface{}, usage string, rootCmd *cobra.Command) interface{} {
		return rootCmd.PersistentFlags().Uint(name, value.(uint), usage)
	}
	boolFlag flagType = func(name string, value interface{}, usage string, rootCmd *cobra.Command) interface{} {
		return rootCmd.PersistentFlags().Bool(name, value.(bool), usage)
	}
)

// ConfigOption is a complete description of the configuration of a command line option
type ConfigOption struct {
	Name           string              // e.g. "db-url"
	EnvVar         string              // e.g. "DATABASE_URL". Defaults to uppercase/underscore representation of name
	FlagDefault    interface{}         // A default if no option is provided. Set to "" if no default
	Required       bool                // Whether this option must be set for Horizon to run
	Usage          string              // Help text
	CustomSetValue func(*ConfigOption) // Optional function for custom validation/transformation
	ConfigKey      interface{}         // Pointer to the final key in the horizon.Config struct
}

// Init handles initialisation steps, including configuring and binding the env variable name.
func (co *ConfigOption) Init(cmd *cobra.Command) {
	// Bind the command line and environment variable name
	// Unless overriden, default to a transform like tls-key -> TLS_KEY
	if co.EnvVar == "" {
		co.EnvVar = strutils.KebabToConstantCase(co.Name)
	}
	viper.BindEnv(co.Name, co.EnvVar)
	// Initialise the persistent flags
	co.setFlag(cmd)
}

// Require checks that a required string configuration option is not empty, raising a user error if it is.
func (co *ConfigOption) Require() {
	if co.Required == true && viper.GetString(co.Name) == "" {
		stdLog.Fatalf("Invalid config: %s is blank. Please specify --%s on the command line or set the %s environment variable.", co.Name, co.Name, co.EnvVar)
	}
}

// SetValue sets a value in the global config, using a custom function, if one was provided.
func (co *ConfigOption) SetValue() {
	// Use a custom setting function, if one is provided
	if co.CustomSetValue != nil {
		co.CustomSetValue(co)
		// Otherwise, just set the provided arg directly
	} else if co.ConfigKey != nil {
		co.setSimpleValue()
	}
}

// setSimpleValue sets the value of a ConfigOption's configKey, based on the ConfigOption's default type.
func (co *ConfigOption) setSimpleValue() {
	if co.ConfigKey != nil {
		switch co.FlagDefault.(type) {
		case string:
			*(co.ConfigKey.(*string)) = viper.GetString(co.Name)
		case int:
			*(co.ConfigKey.(*int)) = viper.GetInt(co.Name)
		case bool:
			*(co.ConfigKey.(*bool)) = viper.GetBool(co.Name)
		case uint:
			*(co.ConfigKey.(*uint)) = uint(viper.GetInt(co.Name))
		}
	}
}

// setFlag sets the correct pFlag type, based on the ConfigOption's default type.
func (co *ConfigOption) setFlag(cmd *cobra.Command) {
	switch co.FlagDefault.(type) {
	case string:
		stringFlag(co.Name, co.FlagDefault, co.Usage, cmd)
	case int:
		intFlag(co.Name, co.FlagDefault, co.Usage, cmd)
	case bool:
		boolFlag(co.Name, co.FlagDefault, co.Usage, cmd)
	case uint:
		uintFlag(co.Name, co.FlagDefault, co.Usage, cmd)
	}
}

// SetDuration converts a command line int to a duration, and stores it in the final config.
func SetDuration(co *ConfigOption) {
	*(co.ConfigKey.(*time.Duration)) = time.Duration(viper.GetInt(co.Name)) * time.Second
}

// SetURL converts a command line string to a URL, and stores it in the final config.
func SetURL(co *ConfigOption) {
	urlString := viper.GetString(co.Name)
	if urlString != "" {
		urlType, err := url.Parse(urlString)
		if err != nil {
			stdLog.Fatalf("Unable to parse URL: %s/%v", urlString, err)
		}
		*(co.ConfigKey.(**url.URL)) = urlType
	}
}

// SetLogLevel validates and sets the log level in the final config.
func SetLogLevel(co *ConfigOption) {
	ll, err := logrus.ParseLevel(viper.GetString(co.Name))
	if err != nil {
		stdLog.Fatalf("Could not parse log-level: %v", viper.GetString(co.Name))
	}
	*(co.ConfigKey.(*logrus.Level)) = ll
}

// SetRateLimit converts a command line rate limit, and sets rate and burst limiting in the final config.
func SetRateLimit(co *ConfigOption) {
	var rateLimit *throttled.RateQuota = nil
	perHourRateLimit := viper.GetInt(co.Name)
	if perHourRateLimit != 0 {
		rateLimit = &throttled.RateQuota{
			MaxRate:  throttled.PerHour(perHourRateLimit),
			MaxBurst: 100,
		}
		*(co.ConfigKey.(**throttled.RateQuota)) = rateLimit
	}
}
