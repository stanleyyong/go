package config

import (
	"go/types"
	stdLog "log"
	"net/url"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stellar/go/support/strutils"
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
	OptType        types.BasicKind     // The type of this option, e.g. types.Bool
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
		switch co.OptType {
		case types.String:
			*(co.ConfigKey.(*string)) = viper.GetString(co.Name)
		case types.Int:
			*(co.ConfigKey.(*int)) = viper.GetInt(co.Name)
		case types.Bool:
			*(co.ConfigKey.(*bool)) = viper.GetBool(co.Name)
		case types.Uint:
			*(co.ConfigKey.(*uint)) = uint(viper.GetInt(co.Name))
		}
	}
}

// setFlag sets the correct pFlag type, based on the ConfigOption's default type.
func (co *ConfigOption) setFlag(cmd *cobra.Command) {
	switch co.OptType {
	case types.String:
		co.setDefault()
		stringFlag(co.Name, co.FlagDefault, co.Usage, cmd)
	case types.Int:
		intFlag(co.Name, co.FlagDefault, co.Usage, cmd)
	case types.Bool:
		boolFlag(co.Name, co.FlagDefault, co.Usage, cmd)
	case types.Uint:
		uintFlag(co.Name, co.FlagDefault, co.Usage, cmd)
	}
}

// setDefault sets an empty string, if no default has been specified. Other types have no obvious default, so
// attempting to set their defaults is an error.
func (co *ConfigOption) setDefault() {
	if co.FlagDefault != nil {
		return
	}
	if co.OptType != types.String {
		stdLog.Fatal("Non-string options require a default to be set")
	}
	co.FlagDefault = ""
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
