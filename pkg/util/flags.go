package util

import (
	"flag"
	"os"
	"strings"

	"github.com/golang/glog"
	"github.com/spf13/pflag"
)

// EnvFromFlag converts a flag name to an environment variable name.
// Flags are assumed to be in the format [a-z0-9](-[a-z0-9])*
func EnvFromFlag(prefix, name string) string {
	return prefix + "_" + strings.ToUpper(strings.Replace(name, "-", "_", -1))
}

// ParseFlagsFromEnv takes a flag set and sets the values from the
// environment. It uses EnvFromFlag to generate the environment variable
// name so flags must be in the format [a-z0-9](-[a-z0-9])*
func ParseFlagsFromEnv(prefix string, fs *flag.FlagSet) {
	fs.VisitAll(func(f *flag.Flag) {
		env := EnvFromFlag(prefix, f.Name)
		val := os.Getenv(env)
		if val != "" {
			glog.V(5).Infof("found %s in environment", env)
			fs.Set(f.Name, val)
		}
	})
}

// ParsePFlagsFromEnv takes a flag set and sets the values from the
// environment. It uses EnvFromFlag to generate the environment variable
// name so flags must be in the format [a-z0-9](-[a-z0-9])*
func ParsePFlagsFromEnv(prefix string, fs *pflag.FlagSet) {
	fs.VisitAll(func(f *pflag.Flag) {
		env := EnvFromFlag(prefix, f.Name)
		val := os.Getenv(env)
		if val != "" && !f.Changed {
			glog.V(5).Infof("found %s in environment", env)
			fs.Set(f.Name, val)
		}
	})
}
