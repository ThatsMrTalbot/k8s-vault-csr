package main

import (
	"flag"
	"fmt"
	"runtime"

	"github.com/golang/glog"
	"github.com/spf13/cobra"
	"github.com/spf13/cobra/doc"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/cmd/bootstrap"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/cmd/controller"
	"github.com/thatsmrtalbot/k8s-vault-csr/pkg/util"
	"k8s.io/apiserver/pkg/util/logs"
)

// EnvPrefix is the prefix used when setting flags via environment vars
const EnvPrefix = "K8S_VAULT_CSR"

// Version is the application version set by the compiler
var Version = "devel"

var rootCmd = &cobra.Command{
	Use:   "k8s-vault-csr",
	Short: "tools for managing kubernetes certs with vault",
	Args:  cobra.NoArgs,
	Long: `Kubernetes Vault CSR tools.

  Tools to manage and bootstrap Kubernetes certificates
  using Vault.
	
  It can sign Kubernetes CSRs as a controller in order
  to facilitate Node cert rotation. 
  
  It also contains a tool for generating a bootstrap
  certificates that nodes can use in order to generate
  their initial certificate`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		util.ParsePFlagsFromEnv(EnvPrefix, cmd.Flags())
	},
}

var docsCmd = &cobra.Command{
	Use:   "docs [path]",
	Short: "generate markdown docs for commands",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		err := doc.GenMarkdownTree(rootCmd, args[0])
		if err != nil {
			glog.Exitf("error generating markdown docs: %s", err)
		}
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "print the command version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("version=%s runtime=%s\n", rootCmd.Version, runtime.Version())
	},
}

// init sets up logs and parses flags
func init() {
	logs.InitLogs()
	rootCmd.Version = Version
	rootCmd.AddCommand(bootstrap.Cmd, controller.Cmd, docsCmd, versionCmd)

	// Setup glog
	rootCmd.PersistentFlags().AddGoFlagSet(flag.CommandLine)
	rootCmd.Flag("logtostderr").DefValue = "true"
	rootCmd.Flag("logtostderr").Value.Set("true")
	flag.CommandLine.Parse(nil)
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		glog.Exitf("error: %s", err)
	}
}
