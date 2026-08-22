package cmd

import (
	"github.com/dn-11/wg-quick-op/daemon"
	"github.com/dn-11/wg-quick-op/lib/dns"

	"github.com/spf13/cobra"
)

// serviceCmd represents the service command
var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "run service in backend",
	Long: `run service in backend. 
the service will read config file, according to the config file, it do ddns resolve updating, specific interface upping and so on`,
	Run: func(cmd *cobra.Command, args []string) {
		dns.Init()
		daemon.Serve()
	},
}

func init() {
	rootCmd.AddCommand(serviceCmd)
}
