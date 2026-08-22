package cmd

import (
	"github.com/dn-11/wg-quick-op/quick"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// downCmd represents the down command
var downCmd = &cobra.Command{
	Use:   "down",
	Short: "down [interface name]",
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) != 1 {
			log.Error().Msg("down command requires exactly one interface name or regular expression")
			return
		}
		cfgs, err := quick.LoadMatchingConfigs(args[0])
		if err != nil {
			log.Err(err).Msg("failed to load matching configs")
		}
		for iface, cfg := range cfgs {
			err := quick.Down(cfg, iface, log.With().Str("iface", iface).Logger())
			if err != nil {
				log.Err(err).Msg("failed to down interface")
			}
		}
	},
}

func init() {
	rootCmd.AddCommand(downCmd)
}
