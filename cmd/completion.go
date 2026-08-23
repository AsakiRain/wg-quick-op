package cmd

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/dn-11/wg-quick-op/quick"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var bashCompletionDirs = []string{
	"/usr/share/bash-completion/completions",
	"/etc/bash_completion.d",
}

func completeInterfaceNames(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	names, err := quick.ListConfigNames()
	if err != nil {
		cobra.CompErrorln(err.Error())
		return nil, cobra.ShellCompDirectiveError | cobra.ShellCompDirectiveNoFileComp
	}

	matches := make([]string, 0, len(names))
	for _, name := range names {
		if strings.HasPrefix(name, toComplete) {
			matches = append(matches, name)
		}
	}
	return matches, cobra.ShellCompDirectiveNoFileComp
}

func installBashCompletion() {
	for _, dir := range bashCompletionDirs {
		info, err := os.Stat(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			log.Warn().Err(err).Str("path", dir).Msg("cannot inspect bash completion directory")
			continue
		}
		if !info.IsDir() {
			continue
		}

		path := filepath.Join(dir, "wg-quick-op")
		if err := rootCmd.GenBashCompletionFileV2(path, true); err != nil {
			log.Warn().Err(err).Str("path", path).Msg("cannot install bash completion")
			continue
		}
		log.Info().Str("path", path).Msg("installed bash completion")
		return
	}
	log.Info().Msg("bash completion directory not found, skip completion installation")
}

func uninstallBashCompletion() {
	for _, dir := range bashCompletionDirs {
		path := filepath.Join(dir, "wg-quick-op")
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			log.Warn().Err(err).Str("path", path).Msg("cannot remove bash completion")
		}
	}
}
