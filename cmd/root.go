package cmd

import (
	"os"

	"github.com/dn-11/wg-quick-op/conf"
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "wg-quick-op",
	Short: "wg-quick-op is a tool to manage wireguard interface",
}

var (
	config string
)

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Verbose output")
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		// 补全只需要读取配置文件名，不初始化运行时配置
		for current := cmd; current != nil; current = current.Parent() {
			if current.Name() == "completion" || current.Name() == cobra.ShellCompRequestCmd || current.Name() == cobra.ShellCompNoDescRequestCmd {
				return
			}
		}
		verbose, _ := cmd.Flags().GetBool("verbose")
		// 根据命令类型设置运行模式
		mode := conf.RuntimeCLI
		if cmd == serviceCmd {
			mode = conf.RuntimeService
		}
		conf.Init(config, mode, verbose)
	}
	rootCmd.PersistentFlags().StringVarP(&config, "config", "c", "/etc/wg-quick-op.toml", "config file path")
}
