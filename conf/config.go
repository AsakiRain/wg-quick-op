package conf

import (
	_ "embed"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
)

//go:embed config-sample.toml
var configSample []byte

var DDNS struct {
	Interval       time.Duration
	IfaceOnly      []string
	IfaceSkip      []string
	HandleShakeMax time.Duration
}

var StartOnBoot struct {
	Enabled   bool
	IfaceOnly []string
	IfaceSkip []string
}

var EnhancedDNS struct {
	DirectResolver struct {
		Enabled       bool
		ROAFinder     []string
		IPv4Only      bool
		MaxCnameDepth int
	}
}

// Wireguard used to change default value of Wireguard
var Wireguard struct {
	MTU        int
	RandomPort bool
}

var Log struct {
	ServiceLevel zerolog.Level
	CLILevel     zerolog.Level
	ActiveLevel  zerolog.Level
}

type RuntimeMode int

const (
	RuntimeCLI RuntimeMode = iota
	RuntimeService
)

var (
	// 配置文件发生变化时，使用这两个状态重新选择当前进程的日志级别。
	runtimeMode RuntimeMode
	verboseMode bool
)

// 读取全局配置，并按照当前运行角色初始化日志级别。
func Init(file string, mode RuntimeMode, verbose bool) {
	runtimeMode = mode
	verboseMode = verbose

	// 短路错误处理，如果配置不存在，写入一份默认配置后就退出。
	if _, err := os.Stat(file); err != nil {
		if !os.IsNotExist(err) {
			log.Fatal().Err(err).Msgf("get stat of %s failed", file)
		}
		log.Info().Msgf("config not existed, creating at %s", file)
		created, err := os.Create(file)
		if err != nil {
			log.Fatal().Err(err).Msgf("create config at %s failed", file)
		}
		defer created.Close()
		if _, err := created.Write(configSample); err != nil {
			log.Fatal().Err(err).Msgf("write config at %s failed", file)
		}
	}

	// 读取配置文件
	viper.SetConfigFile(file)

	// 先设默认值
	viper.SetDefault("ddns.interval", 60)
	viper.SetDefault("ddns.handshake_max", 150)
	viper.SetDefault("enhanced_dns.direct_resolver.ipv4_only", false)
	viper.SetDefault("enhanced_dns.direct_resolver.max_cname_depth", 5)
	viper.SetDefault("wireguard.MTU", 1420)
	viper.SetDefault("wireguard.random_port", false)
	// service 使用 service_log_level，CLI 使用 cli_log_level
	// verbose 会覆盖配置并启用 trace。
	viper.SetDefault("log.service_log_level", "info")
	viper.SetDefault("log.cli_log_level", "info")

	// 再读配置
	if err := viper.ReadInConfig(); err != nil {
		log.Fatal().Err(err).Msgf("read config from %s failed", file)
	}

	// 将配置覆盖到全局变量中，并设置自动重载配置
	syncConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		syncConfig()
	})
	viper.WatchConfig()
}

// 将用户配置覆盖到全局变量中，供其他模块使用
func syncConfig() {
	DDNS.Interval = time.Duration(viper.GetInt("ddns.interval")) * time.Second
	DDNS.HandleShakeMax = time.Duration(viper.GetInt("ddns.handshake_max")) * time.Second
	DDNS.IfaceOnly = viper.GetStringSlice("ddns.only_ifaces")
	DDNS.IfaceSkip = viper.GetStringSlice("ddns.skip_ifaces")

	StartOnBoot.Enabled = viper.GetBool("start_on_boot.enabled")
	StartOnBoot.IfaceOnly = viper.GetStringSlice("start_on_boot.only_ifaces")
	StartOnBoot.IfaceSkip = viper.GetStringSlice("start_on_boot.skip_ifaces")

	EnhancedDNS.DirectResolver.Enabled = viper.GetBool("enhanced_dns.direct_resolver.enabled")
	EnhancedDNS.DirectResolver.ROAFinder = viper.GetStringSlice("enhanced_dns.direct_resolver.roa_finder")
	EnhancedDNS.DirectResolver.IPv4Only = viper.GetBool("enhanced_dns.direct_resolver.ipv4_only")
	EnhancedDNS.DirectResolver.MaxCnameDepth = viper.GetInt("enhanced_dns.direct_resolver.max_cname_depth")

	// 新配置优先；缺少任一角色的独立配置时，都回退到旧的 log.level。
	serviceKey := "log.service_log_level"
	serviceValue := viper.GetString(serviceKey)
	if !viper.InConfig(serviceKey) {
		log.Warn().Msg("log.service_log_level is not configured, fallback to log.level")
		serviceKey = "log.level"
		serviceValue = viper.GetString(serviceKey)
	}
	cliKey := "log.cli_log_level"
	cliValue := viper.GetString(cliKey)
	if !viper.InConfig(cliKey) {
		log.Warn().Msg("log.cli_log_level is not configured, fallback to log.level")
		cliKey = "log.level"
		cliValue = viper.GetString(cliKey)
	}

	Log.ServiceLevel = parseLogLevel(serviceKey, serviceValue)
	Log.CLILevel = parseLogLevel(cliKey, cliValue)

	level := Log.CLILevel
	source := cliKey
	if runtimeMode == RuntimeService {
		level = Log.ServiceLevel
		source = serviceKey
	}
	if verboseMode {
		level = zerolog.TraceLevel
		source = "--verbose"
	}
	Log.ActiveLevel = level
	zerolog.SetGlobalLevel(level)
	log.Trace().Str("log_level_source", source).Str("log_level", level.String()).Msg("log level configured")

	Wireguard.MTU = viper.GetInt("wireguard.MTU")
	Wireguard.RandomPort = viper.GetBool("wireguard.random_port")
}

func parseLogLevel(key, value string) zerolog.Level {
	if value == "" {
		return zerolog.InfoLevel
	}
	level, err := zerolog.ParseLevel(value)
	if err != nil {
		log.Warn().Str(key, value).Msg("invalid log level, fallback to info; valid levels: trace, debug, info, warn, error, fatal, panic")
		return zerolog.InfoLevel
	}
	return level
}
