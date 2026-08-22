package conf

import (
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
)

func TestParseConfig(t *testing.T) {
	Init("config-sample.toml", RuntimeCLI, false)
	assert.Equal(t, zerolog.InfoLevel, Log.ActiveLevel)
	assert.Equal(t, zerolog.ErrorLevel, Log.ServiceLevel)
	assert.Equal(t, zerolog.InfoLevel, Log.CLILevel)
	assert.Equal(t, 5, EnhancedDNS.DirectResolver.MaxCnameDepth)
	t.Logf("config: %+v", DDNS)
	t.Logf("config: %+v", StartOnBoot)
	t.Logf("config: %+v", EnhancedDNS)
	t.Logf("config: %+v", Wireguard)
	t.Logf("config: %+v", Log)
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  zerolog.Level
	}{
		{name: "configured", value: "debug", want: zerolog.DebugLevel},
		{name: "empty defaults to info", value: "", want: zerolog.InfoLevel},
		{name: "invalid defaults to info", value: "nope", want: zerolog.InfoLevel},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseLogLevel("log.test", tt.value))
		})
	}
}
