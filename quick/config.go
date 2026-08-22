package quick

import (
	"bytes"
	"encoding"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/dn-11/wg-quick-op/conf"
	"github.com/dn-11/wg-quick-op/lib/dns"
	"github.com/rs/zerolog/log"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var wireguardConfigDir = "/etc/wireguard"

// Config represents full wg-quick like config structure
type Config struct {
	wgtypes.Config
	configText       []byte
	configScanned    bool
	interfaceEntries []configEntry
	interfaceLoaded  bool
	peerSections     [][]configEntry
	peersLoaded      bool
	peerEndpoints    map[wgtypes.Key]peerEndpoint

	// Address list of IP (v4 or v6) addresses (optionally with CIDR masks) to be assigned to the interface. May be specified multiple times.
	Address []net.IPNet

	// list of IP (v4 or v6) addresses to be set as the interface’s DNS servers. May be specified multiple times. Upon bringing the interface up, this runs ‘resolvconf -a tun.INTERFACE -m 0 -x‘ and upon bringing it down, this runs ‘resolvconf -d tun.INTERFACE‘. If these particular invocations of resolvconf(8) are undesirable, the PostUp and PostDown keys below may be used instead.
	DNS []net.IP

	// MTU is automatically determined from the endpoint addresses or the system default route, which is usually a sane choice. However, to manually specify an MTU to override this automatic discovery, this value may be specified explicitly.
	MTU int

	// Table — Controls the routing table to which routes are added.
	Table *int
	// TableSet tracks whether Table was explicitly configured.
	TableSet bool

	// PreUp, PostUp, PreDown, PostDown — script snippets which will be executed by bash(1) before/after setting up/tearing down the interface, most commonly used to configure custom DNS options or firewall rules. The special string ‘%i’ is expanded to INTERFACE. Each one may be specified multiple times, in which case the commands are executed in order.
	PreUp    []string
	PostUp   []string
	PreDown  []string
	PostDown []string

	// RouteProtocol to set on the route. See linux/rtnetlink.h  Use value > 4 or default 0
	RouteProtocol int

	// RouteMetric sets this metric on all managed routes. Lower number means pick this one
	RouteMetric int

	// Address label to set on the link
	AddressLabel string

	// WireGuard-go binary path, left empty for kernel WireGuard
	WgBin string

	// MTUSet tracks whether MTU was explicitly configured.
	MTUSet bool
}

func newConfig() *Config {
	return &Config{
		Table: new(int),
		MTU:   conf.Wireguard.MTU,
	}
}

var _ encoding.TextMarshaler = (*Config)(nil)

func (cfg *Config) String() string {
	b, err := cfg.MarshalText()
	if err != nil {
		panic(err)
	}
	return string(b)
}

func serializeKey(key *wgtypes.Key) string {
	return base64.StdEncoding.EncodeToString(key[:])
}

func toSeconds(duration time.Duration) int {
	return int(duration / time.Second)
}

func tableString(table *int) string {
	if table == nil {
		return "off"
	}
	return strconv.Itoa(*table)
}

func fwmarkString(mark *int) string {
	if mark == nil {
		return ""
	}
	if *mark == 0 {
		return "off"
	}
	return strconv.Itoa(*mark)
}

var funcMap = template.FuncMap(map[string]interface{}{
	"wgKey":        serializeKey,
	"toSeconds":    toSeconds,
	"tableString":  tableString,
	"fwmarkString": fwmarkString,
})

var cfgTemplate = template.Must(
	template.
		New("wg-cfg").
		Funcs(funcMap).
		Parse(wgtypeTemplateSpec))

func (cfg *Config) MarshalText() (text []byte, err error) {
	buff := &bytes.Buffer{}
	if err := cfgTemplate.Execute(buff, cfg); err != nil {
		return nil, err
	}
	return buff.Bytes(), nil
}

// wireguard 允许写多条 up/down 脚本，所以修改 if 为 range，为模板产生多行切片内容
const wgtypeTemplateSpec = `[Interface]
{{- range .Address }}
Address = {{ . }}
{{- end }}
{{- range .DNS }}
DNS = {{ . }}
{{- end }}
PrivateKey = {{ .PrivateKey | wgKey }}
{{- if .ListenPort }}{{ "\n" }}ListenPort = {{ .ListenPort }}{{ end }}
{{- if .FirewallMark }}{{ "\n" }}FwMark = {{ .FirewallMark | fwmarkString }}{{ end }}
{{- if .MTUSet }}{{ "\n" }}MTU = {{ .MTU }}{{ end }}
{{- if .TableSet }}{{ "\n" }}Table = {{ .Table | tableString }}{{ end }}
{{- if .WgBin }}{{ "\n" }}WgBin = {{ .WgBin }}{{ end }}
{{- range .PreUp }}{{ "\n" }}PreUp = {{ . }}{{ end }}
{{- range .PostUp }}{{ "\n" }}PostUp = {{ . }}{{ end }}
{{- range .PreDown }}{{ "\n" }}PreDown = {{ . }}{{ end }}
{{- range .PostDown }}{{ "\n" }}PostDown = {{ . }}{{ end }}
{{- range .Peers }}
{{- "\n" }}
[Peer]
PublicKey = {{ .PublicKey | wgKey }}
AllowedIPs = {{ range $i, $el := .AllowedIPs }}{{if $i}}, {{ end }}{{ $el }}{{ end }}
{{- if .PresharedKey }}{{ "\n" }}PresharedKey = {{ .PresharedKey }}{{ end }}
{{- if .PersistentKeepaliveInterval }}{{ "\n" }}PersistentKeepalive = {{ .PersistentKeepaliveInterval | toSeconds }}{{ end }}
{{- if .Endpoint }}{{ "\n" }}Endpoint = {{ .Endpoint }}{{ end }}
{{- end }}
`

// ParseKey parses the base64 encoded wireguard private key
func ParseKey(key string) (wgtypes.Key, error) {
	var pkey wgtypes.Key
	pkeySlice, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return pkey, err
	}
	copy(pkey[:], pkeySlice[:])
	return pkey, nil
}

type parseState int

const (
	unknown parseState = iota
	inter              = iota
	peer               = iota
)

// 保存一行命令的行号、key、value
type configEntry struct {
	line  int
	key   string
	value string
}

// 分区域保存配置文件每行的内容
type configSections struct {
	interfaceEntries []configEntry
	peerSections     [][]configEntry
}

type peerEndpoint struct {
	peerIndex int
	raw       string
}

func (cfg *Config) setConfigText(text []byte) {
	next := newConfig()
	next.configText = append([]byte(nil), text...)
	*cfg = *next
}

// 工具函数，确保在解析具体配置前已经解析过 key = value 的内容
func (cfg *Config) ensureConfigScanned() error {
	if cfg.configScanned {
		return nil
	}
	if cfg.configText == nil {
		return fmt.Errorf("config text is not set")
	}
	return cfg.scanConfig()
}

// 扫描一遍配置文件，按 [Interface] 和 [Peer] 分区保存每行的内容。
// 函数只要求配置文件符合 key = value 的格式，具体的合法性检查交给各区域的解析函数
func (cfg *Config) scanConfig() error {
	var sections configSections
	state := unknown
	for no, line := range strings.Split(string(cfg.configText), "\n") {
		line, _, _ = strings.Cut(line, "#")
		ln := strings.TrimSpace(line)
		if len(ln) == 0 {
			continue
		}
		switch ln {
		case "[Interface]":
			state = inter
			continue
		case "[Peer]":
			state = peer
			sections.peerSections = append(sections.peerSections, nil) // 为每个 Peer 区域创建一个新的切片
			continue
		default:
			lhs, rhs, found := strings.Cut(ln, "=")
			if !found { // 不符合 key = value 的格式，直接报错
				return fmt.Errorf("cannot parse line %d, missing =", no+1)
			}
			entry := configEntry{
				line:  no + 1,
				key:   strings.TrimSpace(lhs),
				value: strings.TrimSpace(rhs),
			}

			switch state {
			case inter:
				sections.interfaceEntries = append(sections.interfaceEntries, entry)
			case peer:
				last := len(sections.peerSections) - 1
				sections.peerSections[last] = append(sections.peerSections[last], entry)
			default:
				return fmt.Errorf("[line %d] cannot parse, unknown state", no+1)
			}
		}
	}

	cfg.configText = nil
	cfg.configScanned = true
	cfg.interfaceEntries = sections.interfaceEntries
	cfg.peerSections = sections.peerSections
	return nil
}

// 从 interfaceEntries 解析 [Interface] 区域的配置，解析成功后 interfaceEntries 清空，interfaceLoaded 置为 true
func (cfg *Config) ParseInterface() error {
	if err := cfg.ensureConfigScanned(); err != nil {
		return err
	}
	if cfg.interfaceLoaded {
		return nil
	}

	next := *cfg
	for _, entry := range cfg.interfaceEntries {
		if err := parseInterfaceLine(&next, entry.key, entry.value); err != nil {
			return fmt.Errorf("[line %d]: %v", entry.line, err)
		}
	}
	next.interfaceEntries = nil
	next.interfaceLoaded = true
	*cfg = next
	return nil
}

// 从 peerSections 解析 [Peer] 区域的配置，解析成功后 peerSections 清空，peersLoaded 置为 true
func (cfg *Config) LoadPeers() error {
	if err := cfg.ensureConfigScanned(); err != nil {
		return err
	}
	if cfg.peersLoaded {
		return nil
	}
	if cfg.peerSections == nil {
		cfg.peersLoaded = true
		return nil
	}

	peers := make([]wgtypes.PeerConfig, 0, len(cfg.peerSections))
	peerEndpoints := make(map[wgtypes.Key]peerEndpoint)

	for peerIndex, section := range cfg.peerSections {
		var peerCfg wgtypes.PeerConfig
		var rawEndpoint string

		for _, entry := range section {
			if err := parsePeerLine(&peerCfg, entry.key, entry.value, &rawEndpoint); err != nil {
				return fmt.Errorf("[line %d]: %v", entry.line, err)
			}
		}
		peers = append(peers, peerCfg)
		if rawEndpoint != "" {
			peerEndpoints[peerCfg.PublicKey] = peerEndpoint{peerIndex: peerIndex, raw: rawEndpoint}
		}
	}

	cfg.Peers = peers
	cfg.peerEndpoints = peerEndpoints
	cfg.peerSections = nil
	cfg.peersLoaded = true
	return nil
}

// 将 peerEndpoints 中的 endpoint 解析为 net.UDPAddr，解析成功后按记录的下标写入 Peers
func (cfg *Config) ResolveEndpoints() error {
	if !cfg.peersLoaded {
		return fmt.Errorf("peers must be loaded before resolving endpoints")
	}
	for key := range cfg.peerEndpoints {
		if err := cfg.ResolveEndpoint(key); err != nil {
			log.Warn().Err(err).Str("peer", key.String()).Msg("resolve endpoint")
		}
	}
	return nil
}

// 根据 key 找出对应 peer 的原始 endpoint 字符串，解析为 net.UDPAddr 并写入 Peers。
// 由于该函数被 DDNS 调用，而运行时配置只能拿到 peer key，所以函数签名与批量解析不同
func (cfg *Config) ResolveEndpoint(key wgtypes.Key) error {
	if !cfg.peersLoaded {
		return fmt.Errorf("peers must be loaded before resolving endpoints")
	}
	endpoint, ok := cfg.peerEndpoints[key]
	if !ok {
		return nil
	}
	if endpoint.peerIndex < 0 || endpoint.peerIndex >= len(cfg.Peers) {
		return fmt.Errorf("peer %s has invalid index %d", key, endpoint.peerIndex)
	}
	if cfg.Peers[endpoint.peerIndex].PublicKey != key {
		return fmt.Errorf("peer %s does not match index %d", key, endpoint.peerIndex)
	}

	addr, err := dns.ResolveUDPAddrImpl("", endpoint.raw)
	if err != nil {
		return err
	}
	cfg.Peers[endpoint.peerIndex].Endpoint = addr
	return nil
}

// 返回一个 map，key 为 peer 的 PublicKey，value 为原始 endpoint 字符串
func (cfg *Config) UnresolvedEndpoints() map[wgtypes.Key]string {
	result := make(map[wgtypes.Key]string, len(cfg.peerEndpoints))
	for key, endpoint := range cfg.peerEndpoints {
		result[key] = endpoint.raw
	}
	return result
}

// 从正则表达式加载一组匹配的配置文件，返回一个 map，key 为配置文件名，value 为解析后的 Config
func LoadMatchingConfigs(pattern string) (map[string]*Config, error) {
	if !strings.HasPrefix(pattern, "^") {
		pattern = "^" + pattern
	}
	if !strings.HasSuffix(pattern, "$") {
		pattern = pattern + "$"
	}
	matcher, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid interface pattern %q: %w", pattern, err)
	}

	files, err := os.ReadDir(wireguardConfigDir)
	if err != nil {
		return nil, fmt.Errorf("cannot read config directory: %w", err)
	}

	cfgs := make(map[string]*Config)
	var loadErrors []error
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".conf") {
			continue
		}
		name := strings.TrimSuffix(file.Name(), ".conf")
		if !matcher.MatchString(name) {
			continue
		}

		cfg, err := LoadConfig(name)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Errorf("%s: %w", file.Name(), err))
			continue
		}
		cfgs[name] = cfg
	}
	return cfgs, errors.Join(loadErrors...)
}

// 加载单个配置，默认只解析 interface 区域
func LoadConfig(name string) (*Config, error) {
	b, err := os.ReadFile(filepath.Join(wireguardConfigDir, name+".conf"))
	if err != nil {
		return nil, fmt.Errorf("cannot read file: %w", err)
	}
	c := &Config{}
	c.setConfigText(b)
	if err := c.ParseInterface(); err != nil {
		return nil, fmt.Errorf("cannot parse interface config: %w", err)
	}
	return c, nil
}

func parseInterfaceLine(cfg *Config, lhs string, rhs string) error {
	switch lhs {
	case "Address":
		for _, addr := range strings.Split(rhs, ",") {
			ip, cidr, err := net.ParseCIDR(strings.TrimSpace(addr))
			if err != nil {
				return err
			}
			cfg.Address = append(cfg.Address, net.IPNet{IP: ip, Mask: cidr.Mask})
		}
	case "DNS":
		for _, addr := range strings.Split(rhs, ",") {
			ip := net.ParseIP(strings.TrimSpace(addr))
			if ip == nil {
				return fmt.Errorf("cannot parse IP")
			}
			cfg.DNS = append(cfg.DNS, ip)
		}
	case "MTU":
		mtu, err := strconv.ParseInt(rhs, 10, 64)
		if err != nil {
			return err
		}
		cfg.MTU = int(mtu)
		cfg.MTUSet = true
	case "Table":
		if strings.ToLower(rhs) == "off" {
			cfg.Table = nil
			return nil
		}
		tbl, err := strconv.ParseInt(rhs, 10, 64)
		if err != nil {
			return err
		}
		inttbl := int(tbl)
		cfg.Table = &inttbl
		cfg.TableSet = true
	case "ListenPort":
		portI64, err := strconv.ParseInt(rhs, 10, 64)
		if err != nil {
			return err
		}
		port := int(portI64)
		cfg.ListenPort = &port
	case "PreUp":
		cfg.PreUp = append(cfg.PreUp, rhs)
	case "PostUp":
		cfg.PostUp = append(cfg.PostUp, rhs)
	case "PreDown":
		cfg.PreDown = append(cfg.PreDown, rhs)
	case "PostDown":
		cfg.PostDown = append(cfg.PostDown, rhs)
	case "SaveConfig":
		if _, err := strconv.ParseBool(rhs); err != nil {
			return err
		}
	case "PrivateKey":
		key, err := ParseKey(rhs)
		if err != nil {
			return fmt.Errorf("cannot decode key %v", err)
		}
		cfg.PrivateKey = &key
	case "WgBin":
		cfg.WgBin = rhs
	case "FwMark":
		if strings.ToLower(rhs) == "off" {
			mark := 0
			cfg.FirewallMark = &mark
			return nil
		}
		mark64, err := strconv.ParseInt(rhs, 0, 64)
		if err != nil {
			return err
		}
		mark := int(mark64)
		cfg.FirewallMark = &mark
	default:
		return fmt.Errorf("unknown directive %s", lhs)
	}
	return nil
}

func parsePeerLine(peerCfg *wgtypes.PeerConfig, lhs string, rhs string, rawEndpoint *string) error {
	switch lhs {
	case "PublicKey":
		key, err := ParseKey(rhs)
		if err != nil {
			return fmt.Errorf("cannot decode key %v", err)
		}
		peerCfg.PublicKey = key
	case "PresharedKey":
		key, err := ParseKey(rhs)
		if err != nil {
			return fmt.Errorf("cannot decode key %v", err)
		}
		if peerCfg.PresharedKey != nil {
			return fmt.Errorf("preshared key already defined %v", err)
		}
		peerCfg.PresharedKey = &key
	case "AllowedIPs":
		for _, addr := range strings.Split(rhs, ",") {
			ip, cidr, err := net.ParseCIDR(strings.TrimSpace(addr))
			if err != nil {
				return fmt.Errorf("cannot parse %s: %v", addr, err)
			}
			peerCfg.AllowedIPs = append(peerCfg.AllowedIPs, net.IPNet{IP: ip, Mask: cidr.Mask})
		}
	case "Endpoint":
		*rawEndpoint = rhs
	case "PersistentKeepalive":
		t, err := strconv.ParseInt(rhs, 10, 64)
		if err != nil {
			return err
		}
		dur := time.Duration(t * int64(time.Second))
		peerCfg.PersistentKeepaliveInterval = &dur
	default:
		return fmt.Errorf("unknown directive %s", lhs)
	}
	return nil
}
