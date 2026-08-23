package quick

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	libdns "github.com/dn-11/wg-quick-op/lib/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testConfigs = map[string]string{
	"simple": `[Interface]
Address = 10.200.100.8/24
DNS = 10.200.100.1
PrivateKey = oK56DE9Ue9zK76rAc8pBl6opph+1v36lm7cXXsQKrQM=

[Peer]
PublicKey = GtL7fZc/bLnqZldpVofMCD6hDjrK28SsdLxevJ+qtKU=
AllowedIPs = 0.0.0.0/0
PresharedKey = /UwcSPg38hW/D9Y3tcS1FOV0K1wuURMbS0sesJEP5ak=
Endpoint = 123.12.12.1:51820
`,
	"sample-2": `[Interface]
Address = 10.192.122.1/24
Address = 10.10.0.1/16
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 10.192.122.3/32, 10.192.124.1/24

[Peer]
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
AllowedIPs = 10.192.122.4/32, 192.168.0.0/16

[Peer]
PublicKey = gN65BkIKy1eCE9pP1wdc8ROUtkHLF2PfAqYdyYBz6EA=
AllowedIPs = 10.10.10.230/32
`,
	"sample-3": `[Interface]
Address = 10.192.122.1/24
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
ListenPort = 51820
FwMark = 51820
MTU = 1380
Table = 1234
WgBin = wireguard-go
PostUp = ip rule add ipproto tcp dport 22 table 1234
PostUp = echo key=value
PreDown = ip rule delete ipproto tcp dport 22 table 1234

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`,
}

// 验证示例配置经过分阶段解析并重新序列化后，其中的受支持字段和多条脚本保持不变
func TestExampleConfig(t *testing.T) {
	for name, cfg := range testConfigs {
		t.Run(name, func(t *testing.T) {
			c := &Config{}
			c.setConfigText([]byte(cfg))
			require.NoError(t, c.ParseInterface())
			require.NoError(t, c.LoadPeers())
			require.NoError(t, c.ResolveEndpoints())
			tt, err := c.MarshalText()
			assert.NoError(t, err)
			t.Logf("Got after remarshaling:\n%s", tt)
			assert.Equal(t, cfg, string(tt))
		})
	}
}

// 验证 FwMark = off 被解析为非 nil 的 0，从而与未配置 FwMark 区分
func TestFwMarkOffClearsFirewallMark(t *testing.T) {
	c := &Config{}
	c.setConfigText([]byte(`[Interface]
PrivateKey = oK56DE9Ue9zK76rAc8pBl6opph+1v36lm7cXXsQKrQM=
FwMark = off
`))

	require.NoError(t, c.ParseInterface())
	if assert.NotNil(t, c.FirewallMark) {
		assert.Equal(t, 0, *c.FirewallMark)
	}
}

// 验证合法的 SaveConfig 值可以通过解析，但不会被保存到 Config 或重新序列化
func TestSaveConfigIsAcceptedButNotSerialized(t *testing.T) {
	c := &Config{}
	c.setConfigText([]byte(`[Interface]
PrivateKey = oK56DE9Ue9zK76rAc8pBl6opph+1v36lm7cXXsQKrQM=
SaveConfig = true
`))

	require.NoError(t, c.ParseInterface())
	text, err := c.MarshalText()
	assert.NoError(t, err)
	assert.NotContains(t, string(text), "SaveConfig")
}

// 验证正则批量加载会跳过不匹配和解析失败的文件，并保留 Peer 的延迟加载能力
func TestLoadMatchingConfigs(t *testing.T) {
	oldConfigDir := wireguardConfigDir
	wireguardConfigDir = t.TempDir()
	t.Cleanup(func() { wireguardConfigDir = oldConfigDir })

	require.NoError(t, os.WriteFile(
		filepath.Join(wireguardConfigDir, "wg-one.conf"),
		[]byte(testConfigs["simple"]),
		0o600,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(wireguardConfigDir, "wg-broken.conf"),
		[]byte("[Interface]\nUnknown = value\n"),
		0o600,
	))
	require.NoError(t, os.WriteFile(
		filepath.Join(wireguardConfigDir, "other.conf"),
		[]byte(testConfigs["sample-3"]),
		0o600,
	))

	cfgs, err := LoadMatchingConfigs("wg-.*")
	require.ErrorContains(t, err, "wg-broken.conf")
	require.Len(t, cfgs, 1)
	cfg := cfgs["wg-one"]
	require.NotNil(t, cfg)
	assert.Empty(t, cfg.Peers)

	require.NoError(t, cfg.LoadPeers())
	require.Len(t, cfg.Peers, 1)

	cfgs, err = LoadMatchingConfigs("wg-one")
	require.NoError(t, err)
	require.Len(t, cfgs, 1)
}

// 验证接口名枚举只返回配置文件，不读取文件内容，并忽略同名目录和其他后缀
func TestListConfigNames(t *testing.T) {
	oldConfigDir := wireguardConfigDir
	wireguardConfigDir = t.TempDir()
	t.Cleanup(func() { wireguardConfigDir = oldConfigDir })

	require.NoError(t, os.WriteFile(filepath.Join(wireguardConfigDir, "wg-two.conf"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(wireguardConfigDir, "notes.txt"), nil, 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(wireguardConfigDir, "wg-one.conf"), []byte("invalid"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(wireguardConfigDir, "directory.conf"), 0o700))

	names, err := ListConfigNames()
	require.NoError(t, err)
	assert.Equal(t, []string{"wg-one", "wg-two"}, names)
}

// 验证 ParseInterface 不加载 Peer，LoadPeers 不解析 Endpoint，DNS 查询只在 ResolveEndpoints 时发生
func TestInterfaceParsingDefersPeerAndEndpointResolution(t *testing.T) {
	oldResolver := libdns.ResolveUDPAddrImpl
	resolveCalls := 0
	libdns.ResolveUDPAddrImpl = func(_, address string) (*net.UDPAddr, error) {
		resolveCalls++
		return net.ResolveUDPAddr("udp", address)
	}
	t.Cleanup(func() { libdns.ResolveUDPAddrImpl = oldResolver })

	c := &Config{}
	c.setConfigText([]byte(testConfigs["simple"]))
	require.NoError(t, c.ParseInterface())
	assert.Empty(t, c.Peers)
	assert.Equal(t, 0, resolveCalls)

	require.NoError(t, c.LoadPeers())
	require.Len(t, c.Peers, 1)
	assert.Equal(t, 0, resolveCalls)
	require.NoError(t, c.ResolveEndpoints())
	assert.Equal(t, 1, resolveCalls)
	assert.Equal(t, "123.12.12.1:51820", c.Peers[0].Endpoint.String())
}

// 验证 LoadPeers 是幂等的，重复调用不会重复追加 Peer
func TestLoadPeersIsIdempotent(t *testing.T) {
	c := &Config{}
	c.setConfigText([]byte(testConfigs["sample-2"]))
	require.NoError(t, c.ParseInterface())
	require.NoError(t, c.LoadPeers())
	require.NoError(t, c.LoadPeers())
	assert.Len(t, c.Peers, 3)
}

// 验证未知的 Peer 指令不会阻止 Interface 解析，而是在 LoadPeers 时才返回错误
func TestInterfaceParsingDefersPeerErrors(t *testing.T) {
	c := &Config{}
	c.setConfigText([]byte(`[Interface]
PrivateKey = oK56DE9Ue9zK76rAc8pBl6opph+1v36lm7cXXsQKrQM=

[Peer]
NotAWireGuardField = invalid
`))
	require.NoError(t, c.ParseInterface())
	require.ErrorContains(t, c.LoadPeers(), "unknown directive NotAWireGuardField")
}

// 验证 ResolveEndpoint 只更新指定 PublicKey 对应的 Peer
func TestResolveEndpointUpdatesSelectedPeer(t *testing.T) {
	oldResolver := libdns.ResolveUDPAddrImpl
	libdns.ResolveUDPAddrImpl = func(_, address string) (*net.UDPAddr, error) {
		return net.ResolveUDPAddr("udp", address)
	}
	t.Cleanup(func() { libdns.ResolveUDPAddrImpl = oldResolver })

	c := &Config{}
	c.setConfigText([]byte(`[Interface]
PrivateKey = oK56DE9Ue9zK76rAc8pBl6opph+1v36lm7cXXsQKrQM=

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
AllowedIPs = 10.0.0.1/32
Endpoint = 192.0.2.1:51820

[Peer]
PublicKey = TrMvSoP4jYQlY6RIzBgbssQqY3vxI2Pi+y71lOWWXX0=
AllowedIPs = 10.0.0.2/32
Endpoint = 192.0.2.2:51820
`))
	require.NoError(t, c.LoadPeers())
	require.Len(t, c.Peers, 2)

	secondKey := c.Peers[1].PublicKey

	require.NoError(t, c.ResolveEndpoint(secondKey))
	assert.Nil(t, c.Peers[0].Endpoint)
	require.NotNil(t, c.Peers[1].Endpoint)
	assert.Equal(t, "192.0.2.2:51820", c.Peers[1].Endpoint.String())
}

// 验证 LoadPeers 可以先触发配置扫描，之后 ParseInterface 仍能读取已缓存的 Interface 区域
func TestPeersCanBeLoadedBeforeInterface(t *testing.T) {
	c := &Config{}
	c.setConfigText([]byte(testConfigs["simple"]))

	require.NoError(t, c.LoadPeers())
	require.Len(t, c.Peers, 1)
	assert.Empty(t, c.Address)

	require.NoError(t, c.ParseInterface())
	require.Len(t, c.Address, 1)
}
