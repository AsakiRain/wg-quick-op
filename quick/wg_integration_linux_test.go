package quick

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	libdns "github.com/dn-11/wg-quick-op/lib/dns"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestDownDoesNotResolvePeers(t *testing.T) {
	if os.Getenv("WG_QUICK_OP_TEST_DOWN") == "" {
		t.Skip("WG_QUICK_OP_TEST_DOWN is not set")
	}

	iface := fmt.Sprintf("wqdown%d", os.Getpid())
	if len(iface) > 15 {
		iface = iface[:15]
	}
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: iface}}
	require.NoError(t, netlink.LinkAdd(link))
	t.Cleanup(func() {
		if current, err := netlink.LinkByName(iface); err == nil {
			require.NoError(t, netlink.LinkDel(current))
		}
	})

	oldResolver := libdns.ResolveUDPAddrImpl
	resolveCalls := 0
	libdns.ResolveUDPAddrImpl = func(_, _ string) (*net.UDPAddr, error) {
		resolveCalls++
		return nil, errors.New("endpoint resolution must not run during down")
	}
	t.Cleanup(func() { libdns.ResolveUDPAddrImpl = oldResolver })

	cfg := &Config{}
	cfg.setConfigText([]byte(`[Interface]
PrivateKey = oK56DE9Ue9zK76rAc8pBl6opph+1v36lm7cXXsQKrQM=

[Peer]
PublicKey = GtL7fZc/bLnqZldpVofMCD6hDjrK28SsdLxevJ+qtKU=
AllowedIPs = 192.0.2.1/32
Endpoint = dns-is-broken.invalid:51820
`))
	require.NoError(t, cfg.ParseInterface())
	require.NoError(t, Down(cfg, iface, zerolog.Nop()))
	require.Equal(t, 0, resolveCalls)
	_, err := netlink.LinkByName(iface)
	require.Error(t, err)
}

func TestWgBinAppliesInterfaceAndDeviceConfig(t *testing.T) {
	wgBin := os.Getenv("WG_QUICK_OP_TEST_WGBIN")
	if wgBin == "" {
		t.Skip("WG_QUICK_OP_TEST_WGBIN is not set")
	}

	iface := fmt.Sprintf("wqop%d", os.Getpid())
	if len(iface) > 15 {
		iface = iface[:15]
	}
	_, err := netlink.LinkByName(iface)
	require.Error(t, err, "temporary interface already exists: %s", iface)

	privateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	peerPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	presharedKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	configText := fmt.Sprintf(`[Interface]
PrivateKey = %s
ListenPort = 0
FwMark = 0x2345
MTU = 1377
Table = off
WgBin = %s

[Peer]
PublicKey = %s
PresharedKey = %s
AllowedIPs = 192.0.2.1/32, 2001:db8::1/128
PersistentKeepalive = 17
`, privateKey.String(), wgBin, peerPrivateKey.PublicKey().String(), presharedKey.String())
	cfg := &Config{}
	cfg.setConfigText([]byte(configText))
	require.NoError(t, cfg.ParseInterface())

	t.Cleanup(func() {
		link, linkErr := netlink.LinkByName(iface)
		if linkErr == nil {
			require.NoError(t, netlink.LinkDel(link))
		}
	})

	require.NoError(t, Sync(cfg, iface, zerolog.Nop()))
	link, err := netlink.LinkByName(iface)
	require.NoError(t, err)
	require.Equal(t, cfg.MTU, link.Attrs().MTU)

	device, err := client.Device(iface)
	require.NoError(t, err)
	require.Equal(t, 0x2345, device.FirewallMark)
	require.Equal(t, privateKey.PublicKey(), device.PublicKey)
	require.Len(t, device.Peers, 1)
	require.Equal(t, peerPrivateKey.PublicKey(), device.Peers[0].PublicKey)
	require.Equal(t, presharedKey, device.Peers[0].PresharedKey)
	require.Equal(t, "17s", device.Peers[0].PersistentKeepaliveInterval.String())
	require.Len(t, device.Peers[0].AllowedIPs, 2)
	require.Equal(t, "192.0.2.1/32", device.Peers[0].AllowedIPs[0].String())
	require.Equal(t, "2001:db8::1/128", device.Peers[0].AllowedIPs[1].String())
}

func TestKernelWireGuardAppliesConfiguredMTU(t *testing.T) {
	if os.Getenv("WG_QUICK_OP_TEST_KERNEL") == "" {
		t.Skip("WG_QUICK_OP_TEST_KERNEL is not set")
	}

	iface := fmt.Sprintf("wqkernel%d", os.Getpid())
	if len(iface) > 15 {
		iface = iface[:15]
	}
	_, err := netlink.LinkByName(iface)
	require.Error(t, err, "temporary interface already exists: %s", iface)

	privateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)
	cfg := &Config{
		Config: wgtypes.Config{PrivateKey: &privateKey},
		MTU:    1369,
		MTUSet: true,
		Table:  nil,
	}

	t.Cleanup(func() {
		link, linkErr := netlink.LinkByName(iface)
		if linkErr == nil {
			require.NoError(t, netlink.LinkDel(link))
		}
	})

	require.NoError(t, Sync(cfg, iface, zerolog.Nop()))
	link, err := netlink.LinkByName(iface)
	require.NoError(t, err)
	require.Equal(t, cfg.MTU, link.Attrs().MTU)

	device, err := client.Device(iface)
	require.NoError(t, err)
	require.Equal(t, privateKey.PublicKey(), device.PublicKey)
}
