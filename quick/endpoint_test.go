package quick

import (
	"net"
	"testing"

	libdns "github.com/dn-11/wg-quick-op/lib/dns"
)

// 验证批量解析不会重复查询已成功解析的 endpoint，而单个解析仍可用于 DDNS 主动刷新
func TestResolveEndpointsSkipsResolvedPeers(t *testing.T) {
	oldResolver := libdns.ResolveUDPAddrImpl
	resolveCalls := 0
	libdns.ResolveUDPAddrImpl = func(_, address string) (*net.UDPAddr, error) {
		resolveCalls++
		return net.ResolveUDPAddr("udp", address)
	}
	t.Cleanup(func() { libdns.ResolveUDPAddrImpl = oldResolver })

	cfg := &Config{}
	cfg.setConfigText([]byte(testConfigs["simple"]))
	if err := cfg.LoadPeers(); err != nil {
		t.Fatalf("LoadPeers returned an error: %v", err)
	}
	if err := cfg.ResolveEndpoints(); err != nil {
		t.Fatalf("first ResolveEndpoints returned an error: %v", err)
	}
	if err := cfg.ResolveEndpoints(); err != nil {
		t.Fatalf("second ResolveEndpoints returned an error: %v", err)
	}
	if resolveCalls != 1 {
		t.Fatalf("ResolveEndpoints made %d DNS calls, want 1", resolveCalls)
	}

	if err := cfg.ResolveEndpoint(cfg.Peers[0].PublicKey); err != nil {
		t.Fatalf("ResolveEndpoint returned an error: %v", err)
	}
	if resolveCalls != 2 {
		t.Fatalf("ResolveEndpoint made %d total DNS calls, want 2", resolveCalls)
	}
}
