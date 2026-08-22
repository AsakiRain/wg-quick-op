package daemon

import (
	"github.com/dn-11/wg-quick-op/quick"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type ddns struct {
	cfg                 *quick.Config
	name                string
	unresolvedEndpoints map[wgtypes.Key]string
}

var randomPort int = 0

func newDDNS(iface string) (*ddns, error) {
	var ddnsConfig ddns
	ddnsConfig.name = iface
	cfg, err := quick.LoadConfig(iface)
	if err != nil {
		return nil, err
	}
	ddnsConfig.cfg = cfg
	if err := ddnsConfig.cfg.LoadPeers(); err != nil {
		return nil, err
	}
	if ddnsConfig.cfg.ListenPort == nil {
		ddnsConfig.cfg.ListenPort = &randomPort
	}
	ddnsConfig.unresolvedEndpoints = ddnsConfig.cfg.UnresolvedEndpoints()
	return &ddnsConfig, nil
}
