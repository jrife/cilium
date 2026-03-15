// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"github.com/vishvananda/netlink"

	config_latest "github.com/cilium/cilium/pkg/datapath/config/latest"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/option"
)

// XDP returns a [BPFXDP].
func XDP(lnc *datapath.LocalNodeConfiguration, link netlink.Link) any {
	cfg := config_latest.NewBPFXDP(NodeConfig(lnc))

	cfg.InterfaceIfIndex = uint32(link.Attrs().Index)
	cfg.DeviceMTU = uint32(link.Attrs().MTU)

	cfg.EnableExtendedIPProtocols = option.Config.EnableExtendedIPProtocols

	cfg.EphemeralMin = uint32(lnc.EphemeralMin)

	cfg.EnableXDPPrefilter = option.Config.EnableXDPPrefilter

	cfg.TunnelProtocol = uint32(lnc.TunnelProtocol)
	cfg.TunnelPort = uint32(lnc.TunnelPort)

	cfg.EnableIPv4Fragments = option.Config.EnableIPv4 && option.Config.EnableIPv4FragmentsTracking
	cfg.EnableIPv6Fragments = option.Config.EnableIPv6 && option.Config.EnableIPv6FragmentsTracking

	return cfg
}
