// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

import (
	"errors"
	"fmt"
	"os"
	"strings"

	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/vishvananda/netlink"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/statedb"

	"github.com/cilium/cilium/pkg/bpf/stats/types"
	"github.com/cilium/cilium/pkg/cgroups"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/endpoint"
	"github.com/cilium/cilium/pkg/endpointmanager"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

type progStatsCollector struct {
	db       *statedb.DB
	devices  statedb.Table[*tables.Device]
	epLookup endpointmanager.EndpointsLookup
}

func newProgStatsCollector(lookup endpointmanager.EndpointsLookup, db *statedb.DB, devices statedb.Table[*tables.Device]) types.ProgStatsCollector {
	return &progStatsCollector{
		db:       db,
		devices:  devices,
		epLookup: lookup,
	}
}

func (p *progStatsCollector) CollectProgramStats(pods []k8stypes.NamespacedName, devices []string) ([]types.BpfProgramStats, error) {
	var stats []types.BpfProgramStats

	// Host and non-host endpoints
	for _, ep := range p.epLookup.GetEndpoints() {
		if filterEndpoint(pods, ep) {
			continue
		}

		deviceStats, err := collectDeviceProgramStats(ep.HostInterface(), devices)
		if err != nil {
			return nil, fmt.Errorf("collecting device program stats for endpoint %d interface %s: %w", ep.GetID(), ep.HostInterface(), err)
		}

		if ep.IsHost() {
			secondaryDeviceStats, err := collectDeviceProgramStats(defaults.SecondHostDevice, devices)
			if err != nil {
				return nil, fmt.Errorf("collecting device program stats for endpoint %d interface %s: %w", ep.GetID(), ep.HostInterface(), err)
			}

			deviceStats = append(deviceStats, secondaryDeviceStats...)
		} else {
			for i := range deviceStats {
				deviceStats[i].Pod.Namespace = ep.K8sNamespace
				deviceStats[i].Pod.Name = ep.K8sPodName
			}
		}

		stats = append(stats, deviceStats...)
	}

	// Native devices
	if pods == nil {
		deviceNames := []string{
			defaults.VxlanDevice,
			defaults.GeneveDevice,
			defaults.IPIPv4Device,
			defaults.IPIPv6Device,
			wgTypes.IfaceName,
		}

		devs, _ := tables.SelectedDevices(p.devices, p.db.ReadTxn())
		for _, d := range devs {
			deviceNames = append(deviceNames, d.Name)
		}

		for _, d := range deviceNames {
			deviceStats, err := collectDeviceProgramStats(d, devices)
			if err != nil {
				return nil, fmt.Errorf("collecting device program stats for interface %s: %w", d, err)
			}

			stats = append(stats, deviceStats...)
		}
	}

	// Cgroup programs
	cgroupStats, err := collectCgroupProgramStats()
	if err != nil {
		return nil, fmt.Errorf("collecting cgroup program stats: %w", err)
	}
	stats = append(stats, cgroupStats...)

	return stats, nil
}

func collectDeviceProgramStats(deviceName string, devices []string) ([]types.BpfProgramStats, error) {
	if filterDevice(devices, deviceName) {
		return nil, nil
	}

	device, err := safenetlink.LinkByName(deviceName)
	if errors.As(err, &netlink.LinkNotFoundError{}) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("getting link by name for %s: %w", deviceName, err)
	}

	var stats []types.BpfProgramStats
	progIDs, err := collectDevicePrograms(device)

	for _, id := range progIDs {
		s, err := newBPFProgramStatsFromID(id)
		if err != nil {
			return nil, fmt.Errorf("getting stats for program %d: %w", id, err)
		}

		if isCiliumProgram(s.Info.Name) {
			s.Device = device
			stats = append(stats, s)
		}
	}

	return stats, nil
}

func collectDevicePrograms(device netlink.Link) ([]ebpf.ProgramID, error) {
	var ids []ebpf.ProgramID

	attachTypes := []ebpf.AttachType{
		ebpf.AttachTCXIngress, ebpf.AttachTCXEgress,
	}

	if device.Type() == "netkit" {
		attachTypes = append(attachTypes, ebpf.AttachNetkitPrimary, ebpf.AttachNetkitPeer)
	}

	for _, at := range attachTypes {
		res, err := link.QueryPrograms(link.QueryOptions{
			Target: device.Attrs().Index,
			Attach: at,
		})
		if err != nil {
			return nil, fmt.Errorf("collecting %s programs for ifindex %d: %w", at.String(), device.Attrs().Index, err)
		}

		for _, prog := range res.Programs {
			ids = append(ids, prog.ID)
		}
	}

	// Legacy TC filters
	ingressFilters, err := loader.ListCiliumTCFilters(device, netlink.HANDLE_MIN_INGRESS)
	if err != nil {
		return nil, fmt.Errorf("collecting legacy TC ingress filters: %w", err)
	}

	egressFilters, err := loader.ListCiliumTCFilters(device, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return nil, fmt.Errorf("collecting legacy TC egress filters: %w", err)
	}

	for _, f := range append(ingressFilters, egressFilters...) {
		ids = append(ids, ebpf.ProgramID(f.Id))
	}

	// XDP programs
	if device.Attrs().Xdp != nil && device.Attrs().Xdp.Attached {
		ids = append(ids, ebpf.ProgramID(device.Attrs().Xdp.ProgId))
	}

	return ids, nil
}

func collectCgroupProgramStats() ([]types.BpfProgramStats, error) {
	var stats []types.BpfProgramStats

	cg, err := os.Open(cgroups.GetCgroupRoot())
	if err != nil {
		return nil, fmt.Errorf("opening root cgroup: %w", err)
	}
	defer cg.Close()

	for _, at := range []ebpf.AttachType{
		ebpf.AttachCGroupInet4Bind, ebpf.AttachCGroupInet6Bind,
		ebpf.AttachCGroupUDP4Recvmsg, ebpf.AttachCGroupUDP6Recvmsg,
		ebpf.AttachCgroupInet4GetPeername, ebpf.AttachCgroupInet6GetPeername,
		ebpf.AttachCgroupInet4GetSockname, ebpf.AttachCgroupInet6GetSockname,
		ebpf.AttachCGroupInet4Connect, ebpf.AttachCGroupInet6Connect,
		ebpf.AttachCGroupInet4PostBind, ebpf.AttachCGroupInet6PostBind,
		ebpf.AttachCGroupUDP4Sendmsg, ebpf.AttachCGroupUDP6Sendmsg,
		ebpf.AttachCgroupInetSockRelease,
	} {
		res, err := link.QueryPrograms(link.QueryOptions{
			Attach: at,
			Target: int(cg.Fd()),
		})
		if err != nil {
			return nil, fmt.Errorf("collecting %s programs: %w", at.String(), err)
		}

		for _, prog := range res.Programs {
			s, err := newBPFProgramStatsFromID(prog.ID)
			if err != nil {
				return nil, fmt.Errorf("getting stats for program %d: %w", prog.ID, err)
			}

			if isCiliumProgram(s.Info.Name) {
				stats = append(stats, s)
			}

		}
	}

	return stats, nil
}

func filterEndpoint(pods []k8stypes.NamespacedName, ep *endpoint.Endpoint) bool {
	if ep.IsHost() && pods != nil {
		return true
	}

	for _, p := range pods {
		if p.Namespace == ep.K8sNamespace && p.Name == ep.K8sPodName {
			return false
		}
	}

	return pods != nil
}

func filterDevice(devices []string, name string) bool {
	for _, device := range devices {
		if device == name {
			return false
		}
	}

	return devices != nil
}

func isCiliumProgram(name string) bool {
	return strings.HasPrefix(name, "cil_")
}

func newBPFProgramStatsFromID(id ebpf.ProgramID) (types.BpfProgramStats, error) {
	prog, err := ebpf.NewProgramFromID(id)
	if err != nil {
		return types.BpfProgramStats{}, fmt.Errorf("getting program from id: %w", id, err)
	}
	defer prog.Close()

	info, err := prog.Info()
	if err != nil {
		return types.BpfProgramStats{}, fmt.Errorf("getting program info: %w", err)
	}

	stats, err := prog.Stats()
	if err != nil {
		return types.BpfProgramStats{}, fmt.Errorf("getting program stats: %w", err)
	}

	return types.BpfProgramStats{
		Info:  info,
		Stats: stats,
	}, nil
}
