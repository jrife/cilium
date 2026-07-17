// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statsquery

import (
	"fmt"
	"net"
	"strings"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/bpf/statsquery/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
)

// Cell provides the BPF program stats implementation.
var Cell = cell.Module(
	"bpf-stats-provider",
	"BPF Program Stats Provider",

	cell.Provide(newProgStatsGetter),
)

type progStatsGetter struct {
	epLookup endpointmanager.EndpointsLookup
}

func (p *progStatsGetter) QueryProgramStats(
	pods []string,
	devices []string,
	iterateAll bool,
	cgroupOnly bool,
	programs []string,
) ([]types.BpfProgramStats, error) {
	var epMap map[int]string
	var targetIfindexes map[int]struct{}

	if p.epLookup != nil {
		eps := p.epLookup.GetEndpoints()
		epMap = make(map[int]string)
		for _, ep := range eps {
			podName := ep.K8sPodName
			if podName == "" {
				podName = fmt.Sprintf("endpoint-%d", ep.ID)
			}
			epMap[ep.GetIfIndex()] = podName
		}

		if len(pods) > 0 {
			targetIfindexes = make(map[int]struct{})
			for _, ep := range eps {
				podName := ep.K8sPodName
				if podName != "" && matchesAny(podName, pods) {
					targetIfindexes[ep.GetIfIndex()] = struct{}{}
				}
			}
		}
	}

	if len(devices) > 0 {
		if targetIfindexes == nil {
			targetIfindexes = make(map[int]struct{})
		}
		ifaces, err := net.Interfaces()
		if err == nil {
			for _, iface := range ifaces {
				if matchesDevice(iface.Name, devices) {
					targetIfindexes[iface.Index] = struct{}{}
				}
			}
		}
	}

	return QueryProgramStats(epMap, targetIfindexes, iterateAll, cgroupOnly, programs)
}

func matchesDevice(deviceName string, filters []string) bool {
	for _, f := range filters {
		if f == "host" || strings.Contains(strings.ToLower(deviceName), strings.ToLower(f)) {
			return true
		}
	}
	return false
}

func newProgStatsGetter(lookup endpointmanager.EndpointsLookup) types.ProgStatsGetter {
	return &progStatsGetter{
		epLookup: lookup,
	}
}
