// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"time"

	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	k8stypes "k8s.io/apimachinery/pkg/types"
)

type ProgStatsCollector interface {
	CollectProgramStats(pods []k8stypes.NamespacedName, devices []string) ([]BpfProgramStats, error)
}

type BpfProgramStats struct {
	Info   *ebpf.ProgramInfo
	Pod    k8stypes.NamespacedName
	Device netlink.Link
	Stats  *ebpf.ProgramStats
}

func (s *BpfProgramStats) AvgRuntimeNs() time.Duration {
	if s.Stats.RunCount == 0 {
		return 0
	}

	return s.Stats.Runtime / time.Duration(s.Stats.RunCount)
}

func (s *BpfProgramStats) PodString() string {
	if s.Pod.Name == "" {
		return ""
	}

	return s.Pod.String()
}
