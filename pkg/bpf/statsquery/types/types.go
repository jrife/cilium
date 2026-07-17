// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/time"
)

type ProgStatsGetter interface {
	QueryProgramStats(pods []string, devices []string, iterateAll bool, cgroupOnly bool, programs []string) ([]BpfProgramStats, error)
}

type BpfProgramStats struct {
	ID           ebpf.ProgramID `json:"id,omitempty"`
	Name         string         `json:"name"`
	Type         string         `json:"type"`
	IfaceName    string         `json:"iface_name,omitempty"`
	PodName      string         `json:"pod_name,omitempty"`
	TotalRuns    uint64         `json:"total_runs"`
	TotalRuntime time.Duration  `json:"total_runtime"`
	AvgLatencyNs time.Duration  `json:"avg_latency_ns"`
	Attachment   string         `json:"attachment"`
}
