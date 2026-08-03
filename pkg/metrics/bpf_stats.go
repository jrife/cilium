// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build linux

package metrics

import (
	"log/slog"
	"os"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/bpf/stats/types"
)

type bpfRuntimeCollector struct {
	logger    *slog.Logger
	collector types.ProgStatsCollector

	bpfProgRunsTotal    *prometheus.Desc
	bpfProgRuntimeTotal *prometheus.Desc
}

func newbpfRuntimeCollector(logger *slog.Logger, collector types.ProgStatsCollector) *bpfRuntimeCollector {
	return &bpfRuntimeCollector{
		logger:    logger,
		collector: collector,
		bpfProgRunsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, SubsystemBPF, "prog_total_runs"),
			"Total executions of a BPF program.",
			[]string{"node", "program_id", "program_name", "pod_namespace", "pod_name", "device", "name", "type"}, nil,
		),
		bpfProgRuntimeTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, SubsystemBPF, "prog_runtime_total_seconds"),
			"Total execution time of a BPF program in seconds.",
			[]string{"node", "program_id", "program_name", "pod_namespace", "pod_name", "device", "name", "type"}, nil,
		),
	}
}

func (s *bpfRuntimeCollector) Describe(ch chan<- *prometheus.Desc) {
	if BPFBenchmarkMetrics {
		ch <- s.bpfProgRunsTotal
		ch <- s.bpfProgRuntimeTotal
	}
}

func (s *bpfRuntimeCollector) Collect(ch chan<- prometheus.Metric) {
	if !BPFBenchmarkMetrics {
		return
	}

	// nodeName := getLocalNodeName()
	//
	// stats, err := s.getter.QueryProgramStats(nil, nil, nil)
	// if err != nil {
	// 	s.logger.Error("Failed to query BPF programs", logfields.Error, err)
	// 	return
	// }

	// for _, stat := range stats {
	// 	// ch <- prometheus.MustNewConstMetric(
	// 	// 	s.bpfProgRunsTotal,
	// 	// 	prometheus.CounterValue,
	// 	// 	float64(stat.Stats.RunCount),
	// 	// 	nodeName,
	// 	// 	fmt.Sprintf("%d", info.ID),
	// 	// 	pod,
	// 	// 	attachment,
	// 	// 	info.Name,
	// 	// 	info.Type,
	// 	// )
	// 	//
	// 	// ch <- prometheus.MustNewConstMetric(
	// 	// 	s.bpfProgRuntimeTotal,
	// 	// 	prometheus.CounterValue,
	// 	// 	info.TotalRuntime.Seconds(),
	// 	// 	nodeName,
	// 	// 	fmt.Sprintf("%d", info.ID),
	// 	// 	pod,
	// 	// 	attachment,
	// 	// 	info.Name,
	// 	// 	info.Type,
	// 	// )
	// }
}

func getLocalNodeName() string {
	if name := os.Getenv("K8S_NODE_NAME"); name != "" {
		return name
	}
	if h, err := os.Hostname(); err == nil {
		return h
	}
	return "localhost"
}
