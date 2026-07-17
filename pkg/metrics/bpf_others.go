// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !linux

package metrics

import (
	"log/slog"

	"github.com/cilium/cilium/pkg/bpf/statsquery/types"
	"github.com/prometheus/client_golang/prometheus"
)

type bpfRuntimeCollector struct{}

func newbpfRuntimeCollector(logger *slog.Logger, _ types.ProgStatsGetter) *bpfRuntimeCollector {
	return &bpfRuntimeCollector{}
}

func (s *bpfRuntimeCollector) Describe(ch chan<- *prometheus.Desc) {}
func (s *bpfRuntimeCollector) Collect(ch chan<- prometheus.Metric) {}
