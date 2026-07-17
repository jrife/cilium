// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cilium/hive/shell"

	"github.com/cilium/cilium/pkg/bpf/stats"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/hive"
)

var (
	sortField       string
	podFilters      []string
	deviceFilters   []string
	progTypeFilters []string
	jsonOutput      bool
	cgroupFilter    bool
)

var bpfStatsReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Display BPF runtime stats",
	Long:  `Display BPF runtime stats.`,
	Example: `  # Display all BPF runtime stats
  cilium-dbg bpf stats report

  # Filter by pod name "my-pod"
  cilium-dbg bpf stats report --pod=my-pod

  # Filter by device name "eth0"
  cilium-dbg bpf stats report --device=eth0

	# Filter only cgroup:root attached programs
	cilium-dbg bpf stats report --cgroup

  # Filter by program type "tc"
  cilium-dbg bpf stats report --prog-type=tc

  # Sort by total runtime
  cilium-dbg bpf stats report --sort=total

  # Sort by number of runs
  cilium-dbg bpf stats report --sort=runs

  # Sort by average/total latency or total runs
  cilium-dbg bpf stats report --sort=avg/total/runs`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg := hive.DefaultShellConfig
		if err := cfg.Parse(cmd.Flags()); err != nil {
			return err
		}

		var shellArgs []string
		if sortField != "" {
			shellArgs = append(shellArgs, fmt.Sprintf("--%s=%s", stats.SortFlagName, sortField))
		}
		for _, pod := range podFilters {
			shellArgs = append(shellArgs, fmt.Sprintf("--%s=%s", stats.PodFlagName, pod))
		}
		for _, dev := range deviceFilters {
			shellArgs = append(shellArgs, fmt.Sprintf("--%s=%s", stats.DeviceFlagName, dev))
		}
		for _, pt := range progTypeFilters {
			shellArgs = append(shellArgs, fmt.Sprintf("--%s=%s", stats.ProgTypeFlagName, pt))
		}
		if cgroupFilter {
			shellArgs = append(shellArgs, fmt.Sprintf("--%s", stats.CGroupFlag))
		}

		if jsonOutput || command.OutputOption() {
			shellArgs = append(shellArgs, fmt.Sprintf("--%s", stats.JSONFlag))
		}

		shellCmd := "bpf/stats/report"
		if len(shellArgs) > 0 {
			shellCmd = fmt.Sprintf("%s %s", shellCmd, strings.Join(shellArgs, " "))
		}

		return shell.ShellExchange(cfg, os.Stdout, shellCmd)
	},
}

func init() {
	BPFStatsCmd.AddCommand(bpfStatsReportCmd)
	bpfStatsReportCmd.Flags().StringVar(&sortField, stats.SortFlagName, "avg", "Sort by average latency (avg), total runtime (total), or number of runs (runs)")
	bpfStatsReportCmd.Flags().StringSliceVar(&podFilters, stats.PodFlagName, []string{}, "Filter by pod name(s)")
	bpfStatsReportCmd.Flags().StringSliceVar(&deviceFilters, stats.DeviceFlagName, []string{}, "Filter by device name(s) (e.g. host, eth0, cilium_wg0)")
	bpfStatsReportCmd.Flags().StringSliceVar(&progTypeFilters, stats.ProgTypeFlagName, []string{}, "Filter by bpf program type(s)")
	bpfStatsReportCmd.Flags().BoolVar(&cgroupFilter, stats.CGroupFlag, false, "Show only cgroup:root attached BPF programs")
	bpfStatsReportCmd.Flags().BoolVar(&jsonOutput, stats.JSONFlag, false, "Output report in JSON")
	command.AddOutputOption(bpfStatsReportCmd)
	hive.DefaultShellConfig.Flags(bpfStatsReportCmd.Flags())
}
