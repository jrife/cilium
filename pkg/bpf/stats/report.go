// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf/statsquery/types"
)

const (
	SortFlagName     = "sort"
	PodFlagName      = "pod"
	DeviceFlagName   = "device"
	ProgTypeFlagName = "prog-type"
	CGroupFlag       = "cgroup"
	JSONFlag         = "json"
)

type bpfProgramStats = types.BpfProgramStats

func reportCommand(statsGetter types.ProgStatsGetter) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Display BPF runtime stats",
			Flags: func(fs *pflag.FlagSet) {
				fs.String(SortFlagName, "avg", "Sort by average latency (avg), total runtime (total), or number of runs (runs)")
				fs.StringSlice(PodFlagName, []string{}, "Filter by pod name(s)")
				fs.StringSlice(DeviceFlagName, []string{}, "Filter by device name(s)")
				fs.StringSlice(ProgTypeFlagName, []string{}, "Filter by bpf program type(s)")
				fs.Bool(CGroupFlag, false, "Show only cgroup:root BPF programs")
				fs.Bool(JSONFlag, false, "Output report in JSON")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			sortField, err := s.Flags.GetString(SortFlagName)
			if err != nil {
				return nil, err
			}
			podFilters, err := s.Flags.GetStringSlice(PodFlagName)
			if err != nil {
				return nil, err
			}
			deviceFilters, err := s.Flags.GetStringSlice(DeviceFlagName)
			if err != nil {
				return nil, err
			}
			progTypeFilters, err := s.Flags.GetStringSlice(ProgTypeFlagName)
			if err != nil {
				return nil, err
			}
			cgroupFilter, err := s.Flags.GetBool(CGroupFlag)
			if err != nil {
				return nil, err
			}
			jsonOutput, err := s.Flags.GetBool(JSONFlag)
			if err != nil {
				return nil, err
			}

			stats, err := queryProgramStats(statsGetter, podFilters, deviceFilters, cgroupFilter, progTypeFilters)
			if err != nil {
				return nil, fmt.Errorf("querying program stats: %w", err)
			}

			cmp, err := getCompareFunc(sortField, stats)
			if err != nil {
				return nil, err
			}

			sort.Slice(stats, cmp)

			if err := displayProgramStats(s.LogWriter(), stats, jsonOutput); err != nil {
				return nil, fmt.Errorf("displaying program stats: %w", err)
			}

			return nil, nil
		},
	)
}

func queryProgramStats(statsGetter types.ProgStatsGetter, pods []string, devices []string, cgroupOnly bool, programs []string) ([]bpfProgramStats, error) {

	iterateAllProgs := false
	if cgroupOnly || (len(pods) == 0 && len(devices) == 0) {
		iterateAllProgs = true
	}

	return statsGetter.QueryProgramStats(pods, devices, iterateAllProgs, cgroupOnly, programs)
}

func displayProgramStats(w io.Writer, stats []bpfProgramStats, jsonOutput bool) error {
	if jsonOutput {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(stats); err != nil {
			return fmt.Errorf("failed to encode JSON: %w", err)
		}
	} else {
		if len(stats) == 0 {
			fmt.Fprintln(w, "No entries found.")
		} else {
			printResults(w, stats)
		}
	}
	return nil
}

func printResults(w io.Writer, res []bpfProgramStats) {
	tw := tabwriter.NewWriter(w, 5, 0, 3, ' ', 0)

	fmt.Fprintln(tw, "Attachment Point\tBPF PROGRAM\tTYPE\tTOTAL RUNS\tTOTAL RUNTIME\tAVG LATENCY")

	for _, r := range res {
		fmt.Fprintf(
			tw, "%s\t%s\t%s\t%d\t%.2fs\t%d ns\n",
			r.Attachment,
			r.Name,
			r.Type,
			r.TotalRuns,
			r.TotalRuntime.Seconds(),
			r.AvgLatencyNs.Nanoseconds(),
		)
	}
	tw.Flush()
}

func getCompareFunc(sortField string, stats []bpfProgramStats) (func(i, j int) bool, error) {
	switch strings.ToLower(sortField) {
	case "total":
		return func(i, j int) bool { return stats[i].TotalRuntime > stats[j].TotalRuntime }, nil
	case "runs":
		return func(i, j int) bool { return stats[i].TotalRuns > stats[j].TotalRuns }, nil
	case "avg":
		return func(i, j int) bool { return stats[i].AvgLatencyNs > stats[j].AvgLatencyNs }, nil
	default:
		return nil, fmt.Errorf("invalid sort field: %s. Expected: avg, total, runs", sortField)
	}
}
