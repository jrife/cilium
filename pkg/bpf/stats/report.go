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

	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/bpf/stats/types"
	"github.com/cilium/cilium/pkg/time"
)

const (
	SortFlagName   = "sort"
	PodFlagName    = "pod"
	DeviceFlagName = "device"
	JSONFlag       = "json"
)

type bpfProgramStats struct {
	ProgramID    ebpf.ProgramID `json:"id,omitempty"`
	ProgramName  string         `json:"program_name"`
	ProgramType  string         `json:"program_type"`
	IfaceName    string         `json:"iface_name,omitempty"`
	PodNamespace string         `json:"pod_namespace,omitempty"`
	PodName      string         `json:"pod_name,omitempty"`
	TotalRuns    uint64         `json:"total_runs"`
	TotalRuntime time.Duration  `json:"total_runtime"`
	AvgLatencyNs time.Duration  `json:"avg_latency_ns"`
}

func reportCommand(statsCollector types.ProgStatsCollector) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Display BPF runtime stats",
			Flags: func(fs *pflag.FlagSet) {
				fs.String(SortFlagName, "avg", "Sort by average latency (avg), total runtime (total), or number of runs (runs)")
				fs.StringSlice(PodFlagName, nil, "Filter by pod name(s)")
				fs.StringSlice(DeviceFlagName, nil, "Filter by device name(s)")
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
			pods, err := parseNamespacedNames(podFilters)
			if err != nil {
				return nil, err
			}
			devices, err := s.Flags.GetStringSlice(DeviceFlagName)
			if err != nil {
				return nil, err
			}
			jsonOutput, err := s.Flags.GetBool(JSONFlag)
			if err != nil {
				return nil, err
			}

			if len(pods) == 0 {
				pods = nil
			}
			if len(devices) == 0 {
				devices = nil
			}

			stats, err := statsCollector.CollectProgramStats(pods, devices)
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

func parseNamespacedNames(pods []string) ([]k8stypes.NamespacedName, error) {
	var parsedPods []k8stypes.NamespacedName

	for _, pod := range pods {
		parts := strings.Split(pod, "/")

		if len(parts) != 2 {
			return nil, fmt.Errorf("could not parse namespace/pod from %s: %w", pod)
		}

		parsedPods = append(parsedPods, k8stypes.NamespacedName{
			Namespace: parts[0],
			Name:      parts[1],
		})
	}

	return parsedPods, nil
}

func flattenStats(stats []types.BpfProgramStats) []bpfProgramStats {
	var flattenedStats []bpfProgramStats

	for _, rs := range stats {
		flattened := bpfProgramStats{
			ProgramName:  rs.Info.Name,
			ProgramType:  rs.Info.Type.String(),
			IfaceName:    rs.Device.Attrs().Name,
			PodNamespace: rs.Pod.Namespace,
			PodName:      rs.Pod.Name,
			TotalRuns:    rs.Stats.RunCount,
			TotalRuntime: rs.Stats.Runtime,
		}

		progID, _ := rs.Info.ID()
		flattened.ProgramID = progID
		if flattened.TotalRuns != 0 {
			flattened.AvgLatencyNs = flattened.TotalRuntime / time.Duration(flattened.TotalRuns)
		}
	}

	return flattenedStats
}

func displayProgramStats(w io.Writer, stats []types.BpfProgramStats, jsonOutput bool) error {
	if jsonOutput {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(flattenStats(stats)); err != nil {
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

func printResults(w io.Writer, res []types.BpfProgramStats) {
	tw := tabwriter.NewWriter(w, 5, 0, 3, ' ', 0)

	fmt.Fprintln(tw, "DEVICE\tPOD\tBPF PROGRAM\tTYPE\tTOTAL RUNS\tTOTAL RUNTIME\tAVG RUNTIME")

	for _, r := range res {
		fmt.Fprintf(
			tw, "%s\t%s\t%s\t%s\t%d\t%.2fs\t%d ns\n",
			r.Device.Attrs().Name,
			r.PodString(),
			r.Info.Name,
			r.Info.Type,
			r.Stats.RunCount,
			r.Stats.Runtime.Seconds(),
			r.AvgRuntimeNs().Nanoseconds(),
		)
	}
	tw.Flush()
}

func getCompareFunc(sortField string, stats []types.BpfProgramStats) (func(i, j int) bool, error) {
	switch strings.ToLower(sortField) {
	case "total":
		return func(i, j int) bool { return stats[i].Stats.Runtime > stats[j].Stats.Runtime }, nil
	case "runs":
		return func(i, j int) bool { return stats[i].Stats.RunCount > stats[j].Stats.RunCount }, nil
	case "avg":
		return func(i, j int) bool { return stats[i].AvgRuntimeNs() > stats[j].AvgRuntimeNs() }, nil
	default:
		return nil, fmt.Errorf("invalid sort field: %s. Expected: avg, total, runs", sortField)
	}
}
