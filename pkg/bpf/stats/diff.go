// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package stats

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/cilium/cilium/pkg/time"

	"github.com/cilium/hive/script"
	"github.com/spf13/pflag"
)

const (
	FailOnFlag = "fail-on"
)

func diffCommand() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Compare BPF runtime stats against baseline config",
			Args:    "<baseline.json> <test.json>",
			Flags: func(fs *pflag.FlagSet) {
				fs.Float64(FailOnFlag, -1.0, "Fail if regression percentage is greater than or equal to threshold given")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 2 {
				return nil, fmt.Errorf("exactly 2 arguments required, got %d", len(args))
			}
			baselinePath := args[0]
			testPath := args[1]

			failOnThreshold, err := s.Flags.GetFloat64(FailOnFlag)
			if err != nil {
				return nil, err
			}

			var baselineRes []bpfProgramStats

			baselineRes, err = readStats(s.Path(baselinePath))
			if err != nil {
				return nil, fmt.Errorf("failed to read baseline file: %w", err)
			}

			testRes, err := readStats(s.Path(testPath))
			if err != nil {
				return nil, fmt.Errorf("failed to read test file: %w", err)
			}

			baselineStats := aggregateStats(baselineRes)
			testStats := aggregateStats(testRes)

			var progNames []string

			for name := range baselineStats {
				progNames = append(progNames, name)
			}

			for name := range testStats {
				if _, ok := baselineStats[name]; !ok {
					progNames = append(progNames, name)
				}
			}

			sort.Strings(progNames)

			w := s.LogWriter()
			tw := tabwriter.NewWriter(w, 5, 0, 3, ' ', 0)

			baselineHeader := strings.ToUpper(strings.TrimSuffix(filepath.Base(baselinePath), filepath.Ext(baselinePath)))
			testHeader := strings.ToUpper(strings.TrimSuffix(filepath.Base(testPath), filepath.Ext(testPath)))

			fmt.Fprintf(tw, "\t%s\t%s\n", baselineHeader, testHeader)

			failed := false
			var failures []string

			for _, name := range progNames {
				baseVal, hasBase := baselineStats[name]
				testVal, hasTest := testStats[name]

				baseStr := "-"
				testStr := "-"

				if hasBase {
					baseStr = fmt.Sprintf("%.2f (   0.00%%)", baseVal)
				}
				if hasTest {
					if hasBase && baseVal > 0 {
						diffPercent := ((testVal - baseVal) / baseVal) * 100.0
						sign := ""
						if diffPercent > 0 {
							sign = "+"
						}
						testStr = fmt.Sprintf("%.2f ( %s%.2f%%)", testVal, sign, diffPercent)
						if failOnThreshold >= 0.0 && diffPercent >= failOnThreshold {
							failed = true
							failures = append(failures, fmt.Sprintf("%s regression: %.2f%% (threshold: %.2f%%)", name, diffPercent, failOnThreshold))
						}
					} else {
						testStr = fmt.Sprintf("%.2f", testVal)
					}
				}
				fmt.Fprintf(tw, "ns/run %s\t%s\t%s\n", name, baseStr, testStr)
			}
			tw.Flush()

			if failed {
				fmt.Fprintln(w, "\nFailure: Performance regression detected!")
				for _, f := range failures {
					fmt.Fprintln(w, " -", f)
				}
				return nil, fmt.Errorf("performance regression detected")
			}

			return nil, nil
		},
	)
}

func readStats(path string) ([]bpfProgramStats, error) {
	bz, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var res []bpfProgramStats
	if err := json.Unmarshal(bz, &res); err != nil {
		return nil, err
	}

	return res, nil
}

func aggregateStats(results []bpfProgramStats) map[string]float64 {
	type agg struct {
		runtime time.Duration
		runs    uint64
	}
	aggs := make(map[string]*agg)
	for _, r := range results {
		if _, ok := aggs[r.Name]; !ok {
			aggs[r.Name] = &agg{}
		}
		aggs[r.Name].runtime += r.TotalRuntime
		aggs[r.Name].runs += r.TotalRuns
	}

	stats := make(map[string]float64)
	for name, a := range aggs {
		if a.runs > 0 {
			stats[name] = float64(a.runtime.Nanoseconds()) / float64(a.runs)
		} else {
			stats[name] = 0.0
		}
	}
	return stats
}
