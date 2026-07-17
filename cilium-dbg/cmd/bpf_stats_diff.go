// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cilium/hive/shell"

	"github.com/cilium/cilium/pkg/bpf/stats"
	"github.com/cilium/cilium/pkg/hive"
)

var failOnThreshold float64

var bpfStatsDiffCmd = &cobra.Command{
	Use:   "diff <baseline.json> <test.json>",
	Short: "Compare BPF runtime stats against baseline config",
	Long: `Compare BPF runtime stats against baseline config.

Examples:
  # Compare test.json against baseline.json
  cilium-dbg bpf stats diff baseline.json test.json

  # Fail if regression is 10% or more
  cilium-dbg bpf stats diff baseline.json test.json --fail-on=10.0
  `,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		baselinePath := args[0]
		testPath := args[1]

		cfg := hive.DefaultShellConfig
		if err := cfg.Parse(cmd.Flags()); err != nil {
			return err
		}

		shellCmd := fmt.Sprintf("bpf/stats/diff %s %s", baselinePath, testPath)
		if cmd.Flags().Changed(stats.FailOnFlag) {
			shellCmd = fmt.Sprintf("%s --%s=%f", shellCmd, stats.FailOnFlag, failOnThreshold)
		}

		return shell.ShellExchange(cfg, os.Stdout, shellCmd)
	},
}

func init() {
	BPFStatsCmd.AddCommand(bpfStatsDiffCmd)
	bpfStatsDiffCmd.Flags().Float64Var(&failOnThreshold, stats.FailOnFlag, -1.0, "Fail if regression percentage is greater than or equal to threshold given")
	hive.DefaultShellConfig.Flags(bpfStatsDiffCmd.Flags())
}
