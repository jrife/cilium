// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/command"
	"github.com/cilium/cilium/pkg/common"
	lbmap "github.com/cilium/cilium/pkg/loadbalancer/maps"
)

var bpfSocknatCmd = &cobra.Command{
	Use:   "sockmeta",
	Short: "Socket metadata operations",
}

var bpfSocknatListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List socket-LB socket metadata entries",
	Run: func(cmd *cobra.Command, args []string) {
		common.RequireRootPrivilege("cilium bpf socknat list")

		// Create the maps directly
		sockMeta4Map := lbmap.NewSockMeta4Map(256 * 1024) // Default size
		sockMeta6Map := lbmap.NewSockMeta6Map(256 * 1024) // Default size

		entries := make(map[string][]string)
		dumpSKMetaEntries(entries, sockMeta4Map, sockMeta6Map)

		if command.OutputOption() {
			if err := command.PrintOutput(entries); err != nil {
				Fatalf("Unable to generate %s output: %s",
					command.OutputOptionString(), err)
			}
			return
		}

		TablePrinter("Socket Cookie", "Backend -> Frontend", entries)
	},
}

func dumpSKMetaEntries(entries map[string][]string, sockRevMeta4Map, sockMeta6Map *bpf.Map) {
}

func init() {
	BPFCmd.AddCommand(bpfSocknatCmd)
	bpfSocknatCmd.AddCommand(bpfSocknatListCmd)
	command.AddOutputOption(bpfSocknatListCmd)
}
