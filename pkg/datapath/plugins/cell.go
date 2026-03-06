// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"

	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
)

type DatapathPlugin struct {
	Name             string
	AttachmentPolicy api_v2alpha1.CiliumDatapathPluginAttachmentPolicy
}

func (dpp DatapathPlugin) TableHeader() []string {
	return []string{
		"Name",
		"AttachmentPolicy",
	}
}

func (dpp DatapathPlugin) TableRow() []string {
	return []string{
		dpp.Name,
		string(dpp.AttachmentPolicy),
	}
}

type datapathPluginsConfig struct {
	DatapathPluginsEnabled  bool
	DatapathPluginsStateDir string
}

func (c datapathPluginsConfig) Flags(flags *pflag.FlagSet) {
	flags.Bool("datapath-plugins-enabled", c.DatapathPluginsEnabled, "Flag to enable datapath plugins.")
	flags.String("datapath-plugins-state-dir", c.DatapathPluginsStateDir, "Parent directory for per-plugin subdirectories containing UNIX sockets for talking to a Cilium datapath plugin along with state related to that plugin.")
}

var defaultDatapathPluginsConfig = datapathPluginsConfig{}

var Cell = cell.Module(
	"datapath-plugins",
	"Controller for Cilium Datapath Plugins",

	cell.Config(defaultDatapathPluginsConfig),
	cell.Provide(
		// Provide Table[*DatapathPlugin].
		statedb.RWTable[DatapathPlugin].ToTable,
		newRegistry,
	),
	cell.ProvidePrivate(
		newDPPListerWatcher,
		NewDPPTable,
	),
	cell.Invoke(
		registerDPPReflector,
		registerDPPWatcher,
	),
)
