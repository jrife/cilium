// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb"

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

var Cell = cell.Module(
	"datapath-plugins",
	"Controller for Cilium Datapath Plugins",

	cell.Provide(
		// Provide Table[*DatapathPlugin].
		statedb.RWTable[DatapathPlugin].ToTable,
	),

	cell.ProvidePrivate(
		newDPPListerWatcher,
		NewDPPTable,
	),

	cell.Invoke(
		// Reflect the CiliumLocalRedirectPolicy CRDs into Table[*LocalRedirectPolicy]
		registerDPPReflector,

		// Register a controller to process the changes in the LRP, pod and frontend
		// tables.
		registerDPPWatcher,
	),

	// cell.Provide(dppAPI),
)
