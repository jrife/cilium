// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"log/slog"

	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"k8s.io/client-go/tools/cache"

	"github.com/cilium/cilium/pkg/k8s"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/client"
	k8sUtils "github.com/cilium/cilium/pkg/k8s/utils"
)

const (
	DPPTableName = "datapathplugins"
)

var pluginNameIndex = statedb.Index[DatapathPlugin, string]{
	Name: "name",
	FromObject: func(obj DatapathPlugin) index.KeySet {
		return index.NewKeySet(index.String(obj.Name))
	},
	FromKey:    index.String,
	FromString: index.FromString,
	Unique:     true,
}

func NewDPPTable(db *statedb.DB) (statedb.RWTable[DatapathPlugin], error) {
	return statedb.NewTable(
		db,
		DPPTableName,
		pluginNameIndex,
	)
}

type dppListerWatcher cache.ListerWatcher

func newDPPListerWatcher(cs client.Clientset) dppListerWatcher {
	if !cs.IsEnabled() {
		return nil
	}
	return k8sUtils.ListerWatcherFromTyped(cs.CiliumV2alpha1().CiliumDatapathPlugins())
}

func registerDPPReflector(db *statedb.DB, log *slog.Logger, jg job.Group, lw dppListerWatcher, dpps statedb.RWTable[DatapathPlugin], registry Registry) {
	if !registry.IsEnabled() {
		return
	}

	k8s.RegisterReflector(jg, db,
		k8s.ReflectorConfig[DatapathPlugin]{
			Name:          "dpps",
			Table:         dpps,
			ListerWatcher: lw,
			MetricScope:   "CiliumDatapathPlugin",
			Transform: func(_ statedb.ReadTxn, obj any) (DatapathPlugin, bool) {
				dpp, ok := obj.(*api_v2alpha1.CiliumDatapathPlugin)
				if !ok {
					return DatapathPlugin{}, false
				}
				return DatapathPlugin{
					Name:             dpp.Name,
					AttachmentPolicy: dpp.Spec.AttachmentPolicy,
				}, true
			},
		})
}
