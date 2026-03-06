// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"context"
	"log/slog"

	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
)

func registerDPPWatcher(jg job.Group, db *statedb.DB, table statedb.Table[DatapathPlugin], orchestrator datapath.Orchestrator, registry Registry, logger *slog.Logger) {
	if !registry.IsEnabled() {
		return
	}

	jg.Add(job.OneShot(
		"follow",
		func(ctx context.Context, _ cell.Health) error {
			// Start tracking changes to the table. This instructs the database
			// to keep deleted objects off to the side for us to observe.
			wtxn := db.WriteTxn(table)
			changeIterator, err := table.Changes(wtxn)
			wtxn.Commit()
			if err != nil {
				return err
			}

			for {
				// Iterate over the changed objects.
				changes, watch := changeIterator.Next(db.ReadTxn())
				for change, _ := range changes {
					e := change.Object

					if change.Deleted {
						logger.Info("Datapath plugin deleted", logfields.Name, e.Name)

						if err := registry.Unregister(e); err != nil {
							logger.Error("Unregistering datapath plugin",
								logfields.Error, err,
								logfields.Name, e.Name,
							)
						}
					} else {
						logger.Info("Datapath plugin updated",
							logfields.Name, e.Name,
							logfields.Object, e,
						)

						if err := registry.Register(e); err != nil {
							logger.Error("Registering datapath plugin",
								logfields.Error, err,
								logfields.Name, e.Name,
							)
						}
					}
				}

				if err := orchestrator.Reinitialize(ctx); err != nil {
					logger.Error("Failed to reinitialize datapath", logfields.Error, err)
				}

				// Wait until there's new changes to consume.
				select {
				case <-ctx.Done():
					return nil
				case <-watch:
				}
			}
		},
	))
}
