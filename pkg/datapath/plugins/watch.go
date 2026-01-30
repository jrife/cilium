// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package plugins

import (
	"context"
	"fmt"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/cilium/statedb"
)

func registerDPPWatcher(jg job.Group, db *statedb.DB, table statedb.Table[DatapathPlugin]) {
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
				for change, rev := range changes {
					e := change.Object
					fmt.Printf("Name: %s, AttachmentPolicy: %s (revision: %d, deleted: %v)\n",
						e.Name, e.AttachmentPolicy, rev, change.Deleted)
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
