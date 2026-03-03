package bpf

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/ebpf"
)

type AttachmentContext interface {
	AttachmentContext() *datapathplugins.AttachmentContext
	// TODO: With encryption, the collection is loaded once but pinned and
	// attached to multiple devices. Really, this needs to be able to return
	// a set of link directories.
	LinksDirs() []string
}

type CollectionLoader interface {
	Load(ctx context.Context, logger *slog.Logger, spec *ebpf.CollectionSpec, opts *CollectionOptions, lnc *datapath.LocalNodeConfiguration, attachmentContext AttachmentContext) (*ebpf.Collection, func() error, func(), error)
	LoadAndAssign(ctx context.Context, logger *slog.Logger, to any, spec *ebpf.CollectionSpec, opts *CollectionOptions, lnc *datapath.LocalNodeConfiguration, attachmentContext AttachmentContext) (func() error, func(), error)
}
