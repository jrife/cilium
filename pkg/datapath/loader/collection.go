package loader

import (
	"context"
	"log/slog"

	"github.com/cilium/cilium/pkg/bpf"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/ebpf"
)

type basicCollectionLoader struct {
}

func (bcl *basicCollectionLoader) Load(ctx context.Context, logger *slog.Logger, spec *ebpf.CollectionSpec, opts *bpf.CollectionOptions, lnc *datapath.LocalNodeConfiguration, attachmentContext bpf.AttachmentContext) (*ebpf.Collection, func() error, func(), error) {
	coll, commit, err := bpf.LoadCollection(logger, spec, opts)
	return coll, commit, func() {}, err
}

func (bcl *basicCollectionLoader) LoadAndAssign(ctx context.Context, logger *slog.Logger, to any, spec *ebpf.CollectionSpec, opts *bpf.CollectionOptions, lnc *datapath.LocalNodeConfiguration, attachmentContext bpf.AttachmentContext) (func() error, func(), error) {
	commit, err := bpf.LoadAndAssign(logger, to, spec, opts)
	return commit, func() {}, err
}
