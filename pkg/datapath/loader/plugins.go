package loader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/plugins"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/google/uuid"
	"github.com/vishvananda/netlink"
)

func attachmentContextLXC(ep datapath.Endpoint) *datapathplugins.AttachmentContext {
	return &datapathplugins.AttachmentContext{
		Context: &datapathplugins.AttachmentContext_Tc{
			Tc: &datapathplugins.AttachmentContext_TC{
				EpConfig: &datapathplugins.AttachmentContext_TC_EndpointConfig{},
			},
		},
	}
}

func attachmentContextHost(ep datapath.Endpoint, device netlink.Link) *datapathplugins.AttachmentContext {
	return &datapathplugins.AttachmentContext{}
}

func attachmentContextOverlay(device netlink.Link) *datapathplugins.AttachmentContext {
	return &datapathplugins.AttachmentContext{}
}

func attachmentContextXDP(device netlink.Link) *datapathplugins.AttachmentContext {
	return &datapathplugins.AttachmentContext{}
}

func attachmentContextWireguard(device netlink.Link) *datapathplugins.AttachmentContext {
	return &datapathplugins.AttachmentContext{}
}

func attachmentContextEncryption(ifaces []netlink.Link) *datapathplugins.AttachmentContext {
	return &datapathplugins.AttachmentContext{}
}

type pluginCollectionLoader struct {
	registry plugins.Registry
}

func (l *loader) LoadAndAssign(ctx context.Context, logger *slog.Logger, to any, spec *ebpf.CollectionSpec, opts *bpf.CollectionOptions, lnc *datapath.LocalNodeConfiguration, attachmentContext *datapathplugins.AttachmentContext, linksDirs []string) (func() error, func(), error) {
	coll, commit, cleanupLinks, err := l.Load(ctx, logger, spec, opts, lnc, attachmentContext, linksDirs)
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		if _, err := fmt.Fprintf(os.Stderr, "Verifier error: %s\nVerifier log: %+v\n", err, ve); err != nil {
			return nil, nil, fmt.Errorf("writing verifier log to stderr: %w", err)
		}
	}
	if err != nil {
		return nil, nil, fmt.Errorf("loading eBPF collection into the kernel: %w", err)
	}

	if err := coll.Assign(to); err != nil {
		cleanupLinks()
		coll.Close()
		return nil, nil, fmt.Errorf("assigning eBPF objects to %T: %w", to, err)
	}

	return commit, cleanupLinks, nil
}

func (l *loader) Load(ctx context.Context, logger *slog.Logger, spec *ebpf.CollectionSpec, opts *bpf.CollectionOptions, lnc *datapath.LocalNodeConfiguration, attachmentContext *datapathplugins.AttachmentContext, linksDirs []string) (coll *ebpf.Collection, commit func() error, cleanup func(), err error) {
	if !l.pluginRegistry.IsEnabled() {
		// If plugins were previously enabled, clean up any lingering
		// pinned links in the plugin link directories.
		if err := purgeLinksDirs(linksDirs); err != nil {
			logger.Error("Failed to purge link dirs", logfields.Error, err)
		}

		coll, commit, err = bpf.LoadCollection(logger, spec, opts)
		return coll, commit, func() {}, err
	}

	pluginMap := l.pluginRegistry.Plugins()
	loadHooksRequests, err := prepareHooks(ctx, logger, pluginMap, spec, lnc, attachmentContext)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("preparing hooks: %w", err)
	}

	coll, commit, err = bpf.LoadCollection(logger, spec, opts)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading collection: %w", err)
	}
	defer func() {
		if err != nil {
			coll.Close()
		}
	}()

	commit, cleanup, err = loadHooks(ctx, logger, coll, commit, pluginMap, loadHooksRequests, attachmentContext, linksDirs)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("loading hooks: %w", err)
	}

	return coll, commit, cleanup, nil
}

func prepareHooks(ctx context.Context, logger *slog.Logger, pluginMap map[string]plugins.Plugin, spec *ebpf.CollectionSpec, lnc *datapath.LocalNodeConfiguration, attachmentContext *datapathplugins.AttachmentContext) (_ map[string]*datapathplugins.LoadHooksRequest, err error) {
	req := &datapathplugins.PrepareHooksRequest{
		AttachmentContext: attachmentContext,
		LocalNodeConfig:   &datapathplugins.LocalNodeConfig{},
		Collection: &datapathplugins.PrepareHooksRequest_CollectionSpec{
			Programs: make([]*datapathplugins.PrepareHooksRequest_CollectionSpec_ProgramSpec, 0, len(spec.Programs)),
		},
	}

	for name := range spec.Programs {
		req.Collection.Programs = append(req.Collection.Programs, &datapathplugins.PrepareHooksRequest_CollectionSpec_ProgramSpec{
			Name: name,
		})
	}

	type prepareResult struct {
		plugin plugins.Plugin
		err    error
		resp   *datapathplugins.PrepareHooksResponse
	}

	prepareResults := make(chan prepareResult)
	for _, p := range pluginMap {
		go func(p plugins.Plugin) {
			resp, err := p.PrepareHooks(ctx, req)
			prepareResults <- prepareResult{plugin: p, err: err, resp: resp}
		}(p)
	}

	responses := make(map[string]*datapathplugins.PrepareHooksResponse)
	hooksSpec := newHooksSpec()

	for len(responses) != len(pluginMap) {
		var r prepareResult
		select {
		case r = <-prepareResults:
		case <-ctx.Done():
			return nil, fmt.Errorf("waiting for PrepareHooks() responses: %w", ctx.Err())
		}

		if r.err != nil {
			logger.Error("PrepareHooks() failed",
				logfields.Error, r.err,
				"plugin", r.plugin.Name(),
			)

			if r.plugin.AttachmentPolicy() == api_v2alpha1.AttachmentPolicyAlways {
				err = errors.Join(err, fmt.Errorf("%s: PrepareHooks(): %w", r.plugin.Name(), r.err))
			}

			continue
		}

		logger.Debug("PrepareHooks() succeeded", "plugin", r.plugin.Name())
		responses[r.plugin.Name()] = r.resp

	process_hooks:
		for _, h := range r.resp.Hooks {
			ps := spec.Programs[h.Target]
			if ps == nil {
				err = errors.Join(err, fmt.Errorf("%s: PrepareHooks(): target program \"%s\" does not exist in the collection spec", r.plugin.Name(), h.Target))

				continue
			}

			if h.Type != datapathplugins.HookType_PRE && h.Type != datapathplugins.HookType_POST {
				err = errors.Join(err, fmt.Errorf("%s: PrepareHooks(): invalid hook type %v", r.plugin.Name(), h.Type))

				continue
			}

			hooksSpec.hook(ps.Name, h.Type).addNode(r.plugin.Name())

			for _, c := range h.Constraints {
				otherPlugin := pluginMap[c.Plugin]
				if otherPlugin == nil {
					logger.Debug("PrepareHooks() constraint references unknown plugin",
						"plugin", r.plugin.Name(),
						"otherPlugin", c.Plugin,
					)

					continue
				}

				switch c.Order {
				case datapathplugins.PrepareHooksResponse_HookSpec_OrderingConstraint_BEFORE:
					hooksSpec.hook(ps.Name, h.Type).before(r.plugin.Name(), otherPlugin.Name())
				case datapathplugins.PrepareHooksResponse_HookSpec_OrderingConstraint_AFTER:
					hooksSpec.hook(ps.Name, h.Type).after(r.plugin.Name(), otherPlugin.Name())
				default:
					err = errors.Join(err, fmt.Errorf("%s: PrepareHooks(): invalid ordering constraint: %v", r.plugin.Name(), h.Type))
					continue process_hooks
				}
			}
		}
	}

	if err != nil {
		return nil, err
	}

	loadHooksRequests, err := hooksSpec.instrumentCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("instrumenting collection: %w", err)
	}

	for plugin, req := range loadHooksRequests {
		prepareHooksResp := responses[plugin]
		req.Cookie = prepareHooksResp.Cookie
	}
	return nil, nil
}

func purgeLinksDirs(linksDirs []string) error {
	var err error

	for _, linksDir := range linksDirs {
		if err := bpf.Remove(linksDir); err != nil {
			err = errors.Join(err, fmt.Errorf("purging plugin links dir %s: %w", linksDir, err))
		}
	}

	return err
}

func loadHooks(ctx context.Context, logger *slog.Logger, coll *ebpf.Collection, commit func() error, pluginMap map[string]plugins.Plugin, loadHooksRequests map[string]*datapathplugins.LoadHooksRequest, attachmentContext *datapathplugins.AttachmentContext, linksDirs []string) (_ func() error, _ func(), err error) {
	type loadResult struct {
		plugin plugins.Plugin
		err    error
		resp   *datapathplugins.LoadHooksResponse
	}

	loadResults := make(chan loadResult)

	for plugin, req := range loadHooksRequests {
		requestID := uuid.New().String()
		operationDir := bpffsPluginOperationDir(bpf.CiliumPath(), plugin, requestID)

		if err := bpf.MkdirBPF(operationDir); err != nil {
			return nil, nil, fmt.Errorf("creating BPF operation directory: %w", err)
		}

		defer func() {
			if err := bpf.Remove(operationDir); err != nil {
				logger.Error("Failed to clean up LoadHooks() operation directory",
					logfields.Error, err,
					logfields.Path, operationDir,
				)
			}
		}()

		for _, hook := range req.Hooks {
			prog := coll.Programs[hook.Target]
			if prog == nil {
				return nil, nil, fmt.Errorf("LoadHooksRequest for %s references a non-existant program: %s", plugin, hook.Target)
			}

			info, err := prog.Info()
			if err != nil {
				return nil, nil, fmt.Errorf("getting info for program %s: %w", hook.Target, err)
			}

			id, avail := info.ID()
			if !avail {
				return nil, nil, fmt.Errorf("unable to determine ID for program %s: %w", hook.Target, err)
			}
			hook.AttachTarget.ProgramId = uint64(id) // TODO: make this a uint32
			hook.PinPath = filepath.Join(operationDir, fmt.Sprintf("%s_%s", hook.Target, hook.AttachTarget.SubprogName))
		}

		go func(req *datapathplugins.LoadHooksRequest) {
			p := pluginMap[plugin]
			resp, err := p.LoadHooks(ctx, req)
			loadResults <- loadResult{plugin: p, err: err, resp: resp}
		}(req)
	}

	type pin struct {
		link   link.Link
		plugin plugins.Plugin
		name   string
	}

	var pins []pin

	closeLinks := func() {
		for _, p := range pins {
			p.link.Close()
		}
	}

	defer func() {
		if err != nil {
			closeLinks()
		}
	}()

	for len(loadHooksRequests) > 0 {
		var r loadResult
		select {
		case r = <-loadResults:
		case <-ctx.Done():
			return nil, nil, fmt.Errorf("waiting for LoadHooks() responses: %w", ctx.Err())
		}

		if r.err != nil {
			logger.Error("LoadHooks() failed",
				logfields.Error, r.err,
				"plugin", r.plugin.Name(),
			)

			if r.plugin.AttachmentPolicy() == api_v2alpha1.AttachmentPolicyAlways {
				err = errors.Join(err, fmt.Errorf("%s: LoadHooks(): %w", r.plugin.Name(), r.err))
			}

			continue
		}

		logger.Debug("LoadHooks() succeeded", "plugin", r.plugin.Name())

		req := loadHooksRequests[r.plugin.Name()]

		for _, hook := range req.Hooks {
			prog, err := ebpf.LoadPinnedProgram(hook.PinPath, &ebpf.LoadPinOptions{})
			if err != nil {
				return nil, nil, fmt.Errorf("load pinned hook program at %s: %w", hook.PinPath, err)
			}
			if err := os.Remove(hook.PinPath); err != nil {
				return nil, nil, fmt.Errorf("removing pinned hook program at %s: %w", hook.PinPath, err)
			}
			freplace, err := link.AttachFreplace(coll.Programs[hook.Target], hook.AttachTarget.SubprogName, prog)
			if err != nil {
				return nil, nil, fmt.Errorf("creating freplace link for hook: %w", err)
			}
			pins = append(pins, pin{
				link:   freplace,
				plugin: r.plugin,
				name:   filepath.Base(hook.PinPath),
			})
		}

		delete(loadHooksRequests, r.plugin.Name())
	}

	return func() error {
		if err := purgeLinksDirs(linksDirs); err != nil {
			return err
		}

		for _, linksDir := range linksDirs {
			for _, p := range pins {
				pluginLinksDir := filepath.Join(linksDir, p.plugin.Name())
				if err := bpf.MkdirBPF(pluginLinksDir); err != nil {
					return fmt.Errorf("ensuring the existence of plugin links dir %s: %w", pluginLinksDir, err)
				}

				pinPath := filepath.Join(pluginLinksDir, p.name)
				if err := p.link.Pin(pinPath); err != nil {
					return fmt.Errorf("pinning hook program to %s: %w", pinPath, err)
				}

				logger.Debug("Replaced hook program pin", logfields.Pin, pinPath)
			}
		}

		return commit()
	}, closeLinks, nil
}

func (l *loader) initializePluginsDir() error {
	return bpf.Remove(bpffsPluginsOperationsDir(bpf.CiliumPath()))
}

func preHookSubprogName(pluginName string) string {
	return fmt.Sprintf("__pre_hook_%s__", pluginName)
}

func postHookSubprogName(pluginName string) string {
	return fmt.Sprintf("__post_hook_%s__", pluginName)
}

type hooksSpec struct {
	hooks map[string]map[datapathplugins.HookType]*pluginDependencyGraph
}

func newHooksSpec() *hooksSpec {
	return &hooksSpec{
		hooks: make(map[string]map[datapathplugins.HookType]*pluginDependencyGraph),
	}
}

func (hs *hooksSpec) hook(target string, hookType datapathplugins.HookType) *pluginDependencyGraph {
	if hs.hooks[target] == nil {
		hs.hooks[target] = map[datapathplugins.HookType]*pluginDependencyGraph{
			datapathplugins.HookType_PRE:  &pluginDependencyGraph{},
			datapathplugins.HookType_POST: &pluginDependencyGraph{},
		}
	}

	return hs.hooks[target][hookType]
}

func (hs *hooksSpec) instrumentCollection(cs *ebpf.CollectionSpec) (map[string]*datapathplugins.LoadHooksRequest, error) {
	var err error
	hooks := make(map[string]*datapathplugins.LoadHooksRequest)

	for hookTarget, hookTypes := range hs.hooks {
		pre, sortErr := hookTypes[datapathplugins.HookType_PRE].sort()
		if sortErr != nil {
			err = errors.Join(err, fmt.Errorf("%s/%s: %w", hookTarget, datapathplugins.HookType_PRE, sortErr))
			continue
		}
		post, sortErr := hookTypes[datapathplugins.HookType_POST].sort()
		if sortErr != nil {
			err = errors.Join(err, fmt.Errorf("%s/%s: %w", hookTarget, datapathplugins.HookType_POST, sortErr))
			continue
		}

		if err := hs.instrumentProgram(cs.Programs[hookTarget], pre, post, hooks); err != nil {
			err = errors.Join(err, fmt.Errorf("instrumenting %s: %w", hookTarget, err))
			continue
		}
	}

	return hooks, err
}

func (hs *hooksSpec) instrumentProgram(ps *ebpf.ProgramSpec, pre []string, post []string, hooks map[string]*datapathplugins.LoadHooksRequest) error {
	btfMeta := btf.FuncMetadata(&ps.Instructions[0])
	funcProto, hasFuncProto := btfMeta.Type.(*btf.FuncProto)
	if !hasFuncProto {
		return fmt.Errorf("unable to extract function BTF info for target program")
	}

	var dispatcherInstructions []asm.Instruction

	// Preserve ctx in R6, callee saved register.
	asm.Mov.Reg(asm.R6, asm.R1)

	for _, plugin := range pre {
		subprogName := preHookSubprogName(plugin)
		dispatcherInstructions = append(dispatcherInstructions,
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Call.Label(subprogName),
			asm.JNE.Imm(asm.R0, -1, "return"),
		)
		hooks[plugin].Hooks = append(hooks[plugin].Hooks, &datapathplugins.LoadHooksRequest_Hook{
			AttachTarget: &datapathplugins.LoadHooksRequest_Hook_AttachTarget{
				SubprogName: subprogName,
			},
			Type:   datapathplugins.HookType_PRE,
			Target: ps.Name,
		})
	}

	dispatcherInstructions = append(dispatcherInstructions,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Call.Label(btfMeta.Name),
		asm.Mov.Reg(asm.R7, asm.R0),
	)

	for _, plugin := range post {
		subprogName := postHookSubprogName(plugin)
		dispatcherInstructions = append(dispatcherInstructions,
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Mov.Reg(asm.R2, asm.R7),
			asm.Call.Label(subprogName),
			asm.JNE.Imm(asm.R0, -1, "return"),
		)
		hooks[plugin].Hooks = append(hooks[plugin].Hooks, &datapathplugins.LoadHooksRequest_Hook{
			AttachTarget: &datapathplugins.LoadHooksRequest_Hook_AttachTarget{
				SubprogName: subprogName,
			},
			Type:   datapathplugins.HookType_POST,
			Target: ps.Name,
		})
	}

	dispatcherInstructions = append(dispatcherInstructions,
		asm.Mov.Reg(asm.R0, asm.R7),
		asm.Return().WithSymbol("return"),
	)

	postHookProto := *funcProto
	postHookProto.Params = append(
		append([]btf.FuncParam(nil), postHookProto.Params...),
		btf.FuncParam{Name: "ret", Type: funcProto.Return},
	)

	for _, plugin := range pre {
		hookName := preHookSubprogName(plugin)
		dispatcherInstructions = append(dispatcherInstructions,
			btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol(hookName), &btf.Func{
				Name: hookName,
				Type: funcProto,
				// BTF_FUNC_GLOBAL ensures programs are independently verified.
				Linkage: btf.GlobalFunc,
			}),
			asm.Return(),
		)
	}
	for _, plugin := range post {
		hookName := postHookSubprogName(plugin)
		dispatcherInstructions = append(dispatcherInstructions,
			btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol(hookName), &btf.Func{
				Name: hookName,
				Type: &postHookProto,
				// BTF_FUNC_GLOBAL ensures programs are independently verified.
				Linkage: btf.GlobalFunc,
			}),
			asm.Return(),
		)
	}
	ps.Instructions[0] = ps.Instructions[0].WithSymbol(btfMeta.Name)
	dispatcherInstructions = append(dispatcherInstructions, ps.Instructions...)

	return nil
}

type node struct {
	exists        bool
	outgoing      map[string]struct{}
	incomingCount int
}

type pluginDependencyGraph map[string]*node

func (g pluginDependencyGraph) sort() ([]string, error) {
	var empty []string
	sorted := make([]string, 0, len(g))

	for p, n := range g {
		if n.incomingCount == 0 {
			empty = append(empty, p)
		}
	}

	for len(empty) > 0 {
		batchSize := len(empty)

		for i := 0; i < batchSize; i++ {
			sorted = append(sorted, empty[0])

			for after := range g[empty[0]].outgoing {
				g[after].incomingCount--

				if g[after].incomingCount == 0 {
					empty = append(empty, after)
				}
			}

			empty = empty[1:]
		}
	}

	if len(g) > 0 {
		return nil, fmt.Errorf("cycle detected")
	}

	return sorted, nil
}

func (g pluginDependencyGraph) lazyInitNode(name string) {
	if g[name] == nil {
		g[name] = &node{
			outgoing: map[string]struct{}{},
		}
	}
}

func (g pluginDependencyGraph) addNode(name string) {
	if g[name] == nil {
		g[name] = &node{}
	}

	g[name].exists = true
}

func (g pluginDependencyGraph) before(a, b string) {
	g.after(b, a)
}

func (g pluginDependencyGraph) after(a, b string) {
	if g[a] == nil {
		g[a] = &node{}
	}

	g[a].outgoing[b] = struct{}{}
}
