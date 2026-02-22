package plugins

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/ebpf"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	sockFileName = "plugin.sock"
)

type Manager interface {
	Register(datapathPlugin DatapathPlugin) error
	Unregister(datapathPlugin DatapathPlugin) error
	ForEach(func(datapathPlugin DatapathPlugin, client datapathplugins.DatapathPluginClient) error) error
	PrepareHooks(ctx context.Context, spec *ebpf.CollectionSpec, ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration) (map[string]*datapathplugins.LoadHooksRequest, error)
}

type manager struct {
	mu                     sync.Mutex
	logger                 *slog.Logger
	registry               map[string]*plugin
	datapathPluginStateDir string
}

func newManager(logger *slog.Logger, c datapathPluginsConfig) *manager {
	return &manager{
		logger:                 logger,
		registry:               make(map[string]*plugin),
		datapathPluginStateDir: c.DatapathPluginsStateDir,
	}
}

func (m *manager) Register(datapathPlugin DatapathPlugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.registry[datapathPlugin.Name]
	if ok {
		p.DatapathPlugin = datapathPlugin

		return nil
	}

	c, err := grpc.NewClient("unix://"+filepath.Join(m.datapathPluginStateDir, datapathPlugin.Name, sockFileName), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	m.registry[datapathPlugin.Name] = &plugin{
		DatapathPlugin: datapathPlugin,
		client:         datapathplugins.NewDatapathPluginClient(c),
		conn:           c,
		logger:         m.logger.With("plugin", datapathPlugin.Name),
	}

	go m.registry[datapathPlugin.Name].monitor()

	return nil
}

func (m *manager) Unregister(datapathPlugin DatapathPlugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.registry[datapathPlugin.Name]
	if !ok {
		return nil
	}

	delete(m.registry, datapathPlugin.Name)

	return p.close()
}

func (m *manager) ForEach(do func(plugin DatapathPlugin, client datapathplugins.DatapathPluginClient) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, plugin := range m.registry {
		if err := do(plugin.DatapathPlugin, plugin.client); err != nil {
			return err
		}
	}

	return nil
}

func (m *manager) PrepareHooks(ctx context.Context, spec *ebpf.CollectionSpec, ep datapath.Endpoint, lnc *datapath.LocalNodeConfiguration) (map[string]*datapathplugins.LoadHooksRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	req := &datapathplugins.PrepareHooksRequest{
		AttachmentContext: endpointAttachmentContext(ep),
		LocalNodeConfig:   localNodeConfig(lnc),
		Collection: &datapathplugins.PrepareHooksRequest_CollectionSpec{
			Programs: make([]*datapathplugins.PrepareHooksRequest_CollectionSpec_ProgramSpec, 0, len(spec.Programs)),
		},
	}

	for name := range spec.Programs {
		req.Collection.Programs = append(req.Collection.Programs, &datapathplugins.PrepareHooksRequest_CollectionSpec_ProgramSpec{
			Name: name,
		})
	}

	type result struct {
		plugin *plugin
		err    error
		resp   *datapathplugins.PrepareHooksResponse
	}

	results := make(chan result)
	for _, p := range m.registry {
		go func(p *plugin) {
			resp, err := p.client.PrepareHooks(ctx, req)
			results <- result{plugin: p, err: err, resp: resp}
		}(p)
	}

	var err error
	responses := make(map[string]*datapathplugins.PrepareHooksResponse)
	hooksSpec := newHooksSpec()

	for r := range results {
		if r.err != nil {
			m.logger.Error("PrepareHooks() failed",
				logfields.Error, r.err,
				"plugin", r.plugin.Name,
			)

			if r.plugin.AttachmentPolicy == api_v2alpha1.AttachmentPolicyAlways {
				err = errors.Join(err, fmt.Errorf("%s: PrepareHooks(): %w", r.plugin.Name, r.err))
			}

			continue
		}

		m.logger.Debug("PrepareHooks() succeeded", "plugin", r.plugin.Name)
		responses[r.plugin.Name] = r.resp

	process_hooks:
		for _, h := range r.resp.Hooks {
			ps := spec.Programs[h.Target]
			if ps == nil {
				err = errors.Join(err, fmt.Errorf("%s: PrepareHooks(): target program \"%s\" does not exist in the collection spec", r.plugin.Name, h.Target))

				continue
			}

			if h.Type != datapathplugins.HookType_PRE && h.Type != datapathplugins.HookType_POST {
				err = errors.Join(err, fmt.Errorf("%s: PrepareHooks(): invalid hook type %v", r.plugin.Name, h.Type))

				continue
			}

			hooksSpec.hook(ps.Name, h.Type).addNode(r.plugin.Name)

			for _, c := range h.Constraints {
				otherPlugin := m.registry[c.Plugin]
				if otherPlugin == nil {
					m.logger.Debug("PrepareHooks() constraint references unknown plugin",
						"plugin", r.plugin.Name,
						"otherPlugin", c.Plugin,
					)

					continue
				}

				switch c.Order {
				case datapathplugins.PrepareHooksResponse_HookSpec_OrderingConstraint_BEFORE:
					hooksSpec.hook(ps.Name, h.Type).before(r.plugin.Name, otherPlugin.Name)
				case datapathplugins.PrepareHooksResponse_HookSpec_OrderingConstraint_AFTER:
					hooksSpec.hook(ps.Name, h.Type).after(r.plugin.Name, otherPlugin.Name)
				default:
					err = errors.Join(err, fmt.Errorf("%s: PrepareHooks(): invalid ordering constraint: %v", r.plugin.Name, h.Type))
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

	return loadHooksRequests, nil
}

type plugin struct {
	DatapathPlugin
	client datapathplugins.DatapathPluginClient
	conn   *grpc.ClientConn
	cancel func()
	logger *slog.Logger
}

func (p *plugin) close() error {
	if p.conn == nil {
		return nil
	}
	p.cancel()
	return p.conn.Close()
}

func (p *plugin) monitor() {
	ctx, cancel := context.WithCancel(context.Background())
	p.cancel = cancel

	p.logger.Info("Starting datapath plugin monitor")
	p.logger.Info("Datapath plugin connection state", logfields.State, p.conn.GetState().String())

	for p.conn.WaitForStateChange(ctx, p.conn.GetState()) {
		p.logger.Info("Datapath plugin connection state", logfields.State, p.conn.GetState().String())
	}

	p.logger.Info("Shutting down datapath plugin monitor")
}

func newDatapathPluginManager(logger *slog.Logger, config datapathPluginsConfig) (Manager, error) {
	if !config.DatapathPluginsEnabled {
		logger.Info("Disabling datapath plugins.")

		return nil, nil
	}

	logger.Info("Enabling datapath plugins", logfields.Path, config.DatapathPluginsStateDir)

	return newManager(logger, config), nil
}

func endpointAttachmentContext(ep datapath.Endpoint) *datapathplugins.AttachmentContext {
	return &datapathplugins.AttachmentContext{
		Context: &datapathplugins.AttachmentContext_Tc{
			Tc: &datapathplugins.AttachmentContext_TC{
				EpConfig: &datapathplugins.AttachmentContext_TC_EndpointConfig{},
			},
		},
	}
}

func localNodeConfig(lnc *datapath.LocalNodeConfiguration) *datapathplugins.LocalNodeConfig {
	return &datapathplugins.LocalNodeConfig{}
}
