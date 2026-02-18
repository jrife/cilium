package plugins

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/logging/logfields"

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
	PrepareHooks(ctx context.Context) error
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

func (m *manager) PrepareHooks(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, plugin := range m.registry {
		if _, err := plugin.client.PrepareHooks(ctx, &datapathplugins.PrepareHooksRequest{}); err != nil {
			m.logger.Error("PrepareHooks() failed",
				logfields.Error, err,
				"plugin", plugin.Name,
			)
		} else {
			m.logger.Debug("PrepareHooks() succeeded", "plugin", plugin.Name)
		}
	}

	return nil
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
