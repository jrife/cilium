package plugins

import (
	"fmt"
	"log/slog"
	"path/filepath"
	"sync"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	api_v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	sockFileName = "plugin.sock"
)

func pluginStateDir(stateDir, name string) string {
	return filepath.Join(stateDir, name)
}

func pluginSocketFile(stateDir, name string) string {
	return filepath.Join(pluginStateDir(stateDir, name), sockFileName)
}

type Plugin interface {
	datapathplugins.DatapathPluginClient
	Name() string
	AttachmentPolicy() api_v2alpha1.CiliumDatapathPluginAttachmentPolicy
}

type Registry interface {
	IsEnabled() bool
	Register(datapathPlugin DatapathPlugin) error
	Unregister(datapathPlugin DatapathPlugin) error
	Plugins() map[string]Plugin
}

type registry struct {
	mu                     sync.Mutex
	enabled                bool
	logger                 *slog.Logger
	registry               map[string]*plugin
	datapathPluginStateDir string
}

func newRegistry(logger *slog.Logger, config datapathPluginsConfig) Registry {
	if !config.DatapathPluginsEnabled {
		logger.Info("Disabling datapath plugins.")
	} else {
		logger.Info("Enabling datapath plugins", logfields.Path, config.DatapathPluginsStateDir)
	}

	return &registry{
		enabled:                config.DatapathPluginsEnabled,
		logger:                 logger,
		registry:               make(map[string]*plugin),
		datapathPluginStateDir: config.DatapathPluginsStateDir,
	}
}

func (m *registry) IsEnabled() bool {
	return m.enabled
}

func (m *registry) Register(datapathPlugin DatapathPlugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.registry[datapathPlugin.Name]
	if ok {
		p.DatapathPlugin = datapathPlugin

		return nil
	}

	c, err := grpc.NewClient("unix://"+pluginSocketFile(m.datapathPluginStateDir, datapathPlugin.Name), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("creating client: %w", err)
	}

	m.registry[datapathPlugin.Name] = &plugin{
		DatapathPlugin:       datapathPlugin,
		DatapathPluginClient: datapathplugins.NewDatapathPluginClient(c),
		conn:                 c,
		logger:               m.logger.With("plugin", datapathPlugin.Name),
	}

	return nil
}

func (m *registry) Unregister(datapathPlugin DatapathPlugin) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, ok := m.registry[datapathPlugin.Name]
	if !ok {
		return nil
	}

	delete(m.registry, datapathPlugin.Name)

	return p.close()
}

func (m *registry) Plugins() map[string]Plugin {
	m.mu.Lock()
	defer m.mu.Unlock()

	snapshot := make(map[string]Plugin)

	for name, plugin := range m.registry {
		snapshot[name] = plugin
	}

	return snapshot
}

type plugin struct {
	DatapathPlugin
	datapathplugins.DatapathPluginClient
	conn   *grpc.ClientConn
	logger *slog.Logger
}

func (p *plugin) Name() string {
	return p.DatapathPlugin.Name
}

func (p *plugin) AttachmentPolicy() api_v2alpha1.CiliumDatapathPluginAttachmentPolicy {
	return p.DatapathPlugin.AttachmentPolicy
}

func (p *plugin) close() error {
	if p.conn == nil {
		return nil
	}
	return p.conn.Close()
}
