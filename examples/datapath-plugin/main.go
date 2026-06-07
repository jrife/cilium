// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/api/v1/datapathplugins"

	"github.com/google/uuid"
	"github.com/vishvananda/netlink"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const (
	ciliumVersionMetadataKey = "cilium_version"

	logKeyCiliumVersion = ciliumVersionMetadataKey
	logKeyListenPath    = "listenPath"
	logKeyRequest       = "request"
	logKeyResponse      = "response"
	logKeyTraceId       = "traceId"
	logKeyError         = "error"
	logKeyNamespace     = "namespace"
	logKeyBPFFS         = "bpffsDir"
	logKeyNetkitEnabled = "netkitEnabled"

	fromNetdev          = "cil_from_netdev"
	fromContainer       = "cil_from_container"
	beforeFromNetdev    = "before_cil_from_netdev"
	beforeFromContainer = "before_cil_from_container"

	netkitEnabled = "netkit_enabled"

	proxyPodNamePrefix    = "tproxy"
	workloadPodNamePrefix = "iperf"

	ifindicesMap = "ifindices"
	ifMacsMap    = "ifmacs"

	ifaceProxy        = 0
	ifaceWorkload     = 1
	ifaceWorkloadPeer = 2
	ifaceProxyPeer    = 3
	ifaceUnknown      = 4
)

func main() {
	unixSocketPath := flag.String("unix-socket-path", "", "UNIX socket to listen on")
	namespace := flag.String("namespace", "default", "Kubernetes namespace where test workloads run")
	bpffsDir := flag.String("bpffs-dir", "", "BPFFS directory used for map pins")
	netkitEnabled := flag.Bool("netkit-enabled", false, "Is netkit enabled")
	flag.Parse()

	logger := slog.Default()

	if err := os.MkdirAll(*bpffsDir, 0o755); err != nil {
		logger.Error("Could not create BPFFS dir",
			logKeyBPFFS, *bpffsDir,
		)
		os.Exit(1)
	}
	ifIndices, err := openOrCreateIfindicesMap(*bpffsDir)
	if err != nil {
		logger.Error("Could not open or create ifindices map",
			logKeyError, err,
		)
		os.Exit(1)
	}
	ifMacs, err := openOrCreateIfmacsMap(*bpffsDir)
	if err != nil {
		logger.Error("Could not open or create ifindices map",
			logKeyError, err,
		)
		os.Exit(1)
	}

	logger.Info("Starting plugin server",
		logKeyListenPath, *unixSocketPath,
		logKeyNamespace, *namespace,
		logKeyBPFFS, *bpffsDir,
		logKeyNetkitEnabled, *netkitEnabled,
	)
	os.Remove(*unixSocketPath)
	err = runServer(logger, ifIndices, ifMacs, *unixSocketPath, *namespace, *netkitEnabled)
	logger.Error("Plugin server stopped",
		logKeyError, err,
	)

	if err != nil {
		os.Exit(1)
	}
}

func openOrCreateIfindicesMap(pinsDir string) (*ebpf.Map, error) {
	var spec hostSpecs

	rawSpec, err := loadHost()
	if err != nil {
		return nil, fmt.Errorf("loading host spec: %w", err)
	}

	if err := rawSpec.Assign(&spec); err != nil {
		return nil, fmt.Errorf("assigning host spec: %w", err)
	}

	return ebpf.NewMapWithOptions(spec.Ifindices, ebpf.MapOptions{
		PinPath: pinsDir,
	})
}

func openOrCreateIfmacsMap(pinsDir string) (*ebpf.Map, error) {
	var spec hostSpecs

	rawSpec, err := loadHost()
	if err != nil {
		return nil, fmt.Errorf("loading host spec: %w", err)
	}

	if err := rawSpec.Assign(&spec); err != nil {
		return nil, fmt.Errorf("assigning host spec: %w", err)
	}

	return ebpf.NewMapWithOptions(spec.Ifmacs, ebpf.MapOptions{
		PinPath: pinsDir,
	})
}

func runServer(logger *slog.Logger, ifIndices *ebpf.Map, ifMacs *ebpf.Map, sockPath, namespace string, netkitEnabled bool) error {
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return fmt.Errorf("resolving address: %w", err)
	}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("starting listener: %w", err)
	}

	dps, err := newDatapathPluginServer(logger, ifIndices, ifMacs, namespace, netkitEnabled)
	if err != nil {
		return fmt.Errorf("creating server: %w", err)
	}

	server := grpc.NewServer()
	datapathplugins.RegisterDatapathPluginServer(server, dps)

	return server.Serve(listener)
}

type datapathPluginServer struct {
	logger        *slog.Logger
	ifIndices     *ebpf.Map
	ifMacs        *ebpf.Map
	namespace     string
	netkitEnabled bool
}

func newDatapathPluginServer(logger *slog.Logger, ifIndices *ebpf.Map, ifMacs *ebpf.Map, namespace string, netkitEnabled bool) (*datapathPluginServer, error) {
	s := &datapathPluginServer{
		logger:        logger,
		ifIndices:     ifIndices,
		ifMacs:        ifMacs,
		namespace:     namespace,
		netkitEnabled: netkitEnabled,
	}

	return s, nil
}

func (s *datapathPluginServer) PrepareCollection(ctx context.Context, req *datapathplugins.PrepareCollectionRequest) (resp *datapathplugins.PrepareCollectionResponse, _ error) {
	var hooks []*datapathplugins.PrepareCollectionResponse_HookSpec

	switch attachmentCtx := req.AttachmentContext.Context.(type) {
	case *datapathplugins.AttachmentContext_Host_:
		hooks = []*datapathplugins.PrepareCollectionResponse_HookSpec{
			{
				Type:   datapathplugins.HookType_PRE,
				Target: fromNetdev,
			},
		}
	case *datapathplugins.AttachmentContext_Lxc:
		if attachmentCtx.Lxc.GetPodInfo().GetNamespace() == s.namespace {
			if strings.HasPrefix(attachmentCtx.Lxc.GetPodInfo().GetName(), proxyPodNamePrefix) ||
				strings.HasPrefix(attachmentCtx.Lxc.GetPodInfo().GetName(), workloadPodNamePrefix) {
				hooks = []*datapathplugins.PrepareCollectionResponse_HookSpec{
					{
						Type:   datapathplugins.HookType_PRE,
						Target: fromContainer,
					},
				}
			}
		}
	}

	id := uuid.New().String()
	resp = &datapathplugins.PrepareCollectionResponse{
		Hooks:  hooks,
		Cookie: id,
	}

	s.logger.Info("PrepareCollection()",
		logKeyCiliumVersion, ciliumVersion(ctx),
		logKeyTraceId, id,
		logKeyRequest, req,
		logKeyResponse, resp,
	)

	return resp, nil
}

func (s *datapathPluginServer) InstrumentCollection(ctx context.Context, req *datapathplugins.InstrumentCollectionRequest) (resp *datapathplugins.InstrumentCollectionResponse, err error) {
	logger := s.logger.With(logKeyTraceId, req.GetCookie())

	defer func() {
		if err != nil {
			logger.Error("InstrumentCollection()",
				logKeyCiliumVersion, ciliumVersion(ctx),
				logKeyRequest, req,
				logKeyError, err,
			)
		} else {
			logger.Info("InstrumentCollection()",
				logKeyCiliumVersion, ciliumVersion(ctx),
				logKeyRequest, req,
			)
		}
	}()

	opts := ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			ifindicesMap: s.ifIndices,
			ifMacsMap:    s.ifMacs,
		},
	}

	switch attachmentCtx := req.AttachmentContext.Context.(type) {
	case *datapathplugins.AttachmentContext_Host_:
		if len(req.GetHooks()) != 1 {
			return nil, fmt.Errorf("expected 1 hook, found %d", len(req.GetHooks()))
		}

		hook := req.GetHooks()[0]

		if hook.GetTarget() != fromNetdev {
			return nil, fmt.Errorf("expected target to be %s, got %s", fromNetdev, hook.GetTarget())
		}

		targetProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(hook.GetAttachTarget().GetProgramId()))
		if err != nil {
			return nil, fmt.Errorf("loading target program %d: %w", hook.GetAttachTarget().GetProgramId(), err)
		}
		defer targetProg.Close()

		spec, err := loadHost()
		if err != nil {
			return nil, fmt.Errorf("loading host spec: %w", err)
		}

		progSpec := spec.Programs[beforeFromNetdev]
		progSpec.AttachTarget = targetProg
		progSpec.AttachTo = hook.GetAttachTarget().GetSubprogName()

		coll, err := ebpf.NewCollectionWithOptions(spec, opts)
		if err != nil {
			return nil, fmt.Errorf("loading host objects: %w", err)
		}
		defer coll.Close()

		if err := coll.Programs[beforeFromNetdev].Pin(hook.GetPinPath()); err != nil {
			return nil, fmt.Errorf("pinning %s to %s: %w", beforeFromNetdev, hook.GetPinPath(), err)
		}
	case *datapathplugins.AttachmentContext_Lxc:
		if len(req.GetHooks()) != 1 {
			return nil, fmt.Errorf("expected 1 hook, found %d", len(req.GetHooks()))
		}

		hook := req.GetHooks()[0]

		if hook.GetTarget() != fromContainer {
			return nil, fmt.Errorf("expected target to be %s, got %s", fromContainer, hook.GetTarget())
		}

		if attachmentCtx.Lxc.GetPodInfo().GetNamespace() != s.namespace {
			return nil, fmt.Errorf("expected namespace to be %s, got %s", s.namespace, attachmentCtx.Lxc.GetPodInfo().GetNamespace())
		}

		targetProg, err := ebpf.NewProgramFromID(ebpf.ProgramID(hook.GetAttachTarget().GetProgramId()))
		if err != nil {
			return nil, fmt.Errorf("loading target program %d: %w", hook.GetAttachTarget().GetProgramId(), err)
		}
		defer targetProg.Close()

		var iface uint32 = ifaceUnknown
		var ifacePeer uint32 = ifaceUnknown
		var spec *ebpf.CollectionSpec

		if strings.HasPrefix(attachmentCtx.Lxc.GetPodInfo().GetName(), proxyPodNamePrefix) {
			spec, err = loadProxy()
			if err != nil {
				return nil, fmt.Errorf("loading proxy spec: %w", err)
			}

			iface = ifaceProxy
			ifacePeer = ifaceProxyPeer
		} else if strings.HasPrefix(attachmentCtx.Lxc.GetPodInfo().GetName(), workloadPodNamePrefix) {
			spec, err = loadWorkload()
			if err != nil {
				return nil, fmt.Errorf("loading workload spec: %w", err)
			}

			iface = ifaceWorkload
			ifacePeer = ifaceWorkloadPeer
		}

		if spec == nil {
			return nil, fmt.Errorf("unexpected pod %s", attachmentCtx.Lxc.GetPodInfo().GetName())
		}

		progSpec := spec.Programs[beforeFromContainer]
		progSpec.AttachTarget = targetProg
		progSpec.AttachTo = hook.GetAttachTarget().GetSubprogName()

		coll, err := ebpf.NewCollectionWithOptions(spec, opts)
		if err != nil {
			return nil, fmt.Errorf("loading lxc objects: %w", err)
		}
		defer coll.Close()

		if err := coll.Programs[beforeFromContainer].Pin(hook.GetPinPath()); err != nil {
			return nil, fmt.Errorf("pinning %s to %s: %w", beforeFromContainer, hook.GetPinPath(), err)
		}

		var peerMAC net.HardwareAddr
		if attachmentCtx.Lxc.GetIface().PeerMac != "" {
			mac, err := net.ParseMAC(attachmentCtx.Lxc.GetIface().PeerMac)
			if err != nil {
				s.logger.Warn("Couldn't parse parsing peer mac %s: %w", attachmentCtx.Lxc.GetIface().PeerMac, err)
			}
			peerMAC = mac
		} else {
			var zero [6]byte
			peerMAC = zero[:]
		}

		if err := updateIfinfo(s.ifIndices, s.ifMacs, iface, ifacePeer, attachmentCtx.Lxc.GetIface().GetName(), peerMAC); err != nil {
			return nil, fmt.Errorf("updating iface info for %s: %w", attachmentCtx.Lxc.GetIface().GetName(), err)
		}

		if v, ok := coll.Variables[netkitEnabled]; ok {
			if err := v.Set(s.netkitEnabled); err != nil {
				return nil, fmt.Errorf("setting netkit_enabled: %w", err)
			}
		}
	}

	return &datapathplugins.InstrumentCollectionResponse{}, nil
}

func ciliumVersion(ctx context.Context) string {
	version := "unknown"

	md, ok := metadata.FromIncomingContext(ctx)
	if ok {
		versionMd := md.Get(ciliumVersionMetadataKey)
		if len(versionMd) == 1 {
			version = versionMd[0]
		}
	}

	return version
}

func updateIfinfo(ifIndices *ebpf.Map, ifMacs *ebpf.Map, slot uint32, slotPeer uint32, linkName string, linkPeerAddr net.HardwareAddr) error {
	link, err := netlink.LinkByName(linkName)
	if err != nil {
		return fmt.Errorf("looking up link %s: %w", linkName, err)
	}

	if err := ifIndices.Put(slot, uint32(link.Attrs().Index)); err != nil {
		return fmt.Errorf("putting %d into slot %d: %w", link.Attrs().Index, slot)
	}

	var addr hostMacaddr
	copy(addr.Addr[:], link.Attrs().HardwareAddr)
	if err := ifMacs.Put(slot, &addr); err != nil {
		return fmt.Errorf("putting %s into slot %d: %w", link.Attrs().HardwareAddr.String(), slot)
	}

	copy(addr.Addr[:], linkPeerAddr)
	if err := ifMacs.Put(slotPeer, &addr); err != nil {
		return fmt.Errorf("putting %s into peer slot %d: %w", linkPeerAddr.String(), slotPeer)
	}

	return nil
}
