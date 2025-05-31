// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package demo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path"
	"path/filepath"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/logging/logfields"

	"github.com/cilium/ebpf"

	"google.golang.org/grpc"
)

func StartDemoServer(logger *slog.Logger) (string, error) {
	logger.Info("Starting demo datapath plugin")

	server := grpc.NewServer()
	dir, err := os.MkdirTemp("", "demo-datapath-plugin")
	if err != nil {
		return "", fmt.Errorf("making temp dir: %w", err)
	}

	sockPath := path.Join(dir, "plugin.sock")
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return "", fmt.Errorf("resolving address: %w", err)
	}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return "", fmt.Errorf("starting listener: %w", err)
	}

	dps, err := newDatapathPluginServer(logger, filepath.Join(bpf.CiliumPath(), "demo-datapath-plugin"))
	if err != nil {
		return "", fmt.Errorf("creating server: %w", err)
	}

	datapathplugins.RegisterDatapathPluginServer(server, dps)

	go func() {
		err := server.Serve(listener)
		logger.Error("Demo datapath server stopped",
			logfields.Error, err,
		)
	}()

	return "unix://" + sockPath, nil
}

type datapathPluginServer struct {
	logger *slog.Logger
	pinDir string
}

func newDatapathPluginServer(logger *slog.Logger, pinDir string) (*datapathPluginServer, error) {
	s := &datapathPluginServer{
		logger: logger,
		pinDir: pinDir,
	}

	if err := s.ensurePinDirs(); err != nil {
		return nil, fmt.Errorf("ensuring pin dirs: %w", err)
	}

	return s, nil
}

func (s *datapathPluginServer) LoadSKBProgram(ctx context.Context, req *datapathplugins.LoadSKBProgramRequest) (*datapathplugins.LoadSKBProgramResponse, error) {
	s.logger.Info("LoadSKBProgram()", logfields.Request, req)

	var dir uint32
	switch req.AttachmentPoint.Direction {
	case datapathplugins.Direction_INGRESS:
		dir = 0
	case datapathplugins.Direction_EGRESS:
		dir = 1
	default:
		return nil, fmt.Errorf("invalid direction: %w", req.AttachmentPoint.Direction)
	}

	var mapReplacements map[string]*ebpf.Map
	switch req.AttachmentPoint.Anchor {
	case datapathplugins.Anchor_BEFORE:
		// Nothing to do
	case datapathplugins.Anchor_AFTER:
		ciliumReturn, err := ebpf.NewMapFromID(ebpf.MapID(req.Maps.CiliumReturnMapId))
		if err != nil {
			return nil, fmt.Errorf("loading cilium_return map: %w", err)
		}
		defer ciliumReturn.Close()

		mapReplacements = map[string]*ebpf.Map{
			"cilium_return": ciliumReturn,
		}
	default:
		return nil, fmt.Errorf("invalid anchor: %w", req.AttachmentPoint.Anchor)
	}

	demoSpec, err := loadDemo()
	if err != nil {
		return nil, fmt.Errorf("loading demo spec: %w", err)
	}

	var objs demoObjects
	coll, err := ebpf.NewCollectionWithOptions(demoSpec, ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: s.GlobalsPinDir(),
		},
		MapReplacements: mapReplacements,
	})
	if err != nil {
		return nil, fmt.Errorf("loading collection: %w", err)
	}
	defer coll.Close()

	if err := coll.Assign(&objs); err != nil {
		return nil, fmt.Errorf("assigning objects: %w", err)
	}

	if err := objs.demoVariables.Direction.Set(dir); err != nil {
		return nil, fmt.Errorf("configuring direction: %w", err)
	}

	if err := objs.demoVariables.EndpointId.Set(req.EndpointConfig.Id); err != nil {
		return nil, fmt.Errorf("configuring endpoint id: %w", err)
	}

	var prog *ebpf.Program

	switch req.DeviceType {
	case datapathplugins.DeviceType_CILIUM_HOST:
		switch req.AttachmentPoint.Anchor {
		case datapathplugins.Anchor_BEFORE:
			prog = objs.demoPrograms.BeforeCiliumHost
		case datapathplugins.Anchor_AFTER:
			prog = objs.demoPrograms.AfterCiliumHost
		}
	case datapathplugins.DeviceType_LXC:
		switch req.AttachmentPoint.Anchor {
		case datapathplugins.Anchor_BEFORE:
			prog = objs.demoPrograms.BeforeCiliumLxc
		case datapathplugins.Anchor_AFTER:
			prog = objs.demoPrograms.AfterCiliumLxc
		}
	}

	if prog == nil {
		return &datapathplugins.LoadSKBProgramResponse{}, nil
	}

	pinPath := s.ProgramPinPath(req.AttachmentPoint)
	if err := os.Remove(pinPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("unpinning program from %s: %w", pinPath, err)
	}
	if err := prog.Pin(pinPath); err != nil {
		return nil, fmt.Errorf("pinning program to %s: %w", pinPath, err)
	}

	return &datapathplugins.LoadSKBProgramResponse{
		ProgramPinPath: pinPath,
	}, nil
}

func (s *datapathPluginServer) GlobalsPinDir() string {
	return filepath.Join(s.pinDir, "globals")
}

func (s *datapathPluginServer) ProgramsPinDir() string {
	return filepath.Join(s.pinDir, "programs")
}

func (s *datapathPluginServer) ensurePinDirs() error {
	if err := bpf.MkdirBPF(s.GlobalsPinDir()); err != nil {
		return fmt.Errorf("ensuring pin dir %s: %w", s.GlobalsPinDir(), err)
	}

	if err := bpf.MkdirBPF(s.ProgramsPinDir()); err != nil {
		return fmt.Errorf("ensuring pin dir %s: %w", s.ProgramsPinDir(), err)
	}

	return nil
}

func (s *datapathPluginServer) ProgramPinPath(ap *datapathplugins.AttachmentPoint) string {
	return filepath.Join(s.ProgramsPinDir(), fmt.Sprintf("%s-%s-%s", ap.DeviceName, ap.Direction.String(), ap.Anchor.String()))
}
