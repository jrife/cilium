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
	"time"

	"github.com/cilium/cilium/api/v1/datapathplugins"

	"google.golang.org/grpc"
)

func main() {
	bpffsPinPath := flag.String("bpffs-pin-path", "", "Parent directory for BPF program and map pins")
	unixSocketPath := flag.String("unix-socket-path", "", "UNIX socket to listen on")
	flag.Parse()

	logger := slog.Default()
	logger.Info("Starting plugin server",
		"listen-path", *unixSocketPath,
		"pin-path", *bpffsPinPath,
	)
	os.Remove(*unixSocketPath)
	err := runServer(logger, *unixSocketPath, *bpffsPinPath)
	logger.Error("Plugin server stopped",
		"error", err,
	)

	if err != nil {
		time.Sleep(2 * time.Minute)

		os.Exit(1)
	}
}

func runServer(logger *slog.Logger, sockPath string, pinDir string) error {

	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return fmt.Errorf("resolving address: %w", err)
	}
	listener, err := net.ListenUnix("unix", addr)
	if err != nil {
		return fmt.Errorf("starting listener: %w", err)
	}

	dps, err := newDatapathPluginServer(logger, pinDir)
	if err != nil {
		return fmt.Errorf("creating server: %w", err)
	}

	server := grpc.NewServer()
	datapathplugins.RegisterDatapathPluginServer(server, dps)

	return server.Serve(listener)
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

	return s, nil
}

func (s *datapathPluginServer) PrepareHooks(ctx context.Context, req *datapathplugins.PrepareHooksRequest) (*datapathplugins.PrepareHooksResponse, error) {
	s.logger.Info("PrepareHooks", "request", req)

	return nil, nil
}

func (s *datapathPluginServer) LoadHooks(ctx context.Context, req *datapathplugins.LoadHooksRequest) (*datapathplugins.LoadHooksResponse, error) {
	s.logger.Info("LoadHooks", "request", req)

	return nil, nil
}
