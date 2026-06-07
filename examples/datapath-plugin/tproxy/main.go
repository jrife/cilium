// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"syscall"
)

const (
	ciliumVersionMetadataKey = "cilium_version"

	logKeyError                 = "error"
	logKeyListenAddress         = "listenAddress"
	logKeyOriginalLocalAddress  = "originalLocalAddress"
	logKeyOriginalRemoteAddress = "originalRemoteAddress"
	logKeyPeerLocalAddress      = "peerLocalAddress"
	logKeyPeerRemoteAddress     = "peerRemoteAddress"

	proxyListenAddress  = "127.0.0.1:11111"
	clientBindPort      = 31234
	clientProxyBindPort = 54321
	serverProxyBindPort = 45678
)

func main() {
	logger := slog.Default()
	lc := net.ListenConfig{
		Control: func(network string, address string, c syscall.RawConn) error {
			logger.Info("Configure IP_TRANSPARENT")
			var sockOptErr error
			var fn = func(s uintptr) {
				sockOptErr = syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			}
			if err := c.Control(fn); err != nil {
				return fmt.Errorf("calling control: %w", err)
			}
			if sockOptErr != nil {
				logger.Error("sockopt failed", logKeyError, sockOptErr)
				return fmt.Errorf("configuring socket: %w", sockOptErr)
			}

			return nil
		},
	}

	logger.Info("Start tproxy", logKeyListenAddress, proxyListenAddress)

	listener, err := lc.Listen(context.Background(), "tcp", proxyListenAddress)
	if err != nil {
		logger.Error("Failed to create listener",
			logKeyListenAddress, proxyListenAddress,
			logKeyError, err,
		)
		return
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			logger.Error("Failed to accept connection",
				logKeyError, err,
			)
			return
		}

		go proxyConnection(logger, conn)
	}
}

func proxyConnection(logger *slog.Logger, originalConn net.Conn) {
	var conn net.Conn
	var err error

	logger = logger.With(
		logKeyOriginalLocalAddress, originalConn.RemoteAddr().String(),
		logKeyOriginalRemoteAddress, originalConn.LocalAddr().String(),
	)

	defer func() {
		originalConn.Close()
		if conn != nil {
			conn.Close()
		}
	}()

	originalDaddr, originalDportStr, err := net.SplitHostPort(originalConn.RemoteAddr().String())
	if err != nil {
		logger.Error("Failed to parse remote address",
			logKeyError, err,
		)
		return
	}
	originalDport, err := strconv.Atoi(originalDportStr)
	if err != nil {
		logger.Error("Failed to parse remote port",
			logKeyError, err,
		)
		return
	}

	proxyBindPort := clientProxyBindPort
	if originalDport == clientProxyBindPort {
		proxyBindPort = serverProxyBindPort
	}

	dialer := &net.Dialer{
		LocalAddr: &net.TCPAddr{
			IP:   net.ParseIP(originalDaddr),
			Port: proxyBindPort,
		},
		Control: func(network string, address string, c syscall.RawConn) error {
			var sockOptErr error
			var fn = func(s uintptr) {
				sockOptErr = syscall.SetsockoptInt(int(s), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1)
			}
			if err := c.Control(fn); err != nil {
				return fmt.Errorf("calling control: %w", err)
			}
			if sockOptErr != nil {
				return fmt.Errorf("configuring socket: %w", sockOptErr)
			}

			return nil
		},
	}

	originalSaddr := originalConn.LocalAddr()

	logger = logger.With(
		logKeyPeerLocalAddress, dialer.LocalAddr.String(),
		logKeyPeerRemoteAddress, originalSaddr.String(),
	)
	logger.Info("Dialing")

	conn, err = dialer.Dial(originalSaddr.Network(), originalSaddr.String())
	if err != nil {
		logger.Error("Failed to dial", logKeyError, err)
		return
	}

	logger.Info("Start")

	copyErr := make(chan error)
	go func() {
		_, err := io.Copy(originalConn, conn)
		copyErr <- err
	}()
	go func() {
		_, err := io.Copy(conn, originalConn)
		copyErr <- err
	}()
	err = <-copyErr

	logger.Info("Stop", logKeyError, err)
}
