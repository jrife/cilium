// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockets

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
)

const (
	bpfSockTerm = "bpf_sock_term.o"
)

type netlinkDestroyer struct{}

func (d netlinkDestroyer) Destroy(filter SocketFilter) (func() error, func() error, error) {
	return func() error {
		return DestroyNetlink(filter)
	}, func() error { return nil }, nil
}

type bpfDestroyer struct{}

func (d bpfDestroyer) Destroy(filter SocketFilter) (func() error, func() error, error) {
	return DestroyBPF(filter)
}

func TestSocketDestroyers(t *testing.T) {
	testutils.PrivilegedTest(t)

	origPath := loader.BPFSockTermPath
	loader.BPFSockTermPath = findInPath(t, bpfSockTerm)
	t.Cleanup(func() {
		loader.BPFSockTermPath = origPath
	})
	socketDestroyers := map[string]SocketDestroyer{
		"netlink": &netlinkDestroyer{},
		"bpf":     &bpfDestroyer{},
	}
	servers := map[string]string{
		"127.0.0.1:8888": "udp",
		"[::1]:8888":     "udp6",
		"127.0.0.1:8889": "udp",
		"[::1]:8889":     "udp6",
	}
	testCases := map[string]struct {
		filter      SocketFilter
		expectClose []string
	}{
		"close 127.0.0.1:8888": {
			filter: SocketFilter{
				DestIp:   net.IPv4(127, 0, 0, 1),
				DestPort: 8888,
				Family:   unix.AF_INET,
				Protocol: unix.IPPROTO_UDP,
			},
			expectClose: []string{
				"127.0.0.1:8888",
			},
		},
		"close [::1]:8888": {
			filter: SocketFilter{
				DestIp:   net.IPv6loopback,
				DestPort: 8888,
				Family:   unix.AF_INET6,
				Protocol: unix.IPPROTO_UDP,
			},
			expectClose: []string{
				"[::1]:8888",
			},
		},
	}

	for dName, d := range socketDestroyers {
		t.Run(dName, func(t *testing.T) {
			for name, tc := range testCases {
				t.Run(name, func(t *testing.T) {
					ns := netns.NewNetNS(t)
					defer ns.Close()

					if err := ns.Do(func() error {
						conns := make(map[string]net.Conn)

						link, err := netlink.LinkByName("lo")
						if err != nil {
							return fmt.Errorf("looking up lo: %w", err)
						}

						if err := netlink.LinkSetUp(link); err != nil {
							return fmt.Errorf("bringing up lo: %w", err)
						}

						for addr, network := range servers {
							server, err := startServer(t, network, addr)
							if err != nil {
								return fmt.Errorf("starting server (%s): %w", addr, err)
							}

							defer server.Close()

							conn, err := net.Dial(network, addr)
							if err != nil {
								return fmt.Errorf("connecting: %w", err)
							}

							defer conn.Close()

							conns[addr] = conn
						}

						do, done, err := d.Destroy(tc.filter)
						if err != nil {
							return fmt.Errorf("expected d.Destroy() to succeed, returned %w", err)
						}

						defer done()

						if err := do(); err != nil {
							return fmt.Errorf("doing destroy: %w", err)
						}

						closed := make(map[string]bool)
						for addr, conn := range conns {
							var b [8]byte
							_, err := conn.Write(b[:])
							if err != nil {
								closed[addr] = true
								delete(conns, addr)
							}
						}

						if len(tc.expectClose) != len(closed) {
							return fmt.Errorf("expected %d closed sockets, got %d", len(tc.expectClose), len(closed))
						}

						for _, addr := range tc.expectClose {
							if closed[addr] {
								continue
							}

							return fmt.Errorf("expected %s to be closed", addr)
						}

						return nil
					}); err != nil {
						t.Fatalf("in do: %v", err)
					}
				})
			}
		})
	}
}

func findInPath(t *testing.T, file string) string {
	t.Helper()

	// This logic adapted from os/exec.LookPath except for the parts that
	// check if the file is executable.
	path := os.Getenv("PATH")
	for _, dir := range filepath.SplitList(path) {
		if dir == "" {
			// Unix shell semantics: path element "" means "."
			dir = "."
		}
		path := filepath.Join(dir, file)
		d, err := os.Stat(path)
		if err != nil {
			continue
		}
		m := d.Mode()
		if m.IsDir() {
			continue
		}

		return path
	}

	t.Fatalf("%s not found", file)

	return ""
}

func startServer(t *testing.T, network string, addr string) (net.Conn, error) {
	udpAddr, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, fmt.Errorf("resolving address (%s): %w", network, err)
	}

	conn, err := net.ListenUDP(network, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("starting server: %w", err)
	}

	return conn, nil
}

func TestSocketReqSerialize(t *testing.T) {
	testCases := []struct {
		name     string
		req      SocketRequest
		expected []byte
	}{
		{
			name: "nil addresses",
			req: SocketRequest{
				Family:   2,
				Protocol: 6,
				Ext:      0,
				pad:      0,
				States:   4095,
				ID: netlink.SocketID{
					SourcePort:      0,
					DestinationPort: 0,
					Source:          nil,
					Destination:     nil,
					Interface:       0,
					Cookie:          [2]uint32{0, 0},
				},
			},
			expected: []byte{2, 6, 0, 0, 255, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name: "non-nil addresses",
			req: SocketRequest{
				Family:   2,
				Protocol: 6,
				Ext:      0,
				pad:      0,
				States:   4095,
				ID: netlink.SocketID{
					SourcePort:      59212,
					DestinationPort: 30000,
					Source:          net.ParseIP("127.0.0.1"),
					Destination:     net.ParseIP("127.0.0.1"),
					Interface:       0,
					Cookie:          [2]uint32{4144, 0},
				},
			},
			expected: []byte{2, 6, 0, 0, 255, 15, 0, 0, 231, 76, 117, 48, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 16, 0, 0, 0, 0, 0, 0},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.req.Serialize())
		})
	}
}

func TestSocketDeserialize(t *testing.T) {
	testCases := []struct {
		name     string
		buf      []byte
		expected Socket
	}{
		{
			name: "default route addresses",
			buf:  []byte{2, 7, 0, 0, 170, 213, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 0, 0, 0, 89, 101, 0, 0, 5, 0, 8, 0, 0, 0, 0, 0, 8, 0, 15, 0, 0, 0, 0, 0, 12, 0, 21, 0, 157, 14, 0, 0, 0, 0, 0, 0, 6, 0, 22, 0, 80, 0, 0, 0},
			expected: Socket{
				Family:  2,
				State:   7,
				Timer:   0,
				Retrans: 0,
				ID: netlink.SocketID{
					SourcePort:      43733,
					DestinationPort: 0,
					Source:          net.ParseIP("0.0.0.0"),
					Destination:     net.ParseIP("0.0.0.0"),
					Interface:       0,
					Cookie:          [2]uint32{8201, 0},
				},
				Expires: 0,
				RQueue:  0,
				WQueue:  0,
				UID:     108,
				INode:   25945,
			},
		},
		{
			name: "non default route addresses",
			buf:  []byte{2, 1, 0, 0, 189, 137, 1, 187, 192, 168, 50, 194, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 99, 52, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 3, 0, 0, 146, 138, 10, 0, 5, 0, 8, 0, 0, 0, 0, 0, 8, 0, 15, 0, 0, 0, 0, 0, 12, 0, 21, 0, 1, 42, 0, 0, 0, 0, 0, 0, 6, 0, 22, 0, 80, 0, 0, 0},
			expected: Socket{
				Family:  2,
				State:   1,
				Timer:   0,
				Retrans: 0,
				ID: netlink.SocketID{
					SourcePort:      48521,
					DestinationPort: 443,
					Source:          net.ParseIP("192.168.50.194"),
					Destination:     net.ParseIP("151.99.52.13"),
					Interface:       0,
					Cookie:          [2]uint32{8211, 0},
				},
				Expires: 0,
				RQueue:  0,
				WQueue:  0,
				UID:     1000,
				INode:   690834,
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var sock Socket
			err := sock.Deserialize(tc.buf)
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, sock)
		})
	}
}

func BenchmarkSocketReqSerialize(b *testing.B) {
	requests := [...]SocketRequest{
		{
			Family:   2,
			Protocol: 6,
			Ext:      0,
			pad:      0,
			States:   4095,
			ID: netlink.SocketID{
				SourcePort:      0,
				DestinationPort: 0,
				Source:          nil,
				Destination:     nil,
				Interface:       0,
				Cookie:          [2]uint32{0, 0},
			},
		},
		{
			Family:   2,
			Protocol: 6,
			Ext:      0,
			pad:      0,
			States:   4095,
			ID: netlink.SocketID{
				SourcePort:      59212,
				DestinationPort: 30000,
				Source:          net.ParseIP("127.0.0.1"),
				Destination:     net.ParseIP("127.0.0.1"),
				Interface:       0,
				Cookie:          [2]uint32{4144, 0},
			},
		},
	}

	for i := 0; i < b.N; i++ {
		for _, req := range requests {
			req.Serialize()
		}
	}
}

func BenchmarkSocketDeserialize(b *testing.B) {
	buffers := [...][]byte{
		{2, 7, 0, 0, 170, 213, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 9, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 108, 0, 0, 0, 89, 101, 0, 0, 5, 0, 8, 0, 0, 0, 0, 0, 8, 0, 15, 0, 0, 0, 0, 0, 12, 0, 21, 0, 157, 14, 0, 0, 0, 0, 0, 0, 6, 0, 22, 0, 80, 0, 0, 0},
		{2, 1, 0, 0, 189, 137, 1, 187, 192, 168, 50, 194, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 151, 99, 52, 13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 19, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 232, 3, 0, 0, 146, 138, 10, 0, 5, 0, 8, 0, 0, 0, 0, 0, 8, 0, 15, 0, 0, 0, 0, 0, 12, 0, 21, 0, 1, 42, 0, 0, 0, 0, 0, 0, 6, 0, 22, 0, 80, 0, 0, 0},
	}

	for i := 0; i < b.N; i++ {
		for _, buf := range buffers {
			var sock Socket
			sock.Deserialize(buf)
		}
	}
}
