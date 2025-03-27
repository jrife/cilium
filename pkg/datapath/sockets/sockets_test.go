// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package sockets

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/loader"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/netns"
	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"

	"golang.org/x/sys/unix"
)

const (
	bpfSockTerm = "bpf_sock_term.o"
)

type SocketDestroyerBuilder func(tb testing.TB, f SocketFilter) SocketDestroyer

func makeNetlinkSocketDestroyer(tb testing.TB, f SocketFilter) SocketDestroyer {
	return &NetlinkSocketDestroyer{Filter: f}
}

func makeBPFSocketDestroyer(pinPath string) SocketDestroyerBuilder {
	return func(tb testing.TB, f SocketFilter) SocketDestroyer {
		prog, err := loader.LoadSockTerm(loader.SockParams{
			IP:       f.DestIp,
			Family:   f.Family,
			Port:     f.DestPort,
			Protocol: f.Protocol,
		}, &ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: pinPath},
		})
		require.NoError(tb, err)
		tb.Cleanup(func() {
			prog.Close()
		})

		return &BPFSocketDestroyer{Prog: prog}
	}
}

func TestSocketDestroyers(t *testing.T) {
	testutils.PrivilegedTest(t)
	pinPath := testutils.TempBPFFS(t)

	sockRevNat4Map := bpf.NewMap(lbmap.SockRevNat4MapName,
		ebpf.LRUHash,
		&lbmap.SockRevNat4Key{},
		&lbmap.SockRevNat4Value{},
		lbmap.MaxSockRevNat4MapEntries,
		0,
	).WithPinPath(filepath.Join(pinPath, lbmap.SockRevNat6MapName))
	require.NoError(t, sockRevNat4Map.OpenOrCreate())
	sockRevNat6Map := bpf.NewMap(lbmap.SockRevNat6MapName,
		ebpf.LRUHash,
		&lbmap.SockRevNat6Key{},
		&lbmap.SockRevNat6Value{},
		lbmap.MaxSockRevNat6MapEntries,
		0,
	).WithPinPath(filepath.Join(pinPath, lbmap.SockRevNat6MapName))
	require.NoError(t, sockRevNat6Map.OpenOrCreate())

	var socketDestroyers = map[string]SocketDestroyerBuilder{
		"netlink": makeNetlinkSocketDestroyer,
		"bpf":     makeBPFSocketDestroyer(pinPath),
	}

	origPath := loader.BPFSockTermPath
	loader.BPFSockTermPath = findInPath(t, bpfSockTerm)
	t.Cleanup(func() {
		loader.BPFSockTermPath = origPath
	})

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
				DestIp:   net.IP{127, 0, 0, 1},
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

	for dName, dCreate := range socketDestroyers {
		t.Run(dName, func(t *testing.T) {
			for name, tc := range testCases {
				t.Run(name, func(t *testing.T) {
					ns := netns.NewNetNS(t)
					defer ns.Close()
					defer sockRevNat4Map.DeleteAll()
					defer sockRevNat6Map.DeleteAll()

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
							udpAddr, err := net.ResolveUDPAddr(network, addr)
							require.NoError(t, err)

							server, err := net.ListenUDP(network, udpAddr)
							require.NoError(t, err)
							defer server.Close()

							conn, err := net.Dial(network, addr)
							if err != nil {
								return fmt.Errorf("connecting: %w", err)
							}

							defer conn.Close()

							rawConn, err := conn.(*net.UDPConn).SyscallConn()
							if err != nil {
								return fmt.Errorf("getting raw conn: %w", err)
							}

							var cookie uint64
							rawConn.Control(func(fd uintptr) {
								cookie, err = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
							})
							if err != nil {
								return fmt.Errorf("getting socket cookie: %w", err)
							}

							var key bpf.MapKey
							var value bpf.MapValue
							var sockRevMap *bpf.Map

							switch network {
							case "udp":
								key = lbmap.NewSockRevNat4Key(cookie, udpAddr.IP, uint16(udpAddr.Port))
								value = &lbmap.SockRevNat4Value{}
								sockRevMap = sockRevNat4Map
							case "udp6":
								key = lbmap.NewSockRevNat6Key(cookie, udpAddr.IP, uint16(udpAddr.Port))
								value = &lbmap.SockRevNat6Value{}
								sockRevMap = sockRevNat6Map
							default:
								t.Fatalf("unknown network: %s", network)
							}
							require.NoError(t, sockRevMap.Update(key, value))
							m := map[string][]string{}
							require.NoError(t, sockRevMap.Dump(m))
							t.Logf("map contains %v", m)

							conns[addr] = conn
						}

						sd := dCreate(t, tc.filter)
						require.NoError(t, sd.Destroy())

						closed := make(map[string]bool)
						for addr, conn := range conns {
							var b [8]byte
							_, err := conn.Write(b[:])
							if err != nil {
								t.Logf("Socket error: %v", err)
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

func findInPath(t testing.TB, file string) string {
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

func startServer(t testing.TB, network string, addr string) (net.Conn, error) {
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

func BenchmarkDestroyers(b *testing.B) {
	pinPath := testutils.TempBPFFS(b)
	sockRevNat4Map := bpf.NewMap(lbmap.SockRevNat4MapName,
		ebpf.LRUHash,
		&lbmap.SockRevNat4Key{},
		&lbmap.SockRevNat4Value{},
		lbmap.MaxSockRevNat4MapEntries,
		0,
	).WithPinPath(pinPath)
	require.NoError(b, sockRevNat4Map.OpenOrCreate())
	sockRevNat6Map := bpf.NewMap(lbmap.SockRevNat6MapName,
		ebpf.LRUHash,
		&lbmap.SockRevNat6Key{},
		&lbmap.SockRevNat6Value{},
		lbmap.MaxSockRevNat6MapEntries,
		0,
	).WithPinPath(pinPath)
	require.NoError(b, sockRevNat6Map.OpenOrCreate())

	var socketDestroyers = map[string]SocketDestroyerBuilder{
		"netlink": makeNetlinkSocketDestroyer,
		"bpf":     makeBPFSocketDestroyer(pinPath),
	}

	origPath := loader.BPFSockTermPath
	loader.BPFSockTermPath = findInPath(b, bpfSockTerm)
	b.Cleanup(func() {
		loader.BPFSockTermPath = origPath
	})

	for name, create := range socketDestroyers {
		b.Run(name, func(b *testing.B) {
			addr := "127.0.0.1:8888"
			server, err := startServer(b, "udp", addr)
			if err != nil {
				b.Fatalf("starting server: %v", err)
			}
			defer server.Close()

			for i := 0; i < b.N; i++ {
				(func() {
					conn, err := net.Dial("udp", addr)
					if err != nil {
						b.Fatalf("connecting: %v", err)
					}
					defer conn.Close()

					sd := create(b, SocketFilter{
						DestIp:   net.IPv4(127, 0, 0, 1),
						DestPort: 8888,
						Family:   unix.AF_INET,
						Protocol: unix.IPPROTO_UDP,
					})
					require.NoError(b, sd.Destroy())
				})()
			}
		})
	}
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
