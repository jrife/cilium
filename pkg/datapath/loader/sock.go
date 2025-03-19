package loader

import (
	"fmt"
	"net"
	"syscall"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/datapath/config"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/ebpf"
)

var (
	BPFSockTermPath = "/bpf/bpf_sock_term.o"
)

// SockParams are the input to LoadSockTerm. Except for IP, all fields are
// expected to be in host byte order.
type SockParams struct {
	IP       net.IP
	Family   uint8
	Port     uint16
	Protocol uint8
}

type sockTermObjects struct {
	SockUDPDestroy *ebpf.Program `ebpf:"cil_sock_udp_destroy"`
}

// LoadSockTerm configures and loads the cil_sock_udp_destroy program with the
// given params.
func LoadSockTerm(params SockParams) (*ebpf.Program, error) {
	spec, err := bpf.LoadCollectionSpec(BPFSockTermPath)
	if err != nil {
		return nil, fmt.Errorf("load eBPF ELF: %w", err)
	}

	co := config.NewBPFSockTerm()
	co.AddressFamily = params.Family
	co.DestPort = byteorder.HostToNetwork16(params.Port)
	if params.Family == syscall.AF_INET6 {
		if len(params.IP) < 16 {
			return nil, fmt.Errorf("expected IP to be at least 16 bytes, was %d bytes", len(params.IP))
		}
		co.DestIPv61 = sliceToBe64(params.IP[:8])
		co.DestIPv62 = sliceToBe64(params.IP[8:])
	} else {
		if len(params.IP) < 4 {
			return nil, fmt.Errorf("expected IP to be at least 4 bytes, was %d bytes", len(params.IP))
		}
		co.DestIPv4 = sliceToBe32(params.IP)
	}

	// Since we don't compile bpf_sock_term.o at runtime, we need to adjust
	// MaxEntries for both maps to match the sizes defined in bpf_sock.c.
	if m := spec.Maps[lbmap.SockRevNat4MapName]; m == nil {
		return nil, fmt.Errorf("%s map not found in spec", lbmap.SockRevNat4MapName)
	} else {
		m.MaxEntries = uint32(lbmap.MaxSockRevNat4MapEntries)
	}

	if m := spec.Maps[lbmap.SockRevNat6MapName]; m == nil {
		return nil, fmt.Errorf("%s map not found in spec", lbmap.SockRevNat6MapName)
	} else {
		m.MaxEntries = uint32(lbmap.MaxSockRevNat6MapEntries)
	}

	var obj sockTermObjects
	commit, err := bpf.LoadAndAssign(&obj, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
		Constants: co,
	})

	if err != nil {
		return nil, fmt.Errorf("loading program: %w", err)
	}

	if err := commit(); err != nil {
		return nil, fmt.Errorf("committing bpf pins: %w", err)
	}

	return obj.SockUDPDestroy, nil
}
