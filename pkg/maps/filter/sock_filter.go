// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package filter

import (
	"fmt"
	"net"
	"syscall"

	"github.com/cilium/ebpf"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/byteorder"
	"github.com/cilium/cilium/pkg/types"
)

const (
	// SockFilterMap is the BPF map name.
	SockTermFilterMapName = "cilium_sock_term_filter"

	// SockTermFilterMapSize is the maximum number of entries in the BPF map.
	SockTermFilterMapSize = 1
)

var (
	// SockTermFilter is the socket termination filter BPF map.
	SockTermFilter *SockTermFilterMap

	key = index(0)
)

type index uint32

func (i *index) New() bpf.MapKey {
	return new(index)
}

// String pretty print the config Value.
func (i index) String() string {
	return fmt.Sprintf("%d", i)
}

type SockTermFilterValue struct {
	Address       types.IPv6 `align:"address"`
	Port          uint16     `align:"port"`
	AddressFamily uint8      `align:"address_family"`
	_             uint8
}

func NewSockTermFilterValue(af uint8, addr net.IP, port uint16) *SockTermFilterValue {
	var value SockTermFilterValue
	value.AddressFamily = af
	value.Port = byteorder.NetworkToHost16(port)
	copy(value.Address[:], addr.To16())

	return &value
}

func (v *SockTermFilterValue) New() bpf.MapValue {
	return new(SockTermFilterValue)
}

// String converts the key into a human readable string format.
func (v *SockTermFilterValue) String() string {
	var addr net.IP

	if v.AddressFamily == syscall.AF_INET {
		addr = v.Address.IP().To4()
	} else {
		addr = v.Address.IP()
	}

	return fmt.Sprintf("[%s]:%d, %d", addr, v.Port)
}

type SockTermFilterMap struct {
	*bpf.Map
}

func (m *SockTermFilterMap) Set(af uint8, addr net.IP, port uint16) error {
	return m.Update(&key, NewSockTermFilterValue(af, addr, port))
}

func NewSockTermFilterMap() *SockTermFilterMap {
	return &SockTermFilterMap{
		Map: bpf.NewMap(SockTermFilterMapName,
			ebpf.Array,
			&key,
			&SockTermFilterValue{},
			SockTermFilterMapSize,
			0,
		),
	}
}

// OpenOrCreateSockTermFilterMap opens or creates the socket termination filter
// map.
func OpenOrCreateSockTermFilterMap() error {
	SockTermFilter = NewSockTermFilterMap()
	return SockTermFilter.OpenOrCreate()
}
