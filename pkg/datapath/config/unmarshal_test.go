// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	"testing"

	config_latest "github.com/cilium/cilium/pkg/datapath/config/latest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type e struct {
	B         int    `protobuf:"varint,1,opt,name=b,json=b,proto3"`
	ValUint8  uint32 `protobuf:"varint,1,opt,name=val_uint8,json=val_uint8,proto3"`
	ValUint16 uint32 `protobuf:"varint,1,opt,name=val_uint16,json=val_uint16,proto3"`
	ValInt8   int32  `protobuf:"varint,1,opt,name=val_int8,json=val_int8,proto3"`
	ValInt16  int32  `protobuf:"varint,1,opt,name=val_int16,json=val_int16,proto3"`
	ValBytes  []byte `protobuf:"bytes,1,opt,name=val_bytes,json=val_bytes,proto3"`
}

func (e *e) SizeOf(fieldName string) int {
	return map[string]int{
		"b":          4,
		"val_uint8":  1,
		"val_uint16": 2,
		"val_int8":   1,
		"val_int16":  2,
		"val_bytes":  8,
	}[fieldName]
}

type s struct {
	A int `protobuf:"varint,1,opt,name=a,json=a,proto3"`
	E e

	ignored bool
}

func (s *s) SizeOf(fieldName string) int {
	sz := s.E.SizeOf(fieldName)
	if sz != 0 {
		return sz
	}

	return map[string]int{
		"a": 4,
	}[fieldName]
}

type compl struct {
	C int `protobuf:"varint,1,opt,name=c,json=c,proto3"`
}

func (c *compl) SizeOf(fieldName string) int {
	return 4
}

type dup struct {
	Foo int `protobuf:"varint,1,opt,name=a,json=a,proto3"`
}

func (d *dup) SizeOf(fieldName string) int {
	return 4
}

func TestStructToMap(t *testing.T) {

	obj := s{
		A: 1,
		E: e{
			B:         2,
			ValUint8:  3,
			ValUint16: 4,
			ValInt8:   5,
			ValInt16:  6,
			ValBytes:  []byte{0, 0, 0, 0, 0, 0, 0, 0},
		},
		ignored: true,
	}
	want := map[string]any{
		"a":          1,
		"b":          2,
		"val_uint8":  uint8(3),
		"val_uint16": uint16(4),
		"val_int8":   int8(5),
		"val_int16":  int16(6),
		"val_bytes":  []byte{0, 0, 0, 0, 0, 0, 0, 0},
	}

	values, err := Map(obj)
	require.Error(t, err)

	values, err = Map(&obj)
	require.NoError(t, err)
	assert.Equal(t, want, values)

	values, err = Map([]any{&obj})
	require.NoError(t, err)
	assert.Equal(t, want, values)

	want["c"] = 3
	values, err = Map([]any{&obj, &compl{3}})
	require.NoError(t, err)
	assert.Equal(t, want, values)

	obj.E.ValBytes = nil
	values, err = Map([]any{&obj, &compl{3}})
	require.NoError(t, err)
	assert.Equal(t, want, values)

	_, err = Map([]any{&obj, &dup{3}})
	require.ErrorIs(t, err, errDuplicateVariable)

	_, err = Map(&s{E: e{ValBytes: []byte{}}})
	require.ErrorContains(t, err, "[]byte: length should be 8 (got 0)")

	_, err = Map(&s{E: e{
		ValUint8: (1 << 8),
	}})
	require.ErrorContains(t, err, "uint32: value does not fit into a uint8")

	_, err = Map(&s{E: e{
		ValBytes:  []byte{0, 0, 0, 0, 0, 0, 0, 0},
		ValUint16: (1 << 16),
	}})
	require.ErrorContains(t, err, "uint32: value does not fit into a uint16")

	_, err = Map(&s{E: e{
		ValBytes: []byte{0, 0, 0, 0, 0, 0, 0, 0},
		ValInt8:  (1 << 8),
	}})
	require.ErrorContains(t, err, "int32: value does not fit into an int8")

	_, err = Map(&s{E: e{
		ValBytes: []byte{0, 0, 0, 0, 0, 0, 0, 0},
		ValInt16: (1 << 16),
	}})
	require.ErrorContains(t, err, "int32: value does not fit into an int16")

	// Make sure nil interface doesn't panic.
	_, err = Map(nil)
	require.Error(t, err)

	// Make sure nil pointer doesn't panic.
	_, err = Map((*s)(nil))
	require.Error(t, err)
}

func TestConfigType(t *testing.T) {
	// sanity check to make sure Map() handles our config types
	_, err := Map(&config_latest.BPFHost{Node: &config_latest.Node{}})
	require.NoError(t, err)
	Map(&config_latest.BPFLXC{Node: &config_latest.Node{}})
	require.NoError(t, err)
	Map(&config_latest.BPFOverlay{Node: &config_latest.Node{}})
	require.NoError(t, err)
	Map(&config_latest.BPFSock{Node: &config_latest.Node{}})
	require.NoError(t, err)
	Map(&config_latest.BPFWireguard{Node: &config_latest.Node{}})
	require.NoError(t, err)
	Map(&config_latest.BPFXDP{Node: &config_latest.Node{}})
	require.NoError(t, err)
}
