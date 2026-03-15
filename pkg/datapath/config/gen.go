// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

// Node configuration is present in all objects and doesn't have a dedicated
// ELF, so pull it out of bpf_lxc.
//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_lxc.o --kind node --name Node --go-out latest/node_config.go --proto-out latest/node_config.proto --package github.com/cilium/cilium/pkg/datapath/config/latest
//go:generate protoc --plugin=/go/bin/protoc-gen-go --plugin=/go/bin/protoc-gen-go-json -I ./latest --go_out=paths=source_relative:./latest --go-json_out=orig_name=true,paths=source_relative:./latest ./latest/node_config.proto

//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_lxc.o --embed Node --kind object --name BPFLXC --go-out latest/lxc_config.go --proto-out latest/lxc_config.proto --proto-import node_config.proto --package github.com/cilium/cilium/pkg/datapath/config/latest
//go:generate protoc --plugin=/go/bin/protoc-gen-go --plugin=/go/bin/protoc-gen-go-json -I ./latest --go_out=paths=source_relative:./latest --go-json_out=orig_name=true,paths=source_relative:./latest ./latest/lxc_config.proto

//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_xdp.o --embed Node --kind object --name BPFXDP --go-out latest/xdp_config.go --proto-out latest/xdp_config.proto --proto-import node_config.proto --package github.com/cilium/cilium/pkg/datapath/config/latest
//go:generate protoc --plugin=/go/bin/protoc-gen-go --plugin=/go/bin/protoc-gen-go-json -I ./latest --go_out=paths=source_relative:./latest --go-json_out=orig_name=true,paths=source_relative:./latest ./latest/xdp_config.proto

//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_host.o --embed Node --kind object --name BPFHost --go-out latest/host_config.go --proto-out latest/host_config.proto --proto-import node_config.proto --package github.com/cilium/cilium/pkg/datapath/config/latest
//go:generate protoc --plugin=/go/bin/protoc-gen-go --plugin=/go/bin/protoc-gen-go-json -I ./latest --go_out=paths=source_relative:./latest --go-json_out=orig_name=true,paths=source_relative:./latest ./latest/host_config.proto

//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_overlay.o --embed Node --kind object --name BPFOverlay --go-out latest/overlay_config.go --proto-out latest/overlay_config.proto --proto-import node_config.proto --package github.com/cilium/cilium/pkg/datapath/config/latest
//go:generate protoc --plugin=/go/bin/protoc-gen-go --plugin=/go/bin/protoc-gen-go-json -I ./latest --go_out=paths=source_relative:./latest --go-json_out=orig_name=true,paths=source_relative:./latest ./latest/overlay_config.proto

//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_wireguard.o --embed Node --kind object --name BPFWireguard --go-out latest/wireguard_config.go --proto-out latest/wireguard_config.proto --proto-import node_config.proto --package github.com/cilium/cilium/pkg/datapath/config/latest
//go:generate protoc --plugin=/go/bin/protoc-gen-go --plugin=/go/bin/protoc-gen-go-json -I ./latest --go_out=paths=source_relative:./latest --go-json_out=orig_name=true,paths=source_relative:./latest ./latest/wireguard_config.proto

//go:generate go run github.com/cilium/cilium/tools/dpgen config --path ../../../bpf/bpf_sock.o --embed Node --kind object --name BPFSock --go-out latest/sock_config.go --proto-out latest/sock_config.proto --proto-import node_config.proto --package github.com/cilium/cilium/pkg/datapath/config/latest
//go:generate protoc --plugin=/go/bin/protoc-gen-go --plugin=/go/bin/protoc-gen-go-json -I ./latest --go_out=paths=source_relative:./latest --go-json_out=orig_name=true,paths=source_relative:./latest ./latest/sock_config.proto
