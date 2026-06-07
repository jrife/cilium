// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go host ./bpf/host.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go proxy ./bpf/proxy.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go workload ./bpf/workload.c
