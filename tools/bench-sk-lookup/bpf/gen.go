// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package bpf provides Go skeletons containing BPF programs.
package bpf

//go:generate go tool github.com/cilium/ebpf/cmd/bpf2go BenchSkLookup ../../../bpf/bpf_bench_sk_lookup.c
