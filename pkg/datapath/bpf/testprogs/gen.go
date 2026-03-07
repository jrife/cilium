// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package bpf provides Go skeletons containing BPF programs.
package testprogs

//go:generate go tool github.com/cilium/ebpf/cmd/bpf2go Plugins ../../../../bpf/test-progs/bpf_plugins_test.c
