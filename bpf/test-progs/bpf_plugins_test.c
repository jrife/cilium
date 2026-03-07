// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

int i = 0;

int a_seq;

__section_entry
int program_a(struct __ctx_buff *ctx __maybe_unused)
{
	a_seq = i++;
	return 0;
}

int b_seq;

__section_entry
int program_b(struct __ctx_buff *ctx __maybe_unused)
{
	b_seq = i++;
	return 0;
}

BPF_LICENSE("Dual BSD/GPL");
