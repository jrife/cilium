// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <bpf/tailcall.h>
#include "lib/exits.h"

# define printk(fmt, ...)					\
		({						\
			const char ____fmt[] = fmt;		\
			trace_printk(____fmt, sizeof(____fmt),	\
				     ##__VA_ARGS__);		\
		})

enum direction {
	ingress,
	egress,
};

__u32 direction;
__u64 endpoint_id;

static __always_inline __maybe_unused
const char *direction_str()
{
	switch (direction) {
	case ingress:
		return "ingress";
	case egress:
		return "egress";
	}

	return "unknown";
}

__section_entry
int before_cilium_host(struct __ctx_buff *ctx __maybe_unused)
{
	printk("before cilium_host %s\n", direction_str());

	return CTX_ACT_UNSPEC;
}

__section_entry
int after_cilium_host(struct __ctx_buff *ctx __maybe_unused)
{
	int ret = get_cilium_return();

	printk("after cilium_host %s (ret = %d)\n", direction_str(), ret);

	return ret;
}

__section_entry
int before_cilium_lxc(struct __ctx_buff *ctx __maybe_unused)
{
	printk("before lxc %llu %s\n", endpoint_id, direction_str());

	return CTX_ACT_UNSPEC;
}

__section_entry
int after_cilium_lxc(struct __ctx_buff *ctx __maybe_unused)
{
	int ret = get_cilium_return();

	printk("after lxc %llu %s (ret = %d)\n", endpoint_id, direction_str(), ret);

	return ret;
}

BPF_LICENSE("Dual BSD/GPL");
