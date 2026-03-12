// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <linux/bpf.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_helpers.h>

char attachment_context[256];

#define SYS_PROCEED	1

SEC("freplace")
int before(struct bpf_sock_addr *ctx)
{
	bpf_printk("before %s\n", attachment_context);

	return SYS_PROCEED;
}

SEC("freplace")
int after(struct bpf_sock_addr *ctx, int ret)
{
	bpf_printk("after %s (ret=%d)\n", attachment_context, ret);

	return SYS_PROCEED;
}

char _license[] SEC("license") = "GPL";

