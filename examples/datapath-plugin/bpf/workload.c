// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <lib/common.h>
#include <lib/l4.h>
#include "common.h"

union macaddr interface_mac;

__section("freplace")
int before_cil_from_container(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple;
	__u32 proxy_ifindex;

	if (validate_and_load(ctx, &tuple))
		return TC_ACT_UNSPEC;

	if (bpf_ntohs(tuple.sport) != SERVER_LISTEN_PORT &&
	    bpf_ntohs(tuple.dport) != SERVER_LISTEN_PORT)
		return TC_ACT_UNSPEC;

	printk("[workload] [before_cil_from_container] saddr=%pI4,sport=%d,dport=%d\n",
	       &tuple.saddr, bpf_ntohs(tuple.sport), bpf_ntohs(tuple.dport));

	if (bpf_ntohs(tuple.sport) != CLIENT_BIND_PORT &&
	    bpf_ntohs(tuple.dport) != SERVER_PROXY_BIND_PORT)
		return TC_ACT_UNSPEC;

	proxy_ifindex = ifindex(IFACE_PROXY);
	if (!proxy_ifindex)
		return TC_ACT_UNSPEC;

	if (update_macs(ctx, IFACE_WORKLOAD, IFACE_PROXY_PEER))
		return TC_ACT_UNSPEC;

	printk("[workload] [before_cil_from_container] ctx_redirect(%u)\n",
	       proxy_ifindex);

	return ctx_redirect(ctx, proxy_ifindex, 0);
}

BPF_LICENSE("Dual BSD/GPL");

