// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <lib/common.h>
#include <lib/l4.h>
#include "common.h"

__section("freplace")
int before_cil_from_netdev(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple;
	__u32 proxy_ifindex;

	if (validate_and_load(ctx, &tuple))
		return TC_ACT_UNSPEC;

	if (bpf_ntohs(tuple.sport) != SERVER_LISTEN_PORT &&
	    bpf_ntohs(tuple.dport) != SERVER_LISTEN_PORT)
		return TC_ACT_UNSPEC;

	printk("[host] [before_cil_from_netdev] sport=%d,dport=%d\n",
	       bpf_ntohs(tuple.sport), bpf_ntohs(tuple.dport));

	if (bpf_ntohs(tuple.sport) != CLIENT_PROXY_BIND_PORT &&
	    bpf_ntohs(tuple.dport) != CLIENT_PROXY_BIND_PORT)
		return TC_ACT_UNSPEC;

	proxy_ifindex = ifindex(IFACE_PROXY);
	if (!proxy_ifindex)
		return TC_ACT_UNSPEC;

	printk("[host] [before_cil_from_netdev] ctx_redirect_peer(%u)\n",
	       proxy_ifindex);

	return ctx_redirect_peer(ctx, proxy_ifindex, 0);
}

BPF_LICENSE("Dual BSD/GPL");
