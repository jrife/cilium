// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <lib/common.h>
#include <lib/l4.h>
#include "common.h"

bool netkit_enabled = false;

static __always_inline int redirect_from(struct __ctx_buff *ctx, __u32 ifidx)
{
	if (update_macs(ctx, IFACE_WORKLOAD_PEER, IFACE_WORKLOAD))
		return TC_ACT_UNSPEC;

	if (netkit_enabled) {
		printk("[proxy] [before_cil_from_container] ctx_redirect_peer(%u, BPF_F_EGRESS)\n",
		       ifidx);

		return ctx_redirect_peer(ctx, ifidx, BPF_F_EGRESS);
	} else {
		printk("[proxy] [before_cil_from_container] ctx_redirect(%u, BPF_F_INGRESS)\n",
		       ifidx);

		return ctx_redirect(ctx, ifidx, BPF_F_INGRESS);
	}
}

__section("freplace")
int before_cil_from_container(struct __ctx_buff *ctx)
{
	struct ipv4_ct_tuple tuple;
	__u32 ifidx;

	if (validate_and_load(ctx, &tuple))
		return TC_ACT_UNSPEC;

	if (bpf_ntohs(tuple.sport) != SERVER_LISTEN_PORT &&
	    bpf_ntohs(tuple.dport) != SERVER_LISTEN_PORT)
		return TC_ACT_UNSPEC;

	printk("[proxy] [before_cil_from_container] saddr=%pI4,sport=%d,dport=%d\n",
	       &tuple.saddr, bpf_ntohs(tuple.sport), bpf_ntohs(tuple.dport));

	if (bpf_ntohs(tuple.dport) == CLIENT_BIND_PORT ||
	    bpf_ntohs(tuple.sport) == SERVER_PROXY_BIND_PORT) {
		ifidx = ifindex(IFACE_WORKLOAD);
		if (!ifidx)
			return TC_ACT_UNSPEC;

		if (update_macs(ctx, IFACE_PROXY, IFACE_WORKLOAD_PEER))
			return TC_ACT_UNSPEC;

		printk("[proxy] [before_cil_from_container] ctx_redirect(%u)\n",
		       ifidx);

		return ctx_redirect(ctx, ifidx, 0);
	}

	ifidx = ifindex(IFACE_WORKLOAD);
	if (!ifidx)
		return TC_ACT_UNSPEC;

	return redirect_from(ctx, ifidx);
}

BPF_LICENSE("Dual BSD/GPL");
