// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <linux/in.h>

#include "lib/endian.h"
#include "lib/socket.h"

__be32 saddr = 0;
__be32 daddr = 0;

__be32 saddr6[4] = {};
__be32 daddr6[4] = {};

__u16 sport = 0;
__u16 dport = 0;

__u8 family = AF_INET;

__section_entry
int bench_sk_lookup(struct __ctx_buff *ctx __maybe_unused)
{
	struct bpf_sock_tuple tuple = {};
	struct bpf_sock *sk;
	__u32 len;

	if (family == AF_INET) {
		tuple.ipv4.saddr = saddr;
		tuple.ipv4.daddr = daddr;
		tuple.ipv4.sport = bpf_htons(sport);
		tuple.ipv4.dport = bpf_htons(dport);
		len = sizeof(tuple.ipv4);
	} else if (family == AF_INET6) {
		tuple.ipv6.saddr[0] = saddr6[0];
		tuple.ipv6.saddr[1] = saddr6[1];
		tuple.ipv6.saddr[2] = saddr6[2];
		tuple.ipv6.saddr[3] = saddr6[3];
		tuple.ipv6.daddr[0] = daddr6[0];
		tuple.ipv6.daddr[1] = daddr6[1];
		tuple.ipv6.daddr[2] = daddr6[2];
		tuple.ipv6.daddr[3] = daddr6[3];
		tuple.ipv6.sport = bpf_htons(sport);
		tuple.ipv6.dport = bpf_htons(dport);
		len = sizeof(tuple.ipv6);
	} else {
		return CTX_ACT_DROP;
	}

	sk = sk_lookup_udp(ctx, &tuple, len, BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return CTX_ACT_DROP;
	sk_release(sk);

	sk = sk_lookup_udp(ctx, &tuple, len, BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return CTX_ACT_DROP;
	sk_release(sk);

	sk = sk_lookup_udp(ctx, &tuple, len, BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return CTX_ACT_DROP;
	sk_release(sk);

	sk = sk_lookup_udp(ctx, &tuple, len, BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return CTX_ACT_DROP;
	sk_release(sk);

	sk = sk_lookup_udp(ctx, &tuple, len, BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return CTX_ACT_DROP;
	sk_release(sk);

	sk = sk_lookup_udp(ctx, &tuple, len, BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return CTX_ACT_DROP;
	sk_release(sk);

	sk = sk_lookup_udp(ctx, &tuple, len, BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return CTX_ACT_DROP;
	sk_release(sk);

	sk = sk_lookup_udp(ctx, &tuple, len, BPF_F_CURRENT_NETNS, 0);
	if (!sk)
		return CTX_ACT_DROP;
	sk_release(sk);

	return CTX_ACT_OK;
}

