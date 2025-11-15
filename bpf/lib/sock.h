/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include "ipv6_core.h"
#include "map_defs.h"

static __always_inline __maybe_unused
__sock_cookie sock_local_cookie(struct bpf_sock_addr *ctx)
{
#ifdef TEST_BPF_SOCK
	/* Some BPF tests run bpf_sock.c code in XDP context.
	 * Allow them to pass the verifier.
	 */
	return ctx->protocol == IPPROTO_TCP ? get_prandom_u32() : 0;
#else
	return get_socket_cookie(ctx);
#endif
}

struct ipv4_sk_meta {
	__be32 orig_address;
	__be16 orig_port;
	__u16 rev_nat_index;
	__be32 backend_address;
	__be32 backend_port;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, int);
	__type(value, struct ipv4_sk_meta);
} cilium_lb4_sk_meta __section_maps_btf;

struct ipv6_sk_meta {
	union v6addr orig_address;
	__be16 orig_port;
	__u16 rev_nat_index;
	union v6addr backend_address;
	__be32 backend_port;
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__type(key, int);
	__type(value, struct ipv6_sk_meta);
} cilium_lb6_sk_meta __section_maps_btf;


