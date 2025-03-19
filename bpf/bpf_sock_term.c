// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#include <node_config.h>
#include <lib/static_data.h>

#include "bpf/compiler.h"
#include "lib/common.h"
#include "lib/sock.h"

DECLARE_CONFIG(__u8, address_family, "IPv4 or IPv6")
DECLARE_CONFIG(__u32, dest_ipv4, "Destination IPv4 address")
DECLARE_CONFIG(__u64, dest_ipv6_1, "Destination IPv6 address - first 64 bits")
DECLARE_CONFIG(__u64, dest_ipv6_2, "Destination IPv6 address - second 64 bits")
DECLARE_CONFIG(__u16, dest_port, "Destination port")

/* Stub out types that would normally be found in vmlinux.h to satisfy BTF type
 * checks
 */
struct seq_file {};
struct bpf_iter_meta {
	struct seq_file *seq;
};
struct bpf_iter__udp {
	struct bpf_iter_meta *meta;
	void *udp_sk;
};
struct sock_common {};

#ifndef TEST_BPF_SOCK_TERM
int bpf_sock_destroy(struct sock_common *sk) __section(".ksyms");
static int BPF_FUNC(seq_write, struct seq_file *m, const void *data,
		    __u32 len);
#endif

static __always_inline
bool matches_v4(__sock_cookie cookie)
{
	struct ipv4_revnat_tuple key = {};

	key.address = CONFIG(dest_ipv4),
	key.port    = CONFIG(dest_port),
	key.cookie  = cookie;

	return map_lookup_elem(&cilium_lb4_reverse_sk, &key) != NULL;
}

static __always_inline
bool matches_v6(__sock_cookie cookie)
{
	struct ipv6_revnat_tuple key = {};

	key.address.d1 = CONFIG(dest_ipv6_1);
	key.address.d2 = CONFIG(dest_ipv6_2);
	key.port       = CONFIG(dest_port);
	key.cookie     = cookie;

	return map_lookup_elem(&cilium_lb6_reverse_sk, &key) != NULL;
}

__section("iter/udp")
int cil_sock_udp_destroy(struct bpf_iter__udp *ctx)
{
	void *sk = ctx->udp_sk;
	bool matches = false;
	__sock_cookie cookie;

	if (!sk)
		return 0;

	cookie = get_socket_cookie(sk);
	switch (CONFIG(address_family)) {
	case AF_INET:
		matches = matches_v4(cookie);
		break;
	case AF_INET6:
		matches = matches_v6(cookie);
		break;
	}

	if (!matches)
		return 0;

	if (!bpf_sock_destroy(sk))
		seq_write(ctx->meta->seq, &cookie, sizeof(cookie));

	return 0;
}

BPF_LICENSE("Dual BSD/GPL");
