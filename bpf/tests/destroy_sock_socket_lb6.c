// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include "common.h"
#include "destroy_sock_socket_lb.h"

ASSIGN_CONFIG(__u8, address_family, AF_INET6)
ASSIGN_CONFIG(__u64, dest_ipv6_1, match_addr6_d1)
ASSIGN_CONFIG(__u64, dest_ipv6_2, match_addr6_d2)
ASSIGN_CONFIG(__u16, dest_port, match_port)

CHECK("xdp", "sock6_terminate")
int test_sock6_terminate(__maybe_unused struct xdp_md *ctx)
{
	struct bpf_iter__udp iter_ctx;
	struct bpf_iter_meta meta;
	struct seq_file seq;
	int sk;

	iter_ctx.meta = &meta;
	iter_ctx.udp_sk = &sk;
	meta.seq = &seq;

	test_init();
	assert(!setup());

	reset(no_match_cookie6);
	cil_sock_udp_destroy(&iter_ctx);
	assert(destroys == 0);
	assert(write_len == 0);

	reset(match_cookie6);
	cil_sock_udp_destroy(&iter_ctx);
	assert(destroys == 1);
	assert(write_len == sizeof(__sock_cookie));
	assert(*((__sock_cookie *)write_data) == match_cookie6);

	test_finish();
}
