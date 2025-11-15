// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <bpf/ctx/skb.h>
#include "bpf/builtins.h"
#include "common.h"
#include "bpf/compiler.h"
#include "bpf/types_mapper.h"
#include "bpf/helpers_sock.h"
#include "lib/sock.h"
#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#define COOKIE 42
#define bpf_sock_destroy   mock_bpf_sock_destroy
#define seq_write	   mock_bpf_seq_write
#define get_socket_cookie  mock_get_socket_cookie
#define sk_storage_get	   mock_sk_storage_get

struct sock_common;
struct seq_file;
struct sock;

static int destroys;

static __always_inline int
mock_bpf_sock_destroy(struct sock_common *sk __maybe_unused)
{
	destroys++;

	return 0;
}

static char write_data[sizeof(__sock_cookie)];
static __u32 write_len;

static __always_inline int
mock_bpf_seq_write(struct seq_file *m __maybe_unused, const void *data, __u32 len)
{
	write_len = len;

	if (len > sizeof(__sock_cookie))
		return 0;

	memcpy(write_data, data, len);

	return 0;
}

static __always_inline __sock_cookie mock_get_socket_cookie(void *ctx __maybe_unused)
{
	return COOKIE;
}

struct {
	union {
		struct ipv4_sk_meta v4;
		struct ipv6_sk_meta v6;
	} value;
	bool empty;
} sk_storage;

static __always_inline void *
mock_sk_storage_get(void *map __maybe_unused,
		    struct bpf_sock *sk __maybe_unused,
		    void *value __maybe_unused, __u64 flags __maybe_unused)
{
	return sk_storage.empty ? NULL : &sk_storage.value;
}

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1

#include "lib/socket.h"

#include "bpf_sock_term.c"

const __be32 no_match_addr4 = 0xBEEFDEAD;
const union v6addr no_match_addr6 = { .d1 = 0x2, .d2 = 0x1 };
const __be32 match_addr4 = 0xDEADBEEF;
const union v6addr match_addr6 = { .d1 = 0x1, .d2 = 0x2 };
const __u16 match_port = 8080;

static __always_inline void set_ipv4_sk_meta(struct ipv4_sk_meta *meta)
{
	memcpy(&sk_storage.value.v4, meta, sizeof(*meta));
	sk_storage.empty = false;
}

static __always_inline void set_ipv6_sk_meta(struct ipv6_sk_meta *meta)
{
	memcpy(&sk_storage.value.v6, meta, sizeof(*meta));
	sk_storage.empty = false;
}

static __always_inline void set_filter(struct sock_term_filter *filter)
{
	memcpy(&cilium_sock_term_filter, filter, sizeof(*filter));
}

static __always_inline void reset(void)
{
	destroys = 0;
	memset(write_data, 0, sizeof(__sock_cookie));
	write_len = 0;
	sk_storage.empty = true;
}

CHECK("xdp", "sock_terminate")
int test_sock_terminate(__maybe_unused struct xdp_md *ctx)
{
	struct sock_term_filter filter4 = {
		.address = {
			.addr4 = match_addr4,
		},
		.address_family = AF_INET,
		.port = match_port,
	};
	struct sock_term_filter filter6 = {
		.address = {
			.addr6 = match_addr6,
		},
		.address_family = AF_INET6,
		.port = match_port,
	};
	struct ipv4_sk_meta no_match_meta4 = {
		.backend_address = no_match_addr4,
		.backend_port = bpf_htons(match_port),
	};
	struct ipv6_sk_meta no_match_meta6 = {
		.backend_address = no_match_addr6,
		.backend_port = bpf_htons(match_port),
	};
	struct ipv4_sk_meta match_meta4 = {
		.backend_address = match_addr4,
		.backend_port = bpf_htons(match_port),
	};
	struct ipv6_sk_meta match_meta6 = {
		.backend_address = match_addr6,
		.backend_port = bpf_htons(match_port),
	};
	struct bpf_iter__udp iter_ctx_udp;
	struct bpf_iter__tcp iter_ctx_tcp;
	struct bpf_iter_meta meta;
	struct seq_file seq;
	int sk;

	iter_ctx_udp.meta = &meta;
	iter_ctx_udp.udp_sk = &sk;
	iter_ctx_tcp.meta = &meta;
	iter_ctx_tcp.tcp_sk = &sk;
	meta.seq = &seq;

	test_init();

	/* IPv4 tests */
	set_filter(&filter4);

	/* UDP */
	
	/* Don't destroy the socket if it has no backend address metadata. */
	reset();
	sock_udp_destroy_v4(&iter_ctx_udp);
	assert(destroys == 0);
	assert(write_len == 0);
	/* Don't destroy the socket if its backend address does not match the
	 * filter.
	 */
	reset();
	set_ipv4_sk_meta(&no_match_meta4);
	sock_udp_destroy_v4(&iter_ctx_udp);
	assert(destroys == 0);
	assert(write_len == 0);
	/* Destroy the socket if its backend address matches the filter. */
	reset();
	set_ipv4_sk_meta(&match_meta4);
	sock_udp_destroy_v4(&iter_ctx_udp);
	assert(destroys == 1);
	assert(write_len == sizeof(__sock_cookie));
	assert(*((__sock_cookie *)write_data) == COOKIE);

	/* TCP */

	/* Don't destroy the socket if it has no backend address metadata. */
	reset();
	sock_tcp_destroy_v4(&iter_ctx_tcp);
	assert(destroys == 0);
	assert(write_len == 0);
	/* Don't destroy the socket if its backend address does not match the
	 * filter.
	 */
	reset();
	set_ipv4_sk_meta(&no_match_meta4);
	sock_tcp_destroy_v4(&iter_ctx_tcp);
	assert(destroys == 0);
	assert(write_len == 0);
	/* Destroy the socket if its backend address matches the filter. */
	reset();
	set_ipv4_sk_meta(&match_meta4);
	sock_tcp_destroy_v4(&iter_ctx_tcp);
	assert(destroys == 1);
	assert(write_len == sizeof(__sock_cookie));
	assert(*((__sock_cookie *)write_data) == COOKIE);

	/* IPv6 tests */
	set_filter(&filter6);

	/* UDP */

	/* Don't destroy the socket if it has no backend address metadata. */
	reset();
	sock_udp_destroy_v6(&iter_ctx_udp);
	assert(destroys == 0);
	assert(write_len == 0);
	/* Don't destroy the socket if its backend address does not match the
	 * filter.
	 */
	reset();
	set_ipv6_sk_meta(&no_match_meta6);
	sock_udp_destroy_v6(&iter_ctx_udp);
	assert(destroys == 0);
	assert(write_len == 0);
	/* Destroy the socket if its backend address matches the filter. */
	reset();
	set_ipv6_sk_meta(&match_meta6);
	sock_udp_destroy_v6(&iter_ctx_udp);
	assert(destroys == 1);
	assert(write_len == sizeof(__sock_cookie));
	assert(*((__sock_cookie *)write_data) == COOKIE);

	/* TCP */

	/* Don't destroy the socket if it has no backend address metadata. */
	reset();
	sock_tcp_destroy_v6(&iter_ctx_tcp);
	assert(destroys == 0);
	assert(write_len == 0);
	/* Don't destroy the socket if its backend address does not match the
	 * filter.
	 */
	reset();
	set_ipv6_sk_meta(&no_match_meta6);
	sock_tcp_destroy_v6(&iter_ctx_tcp);
	assert(destroys == 0);
	assert(write_len == 0);
	/* Destroy the socket if its backend address matches the filter. */
	reset();
	set_ipv6_sk_meta(&match_meta6);
	sock_tcp_destroy_v6(&iter_ctx_tcp);
	assert(destroys == 1);
	assert(write_len == sizeof(__sock_cookie));
	assert(*((__sock_cookie *)write_data) == COOKIE);

	test_finish();
}
