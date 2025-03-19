// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#pragma once

#include "bpf/compiler.h"
#include "bpf/types_mapper.h"
#include <bpf/ctx/unspec.h>
#include <bpf/api.h>

#define TEST_BPF_SOCK_TERM 1

#define bpf_sock_destroy mock_bpf_sock_destroy
#define seq_write mock_bpf_seq_write
#define get_socket_cookie mock_get_socket_cookie

struct sock_common;
struct seq_file;
struct sock;

static int destroys;

static __always_inline
int mock_bpf_sock_destroy(struct sock_common *sk __maybe_unused)
{
        destroys++;

        return 0;
}

static char write_data[sizeof(__sock_cookie)];
static __u32 write_len;

static __always_inline
int mock_bpf_seq_write(struct seq_file *m __maybe_unused,
                       const void *data,
                       __u32 len)
{
        write_len = len;

        if (len > sizeof(__sock_cookie))
                return 0;

        memcpy(write_data, data, len);

        return 0;
}

static __sock_cookie current_cookie;

static __always_inline
int mock_get_socket_cookie(void *ctx __maybe_unused)
{
	return current_cookie;
}

#define ENABLE_IPV4 1
#define ENABLE_IPV6 1
#include "bpf_sock_term.c"

const __sock_cookie no_match_cookie4 = 200;
const __sock_cookie no_match_cookie6 = 201;
const __sock_cookie match_cookie4 = 100;
const __sock_cookie match_cookie6 = 101;
const __be32 match_addr4 = 0xDEADBEEF;
const __u64 match_addr6_d1 = 0x1;
const __u64 match_addr6_d2 = 0x2;
const __u16 match_port = 8080;

static __always_inline
int insert4(struct ipv4_revnat_tuple *key)
{
	struct ipv4_revnat_entry val = { };

	return map_update_elem(&cilium_lb4_reverse_sk, key, &val, 0);
}

static __always_inline
int insert6(struct ipv6_revnat_tuple *key)
{
	struct ipv6_revnat_entry val = { };

	return map_update_elem(&cilium_lb6_reverse_sk, key, &val, 0);
}

static __always_inline
int setup(void)
{
	struct ipv4_revnat_tuple key4 = { };
	struct ipv6_revnat_tuple key6 = { };

	key4.address = match_addr4;
	key4.port    = match_port;
	key4.cookie  = match_cookie4;

	key6.address.d1 = match_addr6_d1;
	key6.address.d2 = match_addr6_d2;
	key6.port       = match_port;
	key6.cookie     = match_cookie6;

	if (insert4(&key4))
		return 1;

	if (insert6(&key6))
		return 1;

	return 0;
}

static __always_inline
void reset(__sock_cookie cookie)
{
        current_cookie = cookie;
        destroys = 0;
        memset(write_data, 0, sizeof(__sock_cookie));
        write_len = 0;
}

