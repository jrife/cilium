/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <linux/netfilter/nf_conntrack_tuple_common.h>

#include <bpf/bpf_core_read.h>
#include <bpf/compiler.h>

#include "lib/common.h"

/* bpf_ct_opts - Options for CT lookup helpers
 *
 * Members:
 * @netns_id   - Specify the network namespace for lookup
 *		 Values:
 *		   BPF_F_CURRENT_NETNS (-1)
 *		     Use namespace associated with ctx (xdp_md, __sk_buff)
 *		   [0, S32_MAX]
 *		     Network Namespace ID
 * @error      - Out parameter, set for any errors encountered
 *		 Values:
 *		   -EINVAL - Passed NULL for bpf_tuple pointer
 *		   -EINVAL - opts->reserved is not 0
 *		   -EINVAL - netns_id is less than -1
 *		   -EINVAL - opts__sz isn't NF_BPF_CT_OPTS_SZ (16) or 12
 *		   -EINVAL - opts->ct_zone_id set when
			     opts__sz isn't NF_BPF_CT_OPTS_SZ (16)
 *		   -EPROTO - l4proto isn't one of IPPROTO_TCP or IPPROTO_UDP
 *		   -ENONET - No network namespace found for netns_id
 *		   -ENOENT - Conntrack lookup could not find entry for tuple
 *		   -EAFNOSUPPORT - tuple__sz isn't one of sizeof(tuple->ipv4)
 *				   or sizeof(tuple->ipv6)
 * @l4proto    - Layer 4 protocol
 *		 Values:
 *		   IPPROTO_TCP, IPPROTO_UDP
 * @dir:       - connection tracking tuple direction.
 * @ct_zone_id - connection tracking zone id.
 * @ct_zone_dir - connection tracking zone direction.
 * @reserved   - Reserved member, will be reused for more options in future
 *		 Values:
 *		   0
 */
struct bpf_ct_opts {
	__s32 netns_id;
	__s32 error;
	__u8 l4proto;
	__u8 dir;
	__u16 ct_zone_id;
	__u8 ct_zone_dir;
	__u8 reserved[3];
};

struct nf_conntrack_man {
	union nf_inet_addr u3;
	union nf_conntrack_man_proto u;
	__u16 l3num;
};

/* This contains the information to distinguish a connection. */
struct nf_conntrack_tuple {
	struct nf_conntrack_man src;
	struct {
		union nf_inet_addr u3;
		union {
			/* Add other protocols here. */
			__be16 all;

			struct {
				__be16 port;
			} tcp;
			struct {
				__be16 port;
			} udp;
			struct {
				__u8 type, code;
			} icmp;
			struct {
				__be16 port;
			} dccp;
			struct {
				__be16 port;
			} sctp;
			struct {
				__be16 key;
			} gre;
		} u;

		__u8 protonum;

		struct { } __nfct_hash_offsetend;

		__u8 dir;
	} dst;
};

struct nf_conntrack_tuple_hash {
	struct nf_conntrack_tuple tuple;
};

struct nf_conn {
	struct nf_conntrack_tuple_hash tuplehash[IP_CT_DIR_MAX];
	unsigned long status;
};

static __always_inline
read_nc_conntrack_tuple_hash(struct nf_conn *nfct, enum ip_conntrack_dir dir,
			     struct nf_conntrack_tuple)
{
}

static __always_inline
int nf_ct_lookup_reply_addr_v4(struct __ctx_buff *ctx,
			       const struct ipv4_ct_tuple *otuple,
			       struct ipv4_ct_tuple *rtuple)
{
	struct nf_conntrack_tuple_hash *tuplehash;
	struct nf_conntrack_tuple original;
	struct bpf_sock_tuple tuple = {
		.ipv4 = {
			.saddr = otuple->saddr,
			.daddr = otuple->daddr,
			.sport = otuple->sport,
			.dport = otuple->dport,
		},
	};
	struct bpf_ct_opts opts = {
		.l4proto = otuple->nexthdr,
		.netns_id = -1, /* netns_id is busted. It won't allow any ids higher than a certain amount. wrong type */
	};
	struct nf_conn *nfct;
	__u32 status;
	long err;

	// https://lore.kernel.org/all/20240522050712.732558-1-brad@faucet.nz/
	// 12 or 16 depending on kernel version
	nfct = ctx_ct_lookup(ctx, &tuple, sizeof(tuple.ipv4), &opts,
			     12);
	printk("port error ? %d dir = %d\n", opts.error, opts.dir);
	if (!nfct)
		return 0;
	if (opts.dir != IP_CT_DIR_ORIGINAL)
		return 0;
	err = bpf_core_read(&status, sizeof(nfct->status), &nfct->status);
	if (err)
		return 0;
	printk("port status = %u\n", status);
	if (!(status & IPS_SRC_NAT))
		goto out;
	tuplehash = (struct nf_onntrack_tuple_hash *)(
			(char *)bpf_core_field_offset(nfct->tuplehash) +
			(bpf_core_type_size(struct nf_conntrack_tuple_hash) *
			 IP_CT_DIR_ORIGINAL);
	err = bpf_core_read(&tuplehash, sizeof(tuplehash),
			    &(nfct->tuplehash));
	if (err)
		goto out;
	tuplehash = (struct nf_conntrack_tuple_hash *)((char *)tuplehash + bpf_core_type_size(struct nf_conntrack_tuple_hash)*IP_CT_DIR_ORIGINAL);

	err = bpf_core_read(&original, sizeof(original), &tuplehash->tuple);
	if (err)
		goto out;
out:
	bpf_ct_release(nfct);
	return !!nfct;
}

static __always_inline
int nf_ct_lookup_forward_addr_v4(struct __ctx_buff *ctx,
				 const struct ipv4_ct_tuple *rtuple,
				 struct ipv4_ct_tuple *otuple)
{
	return 0;
}

static __always_inline
int nf_ct_insert_v4(struct __ctx_buff *ctx, const struct ipv4_ct_tuple *otuple,
		    const struct ipv4_ct_tuple *rtuple)
{
	return 0;
}
