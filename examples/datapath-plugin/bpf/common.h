/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

#pragma once

#include <bpf/loader.h>
#include <bpf/section.h>

#define TC_ACT_UNSPEC	-1
#define SYS_PROCEED	1

#define CLIENT_BIND_PORT 31234
#define CLIENT_PROXY_BIND_PORT 54321
#define SERVER_PROXY_BIND_PORT 45678
#define SERVER_LISTEN_PORT 10001

#ifdef printk
# undef printk
#endif

// # define printk(fmt, ...)					\
// 		({						\
// 			const char ____fmt[] = fmt;		\
// 			trace_printk(____fmt, sizeof(____fmt),	\
// 				     ##__VA_ARGS__);		\
// 		})
# define printk(fmt, ...)					\
		do { } while (0)

enum iface {
	IFACE_PROXY = 0,
	IFACE_WORKLOAD = 1,
	IFACE_WORKLOAD_PEER = 2,
	IFACE_PROXY_PEER = 3,
	IFACE_ENTRIES = 4,
	IFACE_NONE = IFACE_ENTRIES,
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, IFACE_ENTRIES);
} ifindices __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, union macaddr);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, IFACE_ENTRIES);
} ifmacs __section_maps_btf;

static __always_inline __u32 ifindex(enum iface i)
{
	__u32 key = (__u32)i;
	__u32 *idx;

	idx = map_lookup_elem(&ifindices, &key);
	if (!idx)
		return 0;

	return *idx;
}

static __always_inline union macaddr *ifmac(enum iface i)
{
	__u32 key = (__u32)i;

	return (union macaddr *)map_lookup_elem(&ifmacs, &key);
}

static __always_inline int update_macs(struct __ctx_buff *ctx,
				       enum iface src,
				       enum iface dst)
{
	union macaddr *src_mac;
	union macaddr *dst_mac;

	if (src != IFACE_NONE) {
		src_mac = ifmac(src);
		if (!src_mac)
			return TC_ACT_UNSPEC;
	}
	if (dst != IFACE_NONE) {
		dst_mac = ifmac(dst);
		if (!dst_mac)
			return TC_ACT_UNSPEC;
	}

	if (src_mac && eth_store_saddr(ctx, (__u8 *)src_mac, 0))
		return TC_ACT_UNSPEC;
	if (dst_mac && eth_store_daddr(ctx, (__u8 *)dst_mac, 0))
		return TC_ACT_UNSPEC;

	return TC_ACT_OK;
}

static __always_inline int validate_and_load(struct __ctx_buff *ctx,
					     struct ipv4_ct_tuple *tuple)
{
	void *data, *data_end;
	struct iphdr *ip4;
	__be16 proto = 0;
	__be16 ports[2];
	
	if (!validate_ethertype(ctx, &proto) ||
	    proto != bpf_htons(ETH_P_IP) ||
	    !revalidate_data_pull(ctx, &data, &data_end, &ip4) ||
	    ip4->protocol != IPPROTO_TCP ||
	    l4_load_ports(ctx, ETH_HLEN + (ip4->ihl * 4), ports) < 0)
		return TC_ACT_UNSPEC;

	tuple->saddr = ip4->saddr;
	tuple->sport = ports[0];
	tuple->daddr = ip4->daddr;
	tuple->dport = ports[1];

	return TC_ACT_OK;
}

