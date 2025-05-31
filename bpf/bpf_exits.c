// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
/* Copyright Authors of Cilium */

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/ctx/skb.h>
#include <bpf/helpers.h>

#include "bpf/loader.h"
#include "bpf/section.h"

#define printk(fmt, ...)				\
	({						\
		const char ____fmt[] = fmt;		\
		trace_printk(____fmt, sizeof(____fmt),	\
			     ##__VA_ARGS__);		\
	})

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 1);
} cilium_return __section_maps_btf;

__section_exit
int exit_handler(int ret)
{
	int zero = 0;

	printk("program returned %d\n", ret);

	if (map_update_elem(&cilium_return, &zero, &ret, 0) < 0)
		return ret;

	printk("exit handler: %d\n", ret);

	return ret;
}

BPF_LICENSE("Dual BSD/GPL");
