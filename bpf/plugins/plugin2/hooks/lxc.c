#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <ep_config.h>
#include <node_config.h>
#include "../../../lib/common.h"
#include "../../../lib/dbg.h"
#include "../../../lib/hooks.h"

int to_container_pre_ct_v4(struct __sk_buff *skb __maybe_unused) {
	printk("plugin2 ipv4 to %d", LXC_ID);
	return TC_ACT_UNSPEC;
}

int from_container_pre_ct_v4(struct __sk_buff *skb __maybe_unused) {
	printk("plugin2 ipv4 from %d", LXC_ID);
	return TC_ACT_UNSPEC;
}

HOOK(to_container_pre_ct_v4);
HOOK(from_container_pre_ct_v4);

BPF_LICENSE("Dual BSD/GPL");
