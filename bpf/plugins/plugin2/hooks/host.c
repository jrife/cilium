#include <bpf/ctx/skb.h>
#include <bpf/api.h>
#include <ep_config.h>
#include <node_config.h>
#include "../../../lib/common.h"
#include "../../../lib/dbg.h"
#include "../../../lib/hooks.h"

int from_netdev_ipv4(struct __sk_buff *skb __maybe_unused) {
	printk("plugin2 ipv4 from host");
	return TC_ACT_UNSPEC;
}

HOOK(from_netdev_ipv4);

BPF_LICENSE("Dual BSD/GPL");