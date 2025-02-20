#pragma once

#include "common.h"
#include "maps.h"

#ifndef __noinline
#define __noinline __attribute__((noinline))
#endif

enum {
    HOOK_CTRL_NEXT       = 0,
    HOOK_CTRL_RETURN     = 1,
    HOOK_CTRL_ENTRIES    = 2,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, int);
	__type(value, int);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, HOOK_CTRL_ENTRIES);
} hook_ctrl __section_maps_btf;

#define EP_HOOK_POINT_MAP(name)                                               \
struct {                                                                      \
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);                                    \
	__type(key, __u32);                                                       \
	__type(value, __u32);                                                     \
    __uint(pinning, LIBBPF_PIN_BY_NAME);                                      \
	__uint(max_entries, 10);                                                  \
} endpoint_hooks_##name##_map_65535 __section_maps_btf;                       \

EP_HOOK_POINT_MAP(to_container_pre_ct_v4);
EP_HOOK_POINT_MAP(from_container_pre_ct_v4);
EP_HOOK_POINT_MAP(to_netdev_ipv4);
EP_HOOK_POINT_MAP(from_netdev_ipv4);

#define EP_HOOK_POINT(name)                                                   \
static __always_inline int hook_point_##name(struct __ctx_buff *ctx, int retprog)          \
{                                                                             \
    int *ret __maybe_unused;                                                  \
    int idx = HOOK_CTRL_NEXT;                                                 \
    int val = 0;                                                              \
                                                                              \
    if (map_update_elem(&hook_ctrl, &idx, &val, 0))                           \
        return DROP_INVALID_HOOK_CTRL;                                        \
    idx = HOOK_CTRL_RETURN;                                                   \
    val = retprog;                                                            \
    if (map_update_elem(&hook_ctrl, &idx, &val, 0))                           \
        return DROP_INVALID_HOOK_CTRL;                                        \
    tail_call(ctx, &endpoint_hooks_##name##_map_65535, 0);                    \
    tail_call(ctx, &CALLS_MAP, retprog);                                      \
    return DROP_MISSED_TAIL_CALL;                                             \
}                                                                             \

#define HOOK(name)                                             \
__section("tc")                                                \
int hook_prog_##name(struct __ctx_buff *ctx)                   \
{                                                              \
	int idx = HOOK_CTRL_NEXT;						           \
	int *val;						                           \
    int ret;                                                   \
                                                               \
    ret = name(ctx);                                           \
    if (IS_ERR(ret) && ret != TC_ACT_UNSPEC)                   \
			goto out;                                          \
    val = map_lookup_elem(&hook_ctrl, &idx);                   \
    if (!val) {                                                \
        ret = DROP_INVALID_HOOK_CTRL;                          \
        goto out;                                              \
    }                                                          \
    *val = *val + 1;                                           \
    if (map_update_elem(&hook_ctrl, &idx, val, 0)) {           \
        ret = DROP_INVALID_HOOK_CTRL;                          \
        goto out;                                              \
    }                                                          \
    tail_call(ctx, &endpoint_hooks_##name##_map_65535, *val);  \
    idx = HOOK_CTRL_RETURN;                                    \
    val = map_lookup_elem(&hook_ctrl, &idx);                   \
    if (!val) {                                                \
        ret = DROP_INVALID_HOOK_CTRL;                          \
        goto out;                                              \
    }                                                          \
    tail_call(ctx, &CALLS_MAP, *val);                          \
    ret = DROP_MISSED_TAIL_CALL;                               \
out:                                                           \
    return ret;                                                \
}          