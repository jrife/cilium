#pragma once

#include "../../../lib/common.h"
#include "../../../lib/maps.h"

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, int);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 1);
} plugin1_count __section_maps_btf;

static __always_inline int inc(void)
{
    int zero = 0;
	int *val = 0;

    val = map_lookup_elem(&plugin1_count, &zero);
    if (!val) {
        val = &zero;
        if (map_update_elem(&plugin1_count, &zero, val, 0))
            return -1;

        return 0;
    }

    return __sync_fetch_and_add(val, 1) + 1;
}