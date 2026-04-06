#!/bin/bash

set -ex

echo "IPv4"
go run github.com/cilium/cilium/tools/bench-sk-lookup \
	--bind 0.0.0.0:11111 \
	--lookup-dst 127.0.0.1:11111
go run github.com/cilium/cilium/tools/bench-sk-lookup \
	--bind 127.0.0.1:11111 \
	--lookup-dst 127.0.0.1:11111
go run github.com/cilium/cilium/tools/bench-sk-lookup \
	--bind 127.0.0.1:11111 \
	--connect 127.0.0.1:22222 \
	--lookup-src 127.0.0.1:22222 \
	--lookup-dst 127.0.0.1:11111

echo "IPv6"
go run github.com/cilium/cilium/tools/bench-sk-lookup \
	--bind [::]:11111 \
	--lookup-dst [::1]:11111
go run github.com/cilium/cilium/tools/bench-sk-lookup \
	--bind [::1]:11111 \
	--lookup-dst [::1]:11111
go run github.com/cilium/cilium/tools/bench-sk-lookup \
	--bind [::1]:11111 \
	--connect [::1]:22222 \
	--lookup-src [::1]:22222 \
	--lookup-dst [::1]:11111

