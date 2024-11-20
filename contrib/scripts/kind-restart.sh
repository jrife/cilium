#!/usr/bin/env bash

have_kind() {
    [[ -n "$(command -v kind)" ]]
}

if ! have_kind; then
    echo "Please install kind first:"
    echo "  https://kind.sigs.k8s.io/docs/user/quick-start/#installation"
    exit 1
fi

default_cluster_name="kind"

for cluster in "${@:-${default_cluster_name}}"; do
    nodes=$(kind get nodes --name "$cluster")

    while IFS= read -r node; do
        echo "Rebooting $node..."

        docker restart -t0 $node
    done <<< "$nodes"

    cilium status --wait
done

