// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"fmt"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	api "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
)

type ReservedIdentityCache interface {
	Put(NumericIdentity, labels.Labels) *Identity
	Lookup(NumericIdentity) *Identity
	LookupByLabels(labels.Labels) *Identity
	ForEach(func(*Identity))
	IsWellKnown(NumericIdentity) bool
	List() IdentityMap
}

type reservedIdentityCache struct {
	mu        lock.RWMutex
	dc        *option.DaemonConfig
	reserved  *ReservedIdentitySet
	cache     map[NumericIdentity]*Identity
	wellKnown map[NumericIdentity]*Identity
}

func NewReservedIdentityCache(dc *option.DaemonConfig, ci cmtypes.ClusterInfo, reservedIdentities *ReservedIdentitySet) *reservedIdentityCache {
	ic := &reservedIdentityCache{
		dc:        dc,
		reserved:  reservedIdentities,
		cache:     map[NumericIdentity]*Identity{},
		wellKnown: map[NumericIdentity]*Identity{},
	}

	reservedIdentities.ForEach(func(ni NumericIdentity, name string, lbls labels.Labels) {
		ic.Put(ni, lbls)
	})

	if dc.EnableWellKnownIdentities {
		fmt.Println("ENABLING WELL KNOWN")
		ic.initWellKnownIdentities(dc, ci)
	}

	return ic
}

func (ic *reservedIdentityCache) initWellKnownIdentities(c *option.DaemonConfig, cinfo cmtypes.ClusterInfo) {
	// etcd-operator labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=cilium-etcd-sa
	//   k8s:io.kubernetes.pod.namespace=<NAMESPACE>
	//   k8s:io.cilium/app=etcd-operator
	//   k8s:io.cilium.k8s.policy.cluster=default
	etcdOperatorLabels := []string{
		"k8s:io.cilium/app=etcd-operator",
		k8sLabel(api.PodNamespaceLabel, c.CiliumNamespaceName()),
		k8sLabel(api.PolicyLabelServiceAccount, "cilium-etcd-sa"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	ic.addWellKnown(ReservedETCDOperator, labels.NewLabelsFromModel(etcdOperatorLabels))
	ic.addWellKnown(ReservedETCDOperator2, labels.NewLabelsFromModel(append(etcdOperatorLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, c.CiliumNamespaceName()))))

	// cilium-etcd labels
	//   k8s:app=etcd
	//   k8s:io.cilium/app=etcd-operator
	//   k8s:etcd_cluster=cilium-etcd
	//   k8s:io.cilium.k8s.policy.serviceaccount=default
	//   k8s:io.kubernetes.pod.namespace=<NAMESPACE>
	//   k8s:io.cilium.k8s.policy.cluster=default
	// these 2 labels are ignored by cilium-agent as they can change over time
	//   container:annotation.etcd.version=3.3.9
	//   k8s:etcd_node=cilium-etcd-6snk6vsjcm
	ciliumEtcdLabels := []string{
		"k8s:app=etcd",
		"k8s:etcd_cluster=cilium-etcd",
		"k8s:io.cilium/app=etcd-operator",
		k8sLabel(api.PodNamespaceLabel, c.CiliumNamespaceName()),
		k8sLabel(api.PolicyLabelServiceAccount, "default"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	ic.addWellKnown(ReservedCiliumKVStore, labels.NewLabelsFromModel(ciliumEtcdLabels))
	ic.addWellKnown(ReservedCiliumKVStore2, labels.NewLabelsFromModel(append(ciliumEtcdLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, c.CiliumNamespaceName()))))

	// kube-dns labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=kube-dns
	//   k8s:io.kubernetes.pod.namespace=kube-system
	//   k8s:k8s-app=kube-dns
	//   k8s:io.cilium.k8s.policy.cluster=default
	kubeDNSLabels := []string{
		"k8s:k8s-app=kube-dns",
		k8sLabel(api.PodNamespaceLabel, "kube-system"),
		k8sLabel(api.PolicyLabelServiceAccount, "kube-dns"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	ic.addWellKnown(ReservedKubeDNS, labels.NewLabelsFromModel(kubeDNSLabels))
	ic.addWellKnown(ReservedKubeDNS2, labels.NewLabelsFromModel(append(kubeDNSLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, "kube-system"))))

	// kube-dns EKS labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=kube-dns
	//   k8s:io.kubernetes.pod.namespace=kube-system
	//   k8s:k8s-app=kube-dns
	//   k8s:io.cilium.k8s.policy.cluster=default
	//   k8s:eks.amazonaws.com/component=kube-dns
	eksKubeDNSLabels := []string{
		"k8s:k8s-app=kube-dns",
		"k8s:eks.amazonaws.com/component=kube-dns",
		k8sLabel(api.PodNamespaceLabel, "kube-system"),
		k8sLabel(api.PolicyLabelServiceAccount, "kube-dns"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	ic.addWellKnown(ReservedEKSKubeDNS, labels.NewLabelsFromModel(eksKubeDNSLabels))
	ic.addWellKnown(ReservedEKSKubeDNS2, labels.NewLabelsFromModel(append(eksKubeDNSLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, "kube-system"))))

	// CoreDNS EKS labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=coredns
	//   k8s:io.kubernetes.pod.namespace=kube-system
	//   k8s:k8s-app=kube-dns
	//   k8s:io.cilium.k8s.policy.cluster=default
	//   k8s:eks.amazonaws.com/component=coredns
	eksCoreDNSLabels := []string{
		"k8s:k8s-app=kube-dns",
		"k8s:eks.amazonaws.com/component=coredns",
		k8sLabel(api.PodNamespaceLabel, "kube-system"),
		k8sLabel(api.PolicyLabelServiceAccount, "coredns"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	ic.addWellKnown(ReservedEKSCoreDNS, labels.NewLabelsFromModel(eksCoreDNSLabels))
	ic.addWellKnown(ReservedEKSCoreDNS2, labels.NewLabelsFromModel(append(eksCoreDNSLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, "kube-system"))))

	// CoreDNS labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=coredns
	//   k8s:io.kubernetes.pod.namespace=kube-system
	//   k8s:k8s-app=kube-dns
	//   k8s:io.cilium.k8s.policy.cluster=default
	coreDNSLabels := []string{
		"k8s:k8s-app=kube-dns",
		k8sLabel(api.PodNamespaceLabel, "kube-system"),
		k8sLabel(api.PolicyLabelServiceAccount, "coredns"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	ic.addWellKnown(ReservedCoreDNS, labels.NewLabelsFromModel(coreDNSLabels))
	ic.addWellKnown(ReservedCoreDNS2, labels.NewLabelsFromModel(append(coreDNSLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, "kube-system"))))

	// CiliumOperator labels
	//   k8s:io.cilium.k8s.policy.serviceaccount=cilium-operator
	//   k8s:io.kubernetes.pod.namespace=<NAMESPACE>
	//   k8s:name=cilium-operator
	//   k8s:io.cilium/app=operator
	//   k8s:app.kubernetes.io/part-of=cilium
	//   k8s:app.kubernetes.io/name=cilium-operator
	//   k8s:io.cilium.k8s.policy.cluster=default
	ciliumOperatorLabels := []string{
		"k8s:name=cilium-operator",
		"k8s:io.cilium/app=operator",
		"k8s:app.kubernetes.io/part-of=cilium",
		"k8s:app.kubernetes.io/name=cilium-operator",
		k8sLabel(api.PodNamespaceLabel, c.CiliumNamespaceName()),
		k8sLabel(api.PolicyLabelServiceAccount, "cilium-operator"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	ic.addWellKnown(ReservedCiliumOperator, labels.NewLabelsFromModel(ciliumOperatorLabels))
	ic.addWellKnown(ReservedCiliumOperator2, labels.NewLabelsFromModel(append(ciliumOperatorLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, c.CiliumNamespaceName()))))

	// cilium-etcd-operator labels
	//   k8s:io.cilium.k8s.policy.cluster=default
	//   k8s:io.cilium.k8s.policy.serviceaccount=cilium-etcd-operator
	//   k8s:io.cilium/app=etcd-operator
	//   k8s:app.kubernetes.io/name: cilium-etcd-operator
	//   k8s:app.kubernetes.io/part-of: cilium
	//   k8s:io.kubernetes.pod.namespace=<NAMESPACE>
	//   k8s:name=cilium-etcd-operator
	ciliumEtcdOperatorLabels := []string{
		"k8s:name=cilium-etcd-operator",
		"k8s:io.cilium/app=etcd-operator",
		"k8s:app.kubernetes.io/name: cilium-etcd-operator",
		"k8s:app.kubernetes.io/part-of: cilium",
		k8sLabel(api.PodNamespaceLabel, c.CiliumNamespaceName()),
		k8sLabel(api.PolicyLabelServiceAccount, "cilium-etcd-operator"),
		k8sLabel(api.PolicyLabelCluster, cinfo.Name),
	}
	ic.addWellKnown(ReservedCiliumEtcdOperator, labels.NewLabelsFromModel(ciliumEtcdOperatorLabels))
	ic.addWellKnown(ReservedCiliumEtcdOperator2, labels.NewLabelsFromModel(append(ciliumEtcdOperatorLabels,
		k8sLabel(api.PodNamespaceMetaNameLabel, c.CiliumNamespaceName()))))
}

func (ic *reservedIdentityCache) addWellKnown(ni NumericIdentity, lbls labels.Labels) {
	identity := NewIdentity(ni, lbls)

	ic.mu.Lock()
	ic.wellKnown[ni] = identity
	ic.cache[ni] = identity
	ic.mu.Unlock()
}

func (ic *reservedIdentityCache) Put(ni NumericIdentity, lbls labels.Labels) *Identity {
	identity := NewIdentity(ni, lbls)

	ic.mu.Lock()
	ic.cache[ni] = identity
	ic.mu.Unlock()

	return identity
}

func (ic *reservedIdentityCache) Lookup(ni NumericIdentity) *Identity {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	return ic.cache[ni]
}

func (ic *reservedIdentityCache) LookupByLabels(lbls labels.Labels) *Identity {
	for _, i := range ic.wellKnown {
		if lbls.Equals(i.Labels) {
			return i
		}
	}

	// Check if a fixed identity exists.
	if lbl, exists := lbls[labels.LabelKeyFixedIdentity]; exists {
		// If the set of labels contain a fixed identity then and exists in
		// the map of reserved IDs then return the identity of that reserved ID.
		id := ic.reserved.ID(lbl.Value)
		if id != IdentityUnknown && IsUserReservedIdentity(id) {
			return ic.Lookup(id)
		}
		// If a fixed identity was not found then we return nil to avoid
		// falling to a reserved identity.
		return nil
	}

	// If there is no reserved label, return nil.
	if !lbls.IsReserved() {
		return nil
	}

	var nid NumericIdentity
	if lbls.Has(labels.LabelHost[labels.IDNameHost]) {
		nid = ReservedIdentityHost
	} else if lbls.Has(labels.LabelRemoteNode[labels.IDNameRemoteNode]) {
		// If selecting remote-nodes via CIDR policies is allowed, then
		// they no longer have a reserved identity.
		if ic.dc.PolicyCIDRMatchesNodes() {
			return nil
		}
		// If selecting remote-nodes via node labels is allowed, then
		// they no longer have a reserved identity and are using
		// IdentityScopeRemoteNode.
		if ic.dc.PerNodeLabelsEnabled() {
			return nil
		}
		nid = ReservedIdentityRemoteNode
		if lbls.Has(labels.LabelKubeAPIServer[labels.IDNameKubeAPIServer]) {
			// If there's a kube-apiserver label, then we know this is
			// kube-apiserver reserved ID, so change it as such.
			// Only traffic from non-kube-apiserver nodes should be
			// considered as remote-node.
			nid = ReservedIdentityKubeAPIServer
		}
	}

	if nid != IdentityUnknown {
		return NewIdentity(nid, lbls)
	}

	// We have handled all the cases where multiple labels can be present.
	// So, we make sure the set of labels only contains a single label and
	// that label is of the reserved type. This is to prevent users from
	// adding cilium-reserved labels into the workloads.
	if len(lbls) != 1 {
		return nil
	}

	nid = ic.reserved.ID(lbls.ToSlice()[0].Key)
	if nid != IdentityUnknown && !IsUserReservedIdentity(nid) {
		return ic.Lookup(nid)
	}
	return nil
}

func (ic *reservedIdentityCache) ForEach(f func(*Identity)) {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	for _, identity := range ic.cache {
		f(identity)
	}
}

func (ic *reservedIdentityCache) IsWellKnown(nid NumericIdentity) bool {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	return ic.wellKnown[nid] != nil
}

func (ic *reservedIdentityCache) List() IdentityMap {
	ic.mu.RLock()
	defer ic.mu.RUnlock()

	out := make(IdentityMap, len(ic.cache))
	for ni, identity := range ic.cache {
		out[ni] = identity.LabelArray
	}

	return out
}
