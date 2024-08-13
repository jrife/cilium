// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"sync"
	"unsafe"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
)

const (
	// Identities also have scopes, which is defined by the high 8 bits.
	// 0x00 -- Global and reserved identities. Reserved identities are
	//         not allocated like global identities, but are known
	//         because they are hardcoded in Cilium. Older versions of
	//         Cilium will not be aware of any "new" reserved identities
	//         that are added.
	// 0x01 -- local (CIDR) identities
	// 0x02 -- remote nodes

	// IdentityScopeMask is the top 8 bits of the 32 bit identity
	IdentityScopeMask = NumericIdentity(0xFF_00_00_00)

	// IdentityScopeGlobal is the identity scope used by global and reserved identities.
	IdentityScopeGlobal = NumericIdentity(0)

	// IdentityScopeLocal is the tag in the numeric identity that identifies
	// a numeric identity to have local (CIDR) scope.
	IdentityScopeLocal = NumericIdentity(1 << 24)

	// IdentityScopeRemoteNode is the tag in the numeric identity that identifies
	// an identity to be a remote in-cluster node.
	IdentityScopeRemoteNode = NumericIdentity(2 << 24)

	// MinAllocatorLocalIdentity represents the minimal numeric identity
	// that the localIdentityCache allocator can allocate for a local (CIDR)
	// identity.
	//
	// Note that this does not represents the minimal value for a local
	// identity, as the allocated ID will then be bitwise OR'ed with
	// LocalIdentityFlag.
	MinAllocatorLocalIdentity = 1

	// MinLocalIdentity represents the actual minimal numeric identity value
	// for a local (CIDR) identity.
	MinLocalIdentity = MinAllocatorLocalIdentity | IdentityScopeLocal

	// MaxAllocatorLocalIdentity represents the maximal numeric identity
	// that the localIdentityCache allocator can allocate for a local (CIDR)
	// identity.
	//
	// Note that this does not represents the maximal value for a local
	// identity, as the allocated ID will then be bitwise OR'ed with
	// LocalIdentityFlag.
	MaxAllocatorLocalIdentity = 0xFFFFFF

	// MaxLocalIdentity represents the actual maximal numeric identity value
	// for a local (CIDR) identity.
	MaxLocalIdentity = MaxAllocatorLocalIdentity | IdentityScopeLocal

	// MinimalNumericIdentity represents the minimal numeric identity not
	// used for reserved purposes.
	MinimalNumericIdentity = NumericIdentity(256)

	// UserReservedNumericIdentity represents the minimal numeric identity that
	// can be used by users for reserved purposes.
	UserReservedNumericIdentity = NumericIdentity(128)

	// InvalidIdentity is the identity assigned if the identity is invalid
	// or not determined yet
	InvalidIdentity = NumericIdentity(0)
)

var (
	// clusterIDInit ensures that clusterIDLen and clusterIDShift can only be
	// set once, and only if we haven't used either value elsewhere already.
	clusterIDInit sync.Once

	// clusterIDShift is the number of bits to shift a cluster ID in a numeric
	// identity and is equal to the number of bits that represent a cluster-local identity.
	clusterIDShift uint32
)

const (
	// IdentityUnknown represents an unknown identity
	IdentityUnknown NumericIdentity = iota

	// ReservedIdentityHost represents the local host
	ReservedIdentityHost

	// ReservedIdentityWorld represents any endpoint outside of the cluster
	ReservedIdentityWorld

	// ReservedIdentityUnmanaged represents unmanaged endpoints.
	ReservedIdentityUnmanaged

	// ReservedIdentityHealth represents the local cilium-health endpoint
	ReservedIdentityHealth

	// ReservedIdentityInit is the identity given to endpoints that have not
	// received any labels yet.
	ReservedIdentityInit

	// ReservedIdentityRemoteNode is the identity given to all nodes in
	// local and remote clusters except for the local node.
	ReservedIdentityRemoteNode

	// ReservedIdentityKubeAPIServer is the identity given to remote node(s) which
	// have backend(s) serving the kube-apiserver running.
	ReservedIdentityKubeAPIServer

	// ReservedIdentityIngress is the identity given to the IP used as the source
	// address for connections from Ingress proxies.
	ReservedIdentityIngress

	// ReservedIdentityWorldIPv4 represents any endpoint outside of the cluster
	// for IPv4 address only.
	ReservedIdentityWorldIPv4

	// ReservedIdentityWorldIPv6 represents any endpoint outside of the cluster
	// for IPv6 address only.
	ReservedIdentityWorldIPv6

	// ReservedEncryptedOverlay represents overlay traffic which must be IPSec
	// encrypted before it leaves the host
	ReservedEncryptedOverlay
)

// Special identities for well-known cluster components
// Each component has two identities. The first one is used for Kubernetes <1.21
// or when the NamespaceDefaultLabelName feature gate is disabled. The second
// one is used for Kubernetes >= 1.21 and when the NamespaceDefaultLabelName is
// enabled.
const (
	// ReservedETCDOperator is the reserved identity used for the etcd-operator
	// managed by Cilium.
	ReservedETCDOperator NumericIdentity = iota + 100

	// ReservedCiliumKVStore is the reserved identity used for the kvstore
	// managed by Cilium (etcd-operator).
	ReservedCiliumKVStore

	// ReservedKubeDNS is the reserved identity used for kube-dns.
	ReservedKubeDNS

	// ReservedEKSKubeDNS is the reserved identity used for kube-dns on EKS
	ReservedEKSKubeDNS

	// ReservedCoreDNS is the reserved identity used for CoreDNS
	ReservedCoreDNS

	// ReservedCiliumOperator is the reserved identity used for the Cilium operator
	ReservedCiliumOperator

	// ReservedEKSCoreDNS is the reserved identity used for CoreDNS on EKS
	ReservedEKSCoreDNS

	// ReservedCiliumEtcdOperator is the reserved identity used for the Cilium etcd operator
	ReservedCiliumEtcdOperator

	// Second identities for all above components
	ReservedETCDOperator2
	ReservedCiliumKVStore2
	ReservedKubeDNS2
	ReservedEKSKubeDNS2
	ReservedCoreDNS2
	ReservedCiliumOperator2
	ReservedEKSCoreDNS2
	ReservedCiliumEtcdOperator2
)

// localNodeIdentity is the endpoint identity allocated for the local node
var localNodeIdentity = struct {
	lock.Mutex
	identity NumericIdentity
}{
	identity: ReservedIdentityRemoteNode,
}

type Configuration interface {
	CiliumNamespaceName() string
}

func k8sLabel(key string, value string) string {
	return "k8s:" + key + "=" + value
}

// GetClusterIDShift returns the number of bits to shift a cluster ID in a numeric
// identity and is equal to the number of bits that represent a cluster-local identity.
// A sync.Once is used to ensure we only initialize clusterIDShift once.
func GetClusterIDShift() uint32 {
	clusterIDInit.Do(initClusterIDShift)
	return clusterIDShift
}

// initClusterIDShift sets variables that control the bit allocation of cluster
// ID in a numeric identity.
func initClusterIDShift() {
	// ClusterIDLen is the number of bits that represent a cluster ID in a numeric identity
	clusterIDLen := uint32(math.Log2(float64(cmtypes.ClusterIDMax + 1)))
	// ClusterIDShift is the number of bits to shift a cluster ID in a numeric identity
	clusterIDShift = NumericIdentityBitlength - clusterIDLen
}

// GetMinimalNumericIdentity returns the minimal numeric identity not used for
// reserved purposes.
func GetMinimalAllocationIdentity(clusterID uint32) NumericIdentity {
	if clusterID > 0 {
		// For ClusterID > 0, the identity range just starts from cluster shift,
		// no well-known-identities need to be reserved from the range.
		return NumericIdentity((1 << GetClusterIDShift()) * clusterID)
	}
	return MinimalNumericIdentity
}

// GetMaximumAllocationIdentity returns the maximum numeric identity that
// should be handed out by the identity allocator.
func GetMaximumAllocationIdentity(clusterID uint32) NumericIdentity {
	return NumericIdentity((1<<GetClusterIDShift())*(clusterID+1) - 1)
}

type ReservedIdentitySet struct {
	toID     map[string]NumericIdentity
	toName   map[NumericIdentity]string
	toLabels map[NumericIdentity]labels.Labels
}

func NewReservedIdentitySet() *ReservedIdentitySet {
	s := &ReservedIdentitySet{
		toID:     map[string]NumericIdentity{},
		toName:   map[NumericIdentity]string{},
		toLabels: map[NumericIdentity]labels.Labels{},
	}

	s.add(IdentityUnknown, labels.IDNameUnknown, nil)
	s.add(ReservedIdentityHost, labels.IDNameHost, labels.LabelHost)
	s.add(ReservedIdentityWorld, labels.IDNameWorld, labels.LabelWorld)
	s.add(ReservedIdentityWorldIPv4, labels.IDNameWorldIPv4, labels.LabelWorldIPv4)
	s.add(ReservedIdentityWorldIPv6, labels.IDNameWorldIPv6, labels.LabelWorldIPv6)
	s.add(ReservedIdentityUnmanaged, labels.IDNameUnmanaged, labels.NewLabelsFromModel([]string{"reserved:" + labels.IDNameUnmanaged}))
	s.add(ReservedIdentityHealth, labels.IDNameHealth, labels.LabelHealth)
	s.add(ReservedIdentityInit, labels.IDNameInit, labels.NewLabelsFromModel([]string{"reserved:" + labels.IDNameInit}))
	s.add(ReservedIdentityRemoteNode, labels.IDNameRemoteNode, labels.LabelRemoteNode)
	s.add(ReservedIdentityKubeAPIServer, labels.IDNameKubeAPIServer, labels.Map2Labels(map[string]string{
		labels.LabelKubeAPIServer.String(): "",
		labels.LabelRemoteNode.String():    "",
	}, ""))
	s.add(ReservedIdentityIngress, labels.IDNameIngress, labels.LabelIngress)
	s.add(ReservedEncryptedOverlay, labels.IDNameEncryptedOverlay, nil)

	return s
}

func (ri *ReservedIdentitySet) ForEach(fn func(NumericIdentity, string, labels.Labels)) {
	for name, ni := range ri.toID {
		fn(ni, name, ri.toLabels[ni])
	}
}

func (ri *ReservedIdentitySet) add(nid NumericIdentity, name string, lbls labels.Labels) {
	ri.toID[name] = nid
	ri.toName[nid] = name

	if lbls != nil {
		ri.toLabels[nid] = lbls
	}
}

func (ri *ReservedIdentitySet) AddUserReserved(ni NumericIdentity, name string) error {
	if !IsUserReservedIdentity(ni) {
		return ErrNotUserIdentity
	}

	ri.add(ni, name, labels.Labels{name: labels.NewLabel(name, "", labels.LabelSourceReserved)})

	return nil
}

func (ri *ReservedIdentitySet) ID(name string) NumericIdentity {
	if ni, exists := ri.toID[name]; exists {
		return ni
	}

	return IdentityUnknown
}

func (ri *ReservedIdentitySet) Name(ni NumericIdentity) string {
	if name, exists := ri.toName[ni]; exists {
		return name
	}

	return "unknown"
}

func (ri *ReservedIdentitySet) has(ni NumericIdentity) bool {
	_, exists := ri.toName[ni]

	return exists
}

func (ri *ReservedIdentitySet) size() int {
	return len(ri.toID)
}

func ReservedIdentities() *ReservedIdentitySet {
	return reservedIdentities
}

var (
	reservedIdentities = NewReservedIdentitySet()

	// ErrNotUserIdentity is an error returned for an identity that is not user
	// reserved.
	ErrNotUserIdentity = errors.New("not a user reserved identity")
)

// IsUserReservedIdentity returns true if the given NumericIdentity belongs
// to the space reserved for users.
func IsUserReservedIdentity(id NumericIdentity) bool {
	return id.Uint32() >= UserReservedNumericIdentity.Uint32() &&
		id.Uint32() < MinimalNumericIdentity.Uint32()
}

// NumericIdentity is the numeric representation of a security identity.
//
// Bits:
//
//	 0-15: identity identifier
//	16-23: cluster identifier
//	   24: LocalIdentityFlag: Indicates that the identity has a local scope
type NumericIdentity uint32

// NumericIdentityBitlength is the number of bits used on the wire for a
// NumericIdentity
const NumericIdentityBitlength = 24

// MaxNumericIdentity is the maximum value of a NumericIdentity.
const MaxNumericIdentity = math.MaxUint32

type NumericIdentitySlice []NumericIdentity

// AsUint32Slice returns the NumericIdentitySlice as a slice of uint32 without copying any data.
// This is safe as long as the underlying type stays as uint32.
func (nids NumericIdentitySlice) AsUint32Slice() []uint32 {
	if len(nids) == 0 {
		return nil
	}
	return unsafe.Slice((*uint32)(&nids[0]), len(nids))
}

func ParseNumericIdentity(id string) (NumericIdentity, error) {
	nid, err := strconv.ParseUint(id, 0, 32)
	if err != nil {
		return NumericIdentity(0), err
	}
	if nid > MaxNumericIdentity {
		return NumericIdentity(0), fmt.Errorf("%s: numeric identity too large", id)
	}
	return NumericIdentity(nid), nil
}

func (id NumericIdentity) StringID() string {
	return strconv.FormatUint(uint64(id), 10)
}

func (id NumericIdentity) String() string {
	if reservedIdentities.has(id) {
		return reservedIdentities.Name(id)
	}

	return id.StringID()
}

// Uint32 normalizes the ID for use in BPF program.
func (id NumericIdentity) Uint32() uint32 {
	return uint32(id)
}

// GetLocalNodeID returns the configured local node numeric identity that is
// set in tunnel headers when encapsulating packets originating from the local
// node.
func GetLocalNodeID() NumericIdentity {
	localNodeIdentity.Lock()
	defer localNodeIdentity.Unlock()
	return localNodeIdentity.identity
}

// SetLocalNodeID sets the local node id.
// Note that currently changes to the local node id only take effect during agent bootstrap
func SetLocalNodeID(nodeid uint32) {
	localNodeIdentity.Lock()
	defer localNodeIdentity.Unlock()
	localNodeIdentity.identity = NumericIdentity(nodeid)
}

// IsReservedIdentity returns whether id is one of the special reserved identities.
func (id NumericIdentity) IsReservedIdentity() bool {
	return reservedIdentities.has(id)
}

// ClusterID returns the cluster ID associated with the identity
func (id NumericIdentity) ClusterID() uint32 {
	return (uint32(id) >> uint32(GetClusterIDShift())) & cmtypes.ClusterIDMax
}

// GetWorldIdentityFromIP gets the correct world identity based
// on the IP address version. If Cilium is not in dual-stack mode
// then ReservedIdentityWorld will always be returned.
func GetWorldIdentityFromIP(addr netip.Addr) NumericIdentity {
	if option.Config.IsDualStack() {
		if addr.Is6() {
			return ReservedIdentityWorldIPv6
		}
		return ReservedIdentityWorldIPv4
	}
	return ReservedIdentityWorld
}

// HasLocalScope returns true if the identity is in the Local (CIDR) scope
func (id NumericIdentity) HasLocalScope() bool {
	return id.Scope() == IdentityScopeLocal
}

func (id NumericIdentity) HasRemoteNodeScope() bool {
	return id.Scope() == IdentityScopeRemoteNode
}

// Scope returns the identity scope of this given numeric ID.
func (id NumericIdentity) Scope() NumericIdentity {
	return id & IdentityScopeMask
}

// IsWorld returns true if the identity is one of the world identities
func (id NumericIdentity) IsWorld() bool {
	if id == ReservedIdentityWorld {
		return true
	}
	return option.Config.IsDualStack() &&
		(id == ReservedIdentityWorldIPv4 || id == ReservedIdentityWorldIPv6)
}

// IsCluster returns true if the identity is a cluster identity by excluding all
// identities that are known to be non-cluster identities.
// NOTE: keep this and bpf identity_is_cluster() in sync!
func (id NumericIdentity) IsCluster() bool {
	if id.IsWorld() || id.HasLocalScope() {
		return false
	}
	return true
}
