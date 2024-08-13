// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identity

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"

	"github.com/cilium/cilium/pkg/labels"
)

const (
	NodeLocalIdentityType    = "node_local"
	ReservedIdentityType     = "reserved"
	ClusterLocalIdentityType = "cluster_local"
	WellKnownIdentityType    = "well_known"
	RemoteNodeIdentityType   = "remote_node"
)

// Identity is the representation of the security context for a particular set of
// labels.
type Identity struct {
	// Identity's ID.
	ID NumericIdentity `json:"id"`
	// Set of labels that belong to this Identity.
	Labels labels.Labels `json:"labels"`

	// LabelArray contains the same labels as Labels in a form of a list, used
	// for faster lookup.
	LabelArray labels.LabelArray `json:"-"`

	// CIDRLabel is the primary identity label when the identity represents
	// a CIDR. The Labels field will consist of all matching prefixes, e.g.
	// 10.0.0.0/8
	// 10.0.0.0/7
	// 10.0.0.0/6
	// [...]
	// reserved:world
	//
	// The CIDRLabel field will only contain 10.0.0.0/8
	CIDRLabel labels.Labels `json:"-"`

	// ReferenceCount counts the number of references pointing to this
	// identity. This field is used by the owning cache of the identity.
	ReferenceCount int `json:"-"`
}

// IPIdentityPair is a pairing of an IP and the security identity to which that
// IP corresponds. May include an optional Mask which, if present, denotes that
// the IP represents a CIDR with the specified Mask.
//
// WARNING - STABLE API
// This structure is written as JSON to the key-value store. Do NOT modify this
// structure in ways which are not JSON forward compatible.
type IPIdentityPair struct {
	IP           net.IP          `json:"IP"`
	Mask         net.IPMask      `json:"Mask"`
	HostIP       net.IP          `json:"HostIP"`
	ID           NumericIdentity `json:"ID"`
	Key          uint8           `json:"Key"`
	Metadata     string          `json:"Metadata"`
	K8sNamespace string          `json:"K8sNamespace,omitempty"`
	K8sPodName   string          `json:"K8sPodName,omitempty"`
	NamedPorts   []NamedPort     `json:"NamedPorts,omitempty"`
}

type IdentityMap map[NumericIdentity]labels.LabelArray

// GetKeyName returns the kvstore key to be used for the IPIdentityPair
func (pair *IPIdentityPair) GetKeyName() string { return pair.PrefixString() }

// Marshal returns the IPIdentityPair object as JSON byte slice
func (pair *IPIdentityPair) Marshal() ([]byte, error) { return json.Marshal(pair) }

// Unmarshal parses the JSON byte slice and updates the IPIdentityPair receiver
func (pair *IPIdentityPair) Unmarshal(key string, data []byte) error {
	newPair := IPIdentityPair{}
	if err := json.Unmarshal(data, &newPair); err != nil {
		return err
	}

	if got := newPair.GetKeyName(); got != key {
		return fmt.Errorf("IP address does not match key: expected %s, got %s", key, got)
	}

	*pair = newPair
	return nil
}

// NamedPort is a mapping from a port name to a port number and protocol.
//
// WARNING - STABLE API
// This structure is written as JSON to the key-value store. Do NOT modify this
// structure in ways which are not JSON forward compatible.
type NamedPort struct {
	Name     string `json:"Name"`
	Port     uint16 `json:"Port"`
	Protocol string `json:"Protocol"`
}

// Sanitize takes a partially initialized Identity (for example, deserialized
// from json) and reconstitutes the full object from what has been restored.
func (id *Identity) Sanitize() {
	if id.Labels != nil {
		id.LabelArray = id.Labels.LabelArray()
	}
}

// StringID returns the identity identifier as string
func (id *Identity) StringID() string {
	return id.ID.StringID()
}

// StringID returns the identity identifier as string
func (id *Identity) String() string {
	return id.ID.StringID()
}

// IsReserved returns whether the identity represents a reserved identity
// (true), or not (false).
func (id *Identity) IsReserved() bool {
	return reservedIdentities.has(id.ID)
}

// IsFixed returns whether the identity represents a fixed identity
// (true), or not (false).
func (id *Identity) IsFixed() bool {
	return reservedIdentities.has(id.ID) &&
		(id.ID == ReservedIdentityHost || id.ID == ReservedIdentityHealth ||
			IsUserReservedIdentity(id.ID))
}

// NewIdentityFromLabelArray creates a new identity
func NewIdentityFromLabelArray(id NumericIdentity, lblArray labels.LabelArray) *Identity {
	var lbls labels.Labels

	if lblArray != nil {
		lbls = lblArray.Labels()
	}
	return &Identity{ID: id, Labels: lbls, LabelArray: lblArray}
}

// NewIdentity creates a new identity
func NewIdentity(id NumericIdentity, lbls labels.Labels) *Identity {
	var lblArray labels.LabelArray

	if lbls != nil {
		lblArray = lbls.LabelArray()
	}
	return &Identity{ID: id, Labels: lbls, LabelArray: lblArray}
}

// IsHost determines whether the IP in the pair represents a host (true) or a
// CIDR prefix (false)
func (pair *IPIdentityPair) IsHost() bool {
	return pair.Mask == nil
}

// PrefixString returns the IPIdentityPair's IP as either a host IP in the
// format w.x.y.z if 'host' is true, or as a prefix in the format the w.x.y.z/N
// if 'host' is false.
func (pair *IPIdentityPair) PrefixString() string {
	ipstr := pair.IP.String()

	if pair.IsHost() {
		return ipstr
	}

	ones, _ := pair.Mask.Size()
	return ipstr + "/" + strconv.Itoa(ones)
}

// RequiresGlobalIdentity returns true if the label combination requires a
// global identity
func RequiresGlobalIdentity(lbls labels.Labels) bool {
	return ScopeForLabels(lbls) == IdentityScopeGlobal
}

// ScopeForLabels returns the identity scope to be used for the label set.
// If all labels are either CIDR or reserved, then returns the CIDR scope.
// Note: This assumes the caller has already called LookupReservedIdentityByLabels;
// it does not handle that case.
func ScopeForLabels(lbls labels.Labels) NumericIdentity {
	scope := IdentityScopeGlobal

	// If this is a remote node, return the remote node scope.
	// Note that this is not reachable when policy-cidr-selects-nodes is false or
	// when enable-node-selector-labels is false, since
	// callers will already have gotten a value from LookupReservedIdentityByLabels.
	if lbls.Has(labels.LabelRemoteNode[labels.IDNameRemoteNode]) {
		return IdentityScopeRemoteNode
	}

	for _, label := range lbls {
		switch label.Source {
		case labels.LabelSourceCIDR, labels.LabelSourceFQDN, labels.LabelSourceReserved:
			scope = IdentityScopeLocal
		default:
			return IdentityScopeGlobal
		}
	}

	return scope
}
