// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Hubble

package observe

import (
	"sort"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
)

// reservedIdentitiesNames returns a slice of all the reserved identity
// strings.
func reservedIdentitiesNames() []string {
	identities := make([]identity.NumericIdentity, 0)
	identity.ReservedIdentities().ForEach(func(ni identity.NumericIdentity, _ string, _ labels.Labels) {
		identities = append(identities, ni)
	})

	sort.Slice(identities, func(i, j int) bool {
		return identities[i].Uint32() < identities[j].Uint32()
	})

	names := make([]string, len(identities))
	for i, id := range identities {
		names[i] = id.String()
	}
	return names
}

// parseIdentity parse and return both numeric and reserved identities, or an
// error.
func parseIdentity(s string) (identity.NumericIdentity, error) {
	if id := identity.ReservedIdentities().ID(s); id != identity.IdentityUnknown {
		return id, nil
	}
	return identity.ParseNumericIdentity(s)
}
