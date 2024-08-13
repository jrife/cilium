package identity

import (
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/hive/cell"
)

var Cell = cell.Module(
	"identity",
	"Identity",

	cell.Provide(NewReservedIdentityCache),
	cell.ProvidePrivate(func(dc *option.DaemonConfig) (*ReservedIdentitySet, error) {
		for k := range dc.FixedIdentityMapping {
			ni, err := ParseNumericIdentity(k)
			if err != nil {
				return nil, err
			}

			if !IsUserReservedIdentity(ni) {
				return nil, ErrNotUserIdentity
			}
		}

		for k, lbl := range dc.FixedIdentityMapping {
			ni, _ := ParseNumericIdentity(k)
			reservedIdentities.AddUserReserved(ni, lbl)
		}

		return reservedIdentities, nil
	}),
	cell.Invoke(func(ic *reservedIdentityCache) {
		metrics.Identity.WithLabelValues(WellKnownIdentityType).Add(float64(len(ic.wellKnown)))

		for _, id := range ic.wellKnown {
			for labelSource := range id.Labels.CollectSources() {
				metrics.IdentityLabelSources.WithLabelValues(labelSource).Inc()
			}
		}

		metrics.Identity.WithLabelValues(ReservedIdentityType).Add(float64(len(ic.cache)))
		metrics.IdentityLabelSources.WithLabelValues(labels.LabelSourceReserved).Add(float64(len(ic.cache)))
	}),
)
