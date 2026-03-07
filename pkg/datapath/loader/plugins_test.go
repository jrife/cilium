package loader

import (
	"testing"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/cilium/pkg/datapath/bpf/testprogs"
	"github.com/cilium/cilium/pkg/testutils"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"
)

func TestPluginDependencyGraph(t *testing.T) {
	type constraintSet struct {
		plugin string
		after  []string
		before []string
	}

	indexOf := func(s string, l []string) int {
		for i, e := range l {
			if e == s {
				return i
			}
		}

		return -1
	}

	intersect := func(a []string, b map[string]bool) []string {
		var result []string

		for _, s := range a {
			if !b[s] {
				continue
			}

			result = append(result, s)
		}

		return result
	}

	testCases := []struct {
		name        string
		constraints []constraintSet
		expectedErr error
	}{
		{
			name: "no constraints single",
			constraints: []constraintSet{
				{
					plugin: "a",
				},
			},
			expectedErr: nil,
		},
		{
			name: "no constraints multiple",
			constraints: []constraintSet{
				{
					plugin: "a",
				},
				{
					plugin: "b",
				},
				{
					plugin: "c",
				},
			},
			expectedErr: nil,
		},
		{
			name: "after constraint two nodes",
			constraints: []constraintSet{
				{
					plugin: "a",
					after:  []string{"b"},
				},
				{
					plugin: "b",
				},
			},
			expectedErr: nil,
		},
		{
			name: "before constraint two nodes",
			constraints: []constraintSet{
				{
					plugin: "a",
					before: []string{"b"},
				},
				{
					plugin: "b",
				},
			},
			expectedErr: nil,
		},
		{
			name: "multiple constraints multiple nodes",
			constraints: []constraintSet{
				{
					plugin: "a",
					before: []string{"b"},
				},
				{
					plugin: "b",
					after:  []string{"a"},
				},
				{
					plugin: "c",
					after:  []string{"a", "b"},
				},
				{
					plugin: "d",
					after:  []string{"c"},
				},
			},
			expectedErr: nil,
		},
		{
			name: "dependency cycle",
			constraints: []constraintSet{
				{
					plugin: "a",
					before: []string{"b"},
				},
				{
					plugin: "b",
					after:  []string{"a"},
				},
				{
					plugin: "c",
					after:  []string{"a", "b"},
					before: []string{"d"},
				},
				{
					plugin: "d",
					before: []string{"b"},
				},
			},
			expectedErr: &dependencyCycleError{
				cycle: []string{"b", "c", "d", "b"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			g := &pluginDependencyGraph{}
			nodes := map[string]bool{}

			for _, c := range tc.constraints {
				nodes[c.plugin] = true
				g.addNode(c.plugin)
				for _, a := range c.after {
					g.after(c.plugin, a)
				}
				for _, b := range c.before {
					g.before(c.plugin, b)
				}
			}

			sorted, err := g.sort()
			if tc.expectedErr != nil {
				require.EqualError(t, err, tc.expectedErr.Error())
				return
			} else {
				require.NoError(t, err)
			}

			require.Lenf(t, sorted, len(nodes), "expected set of plugin names %v to equal the set of all nodes in the graph %v", sorted, nodes)
			require.Subsetf(t, sorted, nodes, "expected set of plugin names %v to equal the set of all nodes in the graph %v", sorted, nodes)
			for _, c := range tc.constraints {
				i := indexOf(c.plugin, sorted)
				require.Subsetf(t, sorted[i+1:], intersect(c.before, nodes), "expected all of %v to come before %s in sorted plugins %v", c.before, c.plugin, sorted)
				require.Subsetf(t, sorted[:i], intersect(c.after, nodes), "expected all of %v to come after %s in sorted plugins %v", c.after, c.plugin, sorted)
			}
		})
	}
}

func TestPrivilegedHooksSpec(t *testing.T) {
	testutils.PrivilegedTest(t)

	testCases := []struct {
		name                    string
		hooks                   map[string][]*datapathplugins.PrepareHooksResponse_HookSpec
		expectLoadHooksRequests map[string]*datapathplugins.LoadHooksRequest
	}{
		{
			name: "basic",
			hooks: map[string][]*datapathplugins.PrepareHooksResponse_HookSpec{
				"plugin_a": {
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_a",
					},
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_b",
					},
				},
				"plugin_b": {
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_a",
					},
					{
						Type:   datapathplugins.HookType_PRE,
						Target: "program_b",
					},
				},
			},
			expectLoadHooksRequests: map[string]*datapathplugins.LoadHooksRequest{
				"plugin_a": {
					Hooks: []*datapathplugins.LoadHooksRequest_Hook{
						{
							Target: "program_a",
							AttachTarget: &datapathplugins.LoadHooksRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_a"),
							},
						},
						{
							Target: "program_b",
							AttachTarget: &datapathplugins.LoadHooksRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_a"),
							},
						},
					},
				},
				"plugin_b": {
					Hooks: []*datapathplugins.LoadHooksRequest_Hook{

						{
							Target: "program_a",
							AttachTarget: &datapathplugins.LoadHooksRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_b"),
							},
						},
						{
							Target: "program_b",
							AttachTarget: &datapathplugins.LoadHooksRequest_Hook_AttachTarget{
								SubprogName: preHookSubprogName("plugin_b"),
							},
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hooksSpec := newHooksSpec()
			for plugin, hooks := range tc.hooks {
				for _, hook := range hooks {
					hooksSpec.hook(hook.Target, hook.Type).addNode(plugin)
					for _, constraint := range hook.Constraints {
						switch constraint.Order {
						case datapathplugins.PrepareHooksResponse_HookSpec_OrderingConstraint_BEFORE:
							hooksSpec.hook(hook.Target, hook.Type).before(plugin, constraint.Plugin)
						case datapathplugins.PrepareHooksResponse_HookSpec_OrderingConstraint_AFTER:
							hooksSpec.hook(hook.Target, hook.Type).after(plugin, constraint.Plugin)
						}
					}
				}
			}
			spec, err := testprogs.LoadPlugins()
			require.NoError(t, err)
			loadHooksRequests, err := hooksSpec.instrumentCollection(spec)
			require.NoError(t, err)
			if diff := cmp.Diff(
				tc.expectLoadHooksRequests,
				loadHooksRequests,
				cmpopts.IgnoreUnexported(
					datapathplugins.LoadHooksRequest{},
					datapathplugins.LoadHooksRequest_Hook{},
					datapathplugins.LoadHooksRequest_Hook_AttachTarget{},
				),
				cmpopts.SortMaps(func(a, b string) bool {
					return a < b
				}),
				cmpopts.SortSlices(func(a, b *datapathplugins.LoadHooksRequest_Hook) bool {
					return a.Target < b.Target
				}),
			); diff != "" {
				t.Errorf("loadHooksRequests did not match what was expected (-want +got):\n%s", diff)
			}
			// var objs testprogs.PluginsObjects
			// err = spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{})
			// require.NoError(t, err)
			// objs.Close()
		})
	}
}
