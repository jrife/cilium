// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package status

import (
	"fmt"
	"iter"
	"maps"
	"slices"
	"text/tabwriter"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive"
	"github.com/cilium/hive/script"
	"github.com/cilium/statedb"
	"github.com/cilium/statedb/index"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/api/v1/datapathplugins"
)

const (
	PluginHookStatusTableName = "pluginhooks"
)

type CollectionHookStatus struct {
	AttachmentContext *datapathplugins.AttachmentContext
	Programs          map[string]*ProgramHookStatus
}

func (c *CollectionHookStatus) OrderedTargetNames() iter.Seq[string] {
	return func(yield func(string) bool) {
		targetNames := slices.Collect(maps.Keys(c.Programs))
		slices.Sort(targetNames)

		for _, targetName := range targetNames {
			if !yield(targetName) {
				return
			}
		}
	}
}

type ProgramHookStatus struct {
	ID    ebpf.ProgramID
	Hooks map[datapathplugins.HookType]map[string]*HookInfo
}

func (p *ProgramHookStatus) OrderedHookTypes() iter.Seq[datapathplugins.HookType] {
	return func(yield func(datapathplugins.HookType) bool) {
		hookTypes := slices.Collect(maps.Keys(p.Hooks))
		slices.Sort(hookTypes)

		for _, hookType := range hookTypes {
			if !yield(hookType) {
				return
			}
		}
	}
}

func (p *ProgramHookStatus) OrderedPlugins(hookType datapathplugins.HookType) iter.Seq[string] {
	return func(yield func(string) bool) {
		pluginNames := slices.Collect(maps.Keys(p.Hooks[hookType]))
		slices.SortFunc(pluginNames, func(a, b string) int {
			return p.Hooks[hookType][a].Position - p.Hooks[hookType][b].Position
		})

		for _, pluginName := range pluginNames {
			if !yield(pluginName) {
				return
			}
		}
	}
}

type HookInfo struct {
	ProgramID   ebpf.ProgramID
	ProgramName string
	Constraints []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint
	Position    int
}

func NewCollectionHookStatus(ac *datapathplugins.AttachmentContext) (*CollectionHookStatus, error) {
	return &CollectionHookStatus{
		AttachmentContext: ac,
		Programs:          make(map[string]*ProgramHookStatus),
	}, nil
}

func (c *CollectionHookStatus) TableHeader() []string {
	return []string{
		"Device",
		"Pod",
		"Instrumented Programs",
	}
}

func (c *CollectionHookStatus) TableRow() []string {
	return []string{
		c.AttachmentContext.GetDevice(),
		c.podNamespaceName(),
		fmt.Sprintf("%d", c.hookCount()),
	}
}

func (c *CollectionHookStatus) podNamespaceName() string {
	if c.AttachmentContext.GetPodInfo().GetNamespace() == "" && c.AttachmentContext.GetPodInfo().GetName() == "" {
		return ""
	}

	return fmt.Sprintf("%s/%s", c.AttachmentContext.GetPodInfo().GetNamespace(), c.AttachmentContext.GetPodInfo().GetName())
}

func (c *CollectionHookStatus) hookCount() int {
	var hookCount int

	for _, targetHooksInfo := range c.Programs {
		for _, hooks := range targetHooksInfo.Hooks {
			hookCount += len(hooks)
		}
	}

	return hookCount
}

func (c *CollectionHookStatus) RecordHook(target string, hookType datapathplugins.HookType, plugin string, constraints []*datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint) {
	if c.Programs[target] == nil {
		c.Programs[target] = &ProgramHookStatus{
			Hooks: map[datapathplugins.HookType]map[string]*HookInfo{},
		}
	}

	if c.Programs[target].Hooks[hookType] == nil {
		c.Programs[target].Hooks[hookType] = map[string]*HookInfo{}
	}

	c.Programs[target].Hooks[hookType][plugin] = &HookInfo{
		Constraints: constraints,
	}
}

func (c *CollectionHookStatus) RecordHookOrder(target string, hookType datapathplugins.HookType, plugins []string) error {
	if c.Programs[target] == nil {
		return fmt.Errorf("unknown target %s", target)
	}

	if c.Programs[target].Hooks[hookType] == nil {
		return fmt.Errorf("unknown hook type %s for target %s", hookType, target)
	}

	for i, p := range plugins {
		if c.Programs[target].Hooks[hookType][p] == nil {
			return fmt.Errorf("unknown plugin %s for hook type %s at target %s", p, hookType, target)
		}

		c.Programs[target].Hooks[hookType][p].Position = i
	}

	return nil
}

func (c *CollectionHookStatus) RecordTargetProgramIDs(coll *ebpf.Collection) error {
	for name, state := range c.Programs {
		prog := coll.Programs[name]
		if prog == nil {
			return fmt.Errorf("program %s does not exist", name)
		}

		info, err := prog.Info()
		if err != nil {
			return fmt.Errorf("getting program info for %s: %w", name, err)
		}

		id, avail := info.ID()
		if !avail {
			return fmt.Errorf("getting program ID for %s: %w", name, err)
		}

		state.ID = ebpf.ProgramID(id)
	}

	return nil
}

func (c *CollectionHookStatus) RecordHookProgramID(target string, hookType datapathplugins.HookType, plugin string, prog *ebpf.Program) error {
	if c.Programs[target] == nil {
		return fmt.Errorf("unknown target %s", target)
	}

	if c.Programs[target].Hooks[hookType] == nil {
		return fmt.Errorf("unknown hook type %s for target %s", hookType, target)
	}

	if c.Programs[target].Hooks[hookType][plugin] == nil {
		return fmt.Errorf("unknown plugin %s for hook type %s at target %s", plugin, hookType, target)
	}

	info, err := prog.Info()
	if err != nil {
		return fmt.Errorf("getting hook program info: %w", err)
	}

	id, avail := info.ID()
	if !avail {
		return fmt.Errorf("getting hook program ID: %w", err)
	}

	c.Programs[target].Hooks[hookType][plugin].ProgramID = id
	c.Programs[target].Hooks[hookType][plugin].ProgramName = info.Name

	return nil
}

var (
	acIndex = statedb.Index[*CollectionHookStatus, string]{
		Name: "attachment-context",
		FromObject: func(c *CollectionHookStatus) index.KeySet {
			return index.NewKeySet(index.String(c.AttachmentContext.CollectionKey()))
		},
		FromKey:    index.String,
		FromString: index.FromString,
		Unique:     true,
	}
)

func NewCollectionHookStatuses(db *statedb.DB) (*CollectionHookStatuses, error) {
	collHookStatuses, err := statedb.NewTable(
		db,
		PluginHookStatusTableName,
		acIndex,
	)
	if err != nil {
		return nil, err
	}

	return &CollectionHookStatuses{
		db:                     db,
		collectionHookStatuses: collHookStatuses,
	}, nil
}

type CollectionHookStatuses struct {
	db                     *statedb.DB
	collectionHookStatuses statedb.RWTable[*CollectionHookStatus]
}

func (c *CollectionHookStatuses) Upsert(collHookStatus *CollectionHookStatus) error {
	wtxn := c.db.WriteTxn(c.collectionHookStatuses)
	c.collectionHookStatuses.Insert(wtxn, collHookStatus)
	wtxn.Commit()

	return nil
}

func (c *CollectionHookStatuses) Purge(ac *datapathplugins.AttachmentContext) error {
	collHookStatus, err := NewCollectionHookStatus(ac)
	if err != nil {
		return err
	}

	wtxn := c.db.WriteTxn(c.collectionHookStatuses)
	c.collectionHookStatuses.Delete(wtxn, collHookStatus)
	wtxn.Commit()

	return nil
}

func (c *CollectionHookStatuses) All() iter.Seq[*CollectionHookStatus] {
	return func(yield func(*CollectionHookStatus) bool) {
		for collHookStatus, _ := range c.collectionHookStatuses.All(c.db.ReadTxn()) {
			if !yield(collHookStatus) {
				return
			}
		}
	}
}

const (
	deviceNameFlag        = "device"
	podNamespaceFlag      = "namespace"
	podNameFlag           = "pod"
	targetProgramFlag     = "target"
	hookTypeFlag          = "type"
	pluginNameFlag        = "plugin"
	pluginProgramNameFlag = "program"
)

func BindHookStatusFlags(fs *pflag.FlagSet) {
	fs.String(deviceNameFlag, "", "Filter by device name")
	fs.String(podNamespaceFlag, "", "Filter by pod namespace")
	fs.String(podNameFlag, "", "Filter by pod name")
	fs.String(targetProgramFlag, "", "Filter by target program name")
	fs.String(hookTypeFlag, "", "Filter by hook type (PRE, POST)")
	fs.String(pluginNameFlag, "", "Filter by plugin name")
	fs.String(pluginProgramNameFlag, "", "Filter by hook program name")
}

func hooksStatusCommand(summary string, valueColumnName string, collHookStatuses *CollectionHookStatuses, values func(map[string]*HookInfo, string) iter.Seq[string]) script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: summary,
			Flags: func(fs *pflag.FlagSet) {
				fs.String(deviceNameFlag, "", "Filter by device name")
				fs.String(podNamespaceFlag, "", "Filter by pod namespace")
				fs.String(podNameFlag, "", "Filter by pod name")
				fs.String(targetProgramFlag, "", "Filter by target program name")
				fs.String(hookTypeFlag, "", "Filter by hook type (PRE, POST)")
				fs.String(pluginNameFlag, "", "Filter by plugin name")
				fs.String(pluginProgramNameFlag, "", "Filter by hook program name")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			deviceNameFilter, err := s.Flags.GetString(deviceNameFlag)
			if err != nil {
				return nil, err
			}
			podNamespaceFilter, err := s.Flags.GetString(podNamespaceFlag)
			if err != nil {
				return nil, err
			}
			podNameFilter, err := s.Flags.GetString(podNameFlag)
			if err != nil {
				return nil, err
			}
			targetProgramFilter, err := s.Flags.GetString(targetProgramFlag)
			if err != nil {
				return nil, err
			}
			hookTypeFilter, err := s.Flags.GetString(hookTypeFlag)
			if err != nil {
				return nil, err
			}
			pluginNameFilter, err := s.Flags.GetString(pluginNameFlag)
			if err != nil {
				return nil, err
			}
			pluginProgramNameFilter, err := s.Flags.GetString(pluginProgramNameFlag)
			if err != nil {
				return nil, err
			}

			tw := tabwriter.NewWriter(s.LogWriter(), 5, 0, 3, ' ', 0)

			fmt.Fprintf(tw, "DEVICE\tPOD\tTARGET\tHOOK TYPE\t%s\n", valueColumnName)

			for collHookStatus := range collHookStatuses.All() {
				if deviceNameFilter != "" && collHookStatus.AttachmentContext.GetDevice() != deviceNameFilter {
					continue
				}
				if podNamespaceFilter != "" && collHookStatus.AttachmentContext.GetPodInfo().GetNamespace() != podNamespaceFilter {
					continue
				}
				if podNameFilter != "" && collHookStatus.AttachmentContext.GetPodInfo().GetName() != podNameFilter {
					continue
				}

				deviceStr := collHookStatus.AttachmentContext.GetDevice()
				podStr := collHookStatus.podNamespaceName()

				for targetName := range collHookStatus.OrderedTargetNames() {
					if targetProgramFilter != "" && targetName != targetProgramFilter {
						continue
					}

					targetHookInfo := collHookStatus.Programs[targetName]
					targetProgramInfoStr := fmt.Sprintf("%s (%d)", targetName, targetHookInfo.ID)

					for hookType := range targetHookInfo.OrderedHookTypes() {
						if hookTypeFilter != "" && hookType.String() != hookTypeFilter {
							continue
						}

						hookTypeStr := fmt.Sprintf("%s", hookType)

						for pluginName := range targetHookInfo.OrderedPlugins(hookType) {
							hook := targetHookInfo.Hooks[hookType][pluginName]
							if pluginNameFilter != "" && pluginName != pluginNameFilter {
								continue
							}
							if pluginProgramNameFilter != "" && hook.ProgramName != pluginProgramNameFilter {
								continue
							}

							for v := range values(targetHookInfo.Hooks[hookType], pluginName) {
								fmt.Fprintf(
									tw, "%s\t%s\t%s\t%s\t%s\n",
									deviceStr,
									podStr,
									targetProgramInfoStr,
									hookTypeStr,
									v,
								)

								deviceStr = ""
								podStr = ""
								targetProgramInfoStr = ""
								hookTypeStr = ""
							}
						}
					}
				}
			}

			tw.Flush()

			return nil, nil
		},
	)
}

func hooksListCommand(collHookStatuses *CollectionHookStatuses) script.Cmd {
	return hooksStatusCommand(
		"List active datapath plugin hooks in attachment order",
		"HOOKS",
		collHookStatuses,
		func(hooks map[string]*HookInfo, pluginName string) iter.Seq[string] {
			return func(yield func(string) bool) {
				yield(fmt.Sprintf("%s:%s (%d)", pluginName, hooks[pluginName].ProgramName, hooks[pluginName].ProgramID))
			}
		},
	)
}

func hooksOrderCommand(collHookStatuses *CollectionHookStatuses) script.Cmd {
	return hooksStatusCommand(
		"Explain the order of active datapath plugin hooks",
		"ORDERING CONSTRAINTS",
		collHookStatuses,
		func(hooks map[string]*HookInfo, pluginName string) iter.Seq[string] {
			program := fmt.Sprintf("%s:%s (%d)", pluginName, hooks[pluginName].ProgramName, hooks[pluginName].ProgramID)

			return func(yield func(string) bool) {
				if len(hooks[pluginName].Constraints) == 0 {
					yield(fmt.Sprintf("%s has no constraints", program))
				}

				for _, c := range hooks[pluginName].Constraints {
					var otherProgram string

					if h := hooks[c.GetPlugin()]; h == nil {
						otherProgram = fmt.Sprintf("%s:? (?)", c.GetPlugin())
					} else {
						otherProgram = fmt.Sprintf("%s:%s (%d)", c.GetPlugin(), h.ProgramName, h.ProgramID)
					}

					var explanation string

					switch c.GetOrder() {
					case datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_BEFORE:
						explanation = fmt.Sprintf("%s is before %s", program, otherProgram)
					case datapathplugins.PrepareCollectionResponse_HookSpec_OrderingConstraint_AFTER:
						explanation = fmt.Sprintf("%s is after %s", program, otherProgram)
					default:
						explanation = fmt.Sprintf("%s has an unknown constraint", program)
					}

					if !yield(explanation) {
						return
					}
				}
			}
		},
	)
}

func PluginsStatusCommands(collHookStatuses *CollectionHookStatuses) hive.ScriptCmdsOut {
	return hive.NewScriptCmds(map[string]script.Cmd{
		"plugins/hooks/list":  hooksListCommand(collHookStatuses),
		"plugins/hooks/order": hooksOrderCommand(collHookStatuses),
	})
}
