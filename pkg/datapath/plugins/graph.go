package plugins

import (
	"errors"
	"fmt"

	"github.com/cilium/cilium/api/v1/datapathplugins"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func preHookSubprogName(pluginName string) string {
	return fmt.Sprintf("__pre_hook_%s__", pluginName)
}

func postHookSubprogName(pluginName string) string {
	return fmt.Sprintf("__post_hook_%s__", pluginName)
}

type HooksSpec struct {
	hooks map[string]map[datapathplugins.HookType]*pluginDependencyGraph
}

func newHooksSpec() *HooksSpec {
	return &HooksSpec{
		hooks: make(map[string]map[datapathplugins.HookType]*pluginDependencyGraph),
	}
}

func (hs *HooksSpec) hook(target string, hookType datapathplugins.HookType) *pluginDependencyGraph {
	if hs.hooks[target] == nil {
		hs.hooks[target] = map[datapathplugins.HookType]*pluginDependencyGraph{
			datapathplugins.HookType_PRE:  &pluginDependencyGraph{},
			datapathplugins.HookType_POST: &pluginDependencyGraph{},
		}
	}

	return hs.hooks[target][hookType]
}

func (hs *HooksSpec) instrumentCollection(cs *ebpf.CollectionSpec) (map[string]*datapathplugins.LoadHooksRequest, error) {
	var err error
	hooks := make(map[string]*datapathplugins.LoadHooksRequest)

	for hookTarget, hookTypes := range hs.hooks {
		pre, sortErr := hookTypes[datapathplugins.HookType_PRE].sort()
		if sortErr != nil {
			err = errors.Join(err, fmt.Errorf("%s/%s: %w", hookTarget, datapathplugins.HookType_PRE, sortErr))
			continue
		}
		post, sortErr := hookTypes[datapathplugins.HookType_POST].sort()
		if sortErr != nil {
			err = errors.Join(err, fmt.Errorf("%s/%s: %w", hookTarget, datapathplugins.HookType_POST, sortErr))
			continue
		}

		if err := hs.instrumentProgram(cs.Programs[hookTarget], pre, post, hooks); err != nil {
			err = errors.Join(err, fmt.Errorf("instrumenting %s: %w", hookTarget, err))
			continue
		}
	}

	return hooks, err
}

func (hs *HooksSpec) instrumentProgram(ps *ebpf.ProgramSpec, pre []string, post []string, hooks map[string]*datapathplugins.LoadHooksRequest) error {
	btfMeta := btf.FuncMetadata(&ps.Instructions[0])
	funcProto, hasFuncProto := btfMeta.Type.(*btf.FuncProto)
	if !hasFuncProto {
		return fmt.Errorf("unable to extract function BTF info for target program")
	}

	var dispatcherInstructions []asm.Instruction

	// Preserve ctx in R6, callee saved register.
	asm.Mov.Reg(asm.R6, asm.R1)

	for _, plugin := range pre {
		subprogName := preHookSubprogName(plugin)
		dispatcherInstructions = append(dispatcherInstructions,
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Call.Label(subprogName),
			asm.JNE.Imm(asm.R0, -1, "return"),
		)
		hooks[plugin].Hooks = append(hooks[plugin].Hooks, &datapathplugins.LoadHooksRequest_Hook{
			AttachTarget: &datapathplugins.LoadHooksRequest_Hook_AttachTarget{
				SubprogName: subprogName,
			},
			Type:   datapathplugins.HookType_PRE,
			Target: ps.Name,
		})
	}

	dispatcherInstructions = append(dispatcherInstructions,
		asm.Mov.Reg(asm.R1, asm.R6),
		asm.Call.Label(btfMeta.Name),
		asm.Mov.Reg(asm.R7, asm.R0),
	)

	for _, plugin := range post {
		subprogName := postHookSubprogName(plugin)
		dispatcherInstructions = append(dispatcherInstructions,
			asm.Mov.Reg(asm.R1, asm.R6),
			asm.Mov.Reg(asm.R2, asm.R7),
			asm.Call.Label(subprogName),
			asm.JNE.Imm(asm.R0, -1, "return"),
		)
		hooks[plugin].Hooks = append(hooks[plugin].Hooks, &datapathplugins.LoadHooksRequest_Hook{
			AttachTarget: &datapathplugins.LoadHooksRequest_Hook_AttachTarget{
				SubprogName: subprogName,
			},
			Type:   datapathplugins.HookType_POST,
			Target: ps.Name,
		})
	}

	dispatcherInstructions = append(dispatcherInstructions,
		asm.Mov.Reg(asm.R0, asm.R7),
		asm.Return().WithSymbol("return"),
	)

	postHookProto := *funcProto
	postHookProto.Params = append(
		append([]btf.FuncParam(nil), postHookProto.Params...),
		btf.FuncParam{Name: "ret", Type: funcProto.Return},
	)

	for _, plugin := range pre {
		hookName := preHookSubprogName(plugin)
		dispatcherInstructions = append(dispatcherInstructions,
			btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol(hookName), &btf.Func{
				Name: hookName,
				Type: funcProto,
				// BTF_FUNC_GLOBAL ensures programs are independently verified.
				Linkage: btf.GlobalFunc,
			}),
			asm.Return(),
		)
	}
	for _, plugin := range post {
		hookName := postHookSubprogName(plugin)
		dispatcherInstructions = append(dispatcherInstructions,
			btf.WithFuncMetadata(asm.Mov.Imm(asm.R0, 0).WithSymbol(hookName), &btf.Func{
				Name: hookName,
				Type: &postHookProto,
				// BTF_FUNC_GLOBAL ensures programs are independently verified.
				Linkage: btf.GlobalFunc,
			}),
			asm.Return(),
		)
	}
	ps.Instructions[0] = ps.Instructions[0].WithSymbol(btfMeta.Name)
	dispatcherInstructions = append(dispatcherInstructions, ps.Instructions...)

	return nil
}

type node struct {
	exists        bool
	outgoing      map[string]struct{}
	incomingCount int
}

type pluginDependencyGraph map[string]*node

func (g pluginDependencyGraph) sort() ([]string, error) {
	var empty []string
	sorted := make([]string, 0, len(g))

	for p, n := range g {
		if n.incomingCount == 0 {
			empty = append(empty, p)
		}
	}

	for len(empty) > 0 {
		batchSize := len(empty)

		for i := 0; i < batchSize; i++ {
			sorted = append(sorted, empty[0])

			for after := range g[empty[0]].outgoing {
				g[after].incomingCount--

				if g[after].incomingCount == 0 {
					empty = append(empty, after)
				}
			}

			empty = empty[1:]
		}
	}

	if len(g) > 0 {
		return nil, fmt.Errorf("cycle detected")
	}

	return sorted, nil
}

func (g pluginDependencyGraph) lazyInitNode(name string) {
	if g[name] == nil {
		g[name] = &node{
			outgoing: map[string]struct{}{},
		}
	}
}

func (g pluginDependencyGraph) addNode(name string) {
	if g[name] == nil {
		g[name] = &node{}
	}

	g[name].exists = true
}

func (g pluginDependencyGraph) before(a, b string) {
	g.after(b, a)
}

func (g pluginDependencyGraph) after(a, b string) {
	if g[a] == nil {
		g[a] = &node{}
	}

	g[a].outgoing[b] = struct{}{}
}
