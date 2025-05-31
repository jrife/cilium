package loader

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/datapath/bpf"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

func instrumentExitPoints(logger *slog.Logger, spec *ebpf.CollectionSpec) error {
	fmt.Printf("exit point instrumentation\n")
	eo, err := bpf.LoadExitsObjects()
	if err != nil {
		return fmt.Errorf("loading exit program: %w", err)
	}

	exitHandler := eo.ExitHandler
	for i := 0; i < len(exitHandler.Instructions); i++ {
		exitHandler.Instructions[i] = btf.WithFuncMetadata(exitHandler.Instructions[i], nil)
	}

	for _, prog := range spec.Programs {
		for i := 0; i < len(prog.Instructions); i++ {
			insn := prog.Instructions[i]

			if insn.OpCode.JumpOp() == asm.Exit {
				if i == len(prog.Instructions)-1 {
					prog.Instructions = prog.Instructions[:i]
				} else {
					prog.Instructions[i] = asm.Ja.Imm(0, 0, "exit_prelude")
				}
			}
		}

		prog.Instructions = append(prog.Instructions, asm.Mov.Reg(asm.R1, asm.R0).WithSymbol("exit_prelude"))
		prog.Instructions = append(prog.Instructions, exitHandler.Instructions...)
	}

	spec.Maps[eo.CiliumReturn.Name] = eo.CiliumReturn

	return nil
}
