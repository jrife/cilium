package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

type ExitsObjects struct {
	ExitHandler  *ebpf.ProgramSpec `ebpf:"exit_handler"`
	CiliumReturn *ebpf.MapSpec     `ebpf:"cilium_return"`
}

func LoadExitsObjects() (*ExitsObjects, error) {
	var eo ExitsObjects

	spec, err := loadExits()
	if err != nil {
		return nil, fmt.Errorf("loading collection: %w", err)
	}

	if err := spec.Assign(&eo); err != nil {
		return nil, fmt.Errorf("assigning collection: %w", err)
	}

	return &eo, nil
}
