// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package statsquery

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/cilium/cilium/pkg/bpf/statsquery/types"
	"github.com/cilium/cilium/pkg/time"
)

// AttachedProgInfo stores the attachment details of a BPF program.
type AttachedProgInfo struct {
	IfaceIndex int
	IfaceName  string
	AttachType ebpf.AttachType
}

// GetAttachedPrograms lists all BPF programs attached to network interfaces.
func GetAttachedPrograms() (map[ebpf.ProgramID]AttachedProgInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to list network interfaces: %w", err)
	}

	attachTypes := []ebpf.AttachType{
		ebpf.AttachTCXIngress, ebpf.AttachTCXEgress,
		ebpf.AttachXDP,
		ebpf.AttachNetkitPrimary, ebpf.AttachNetkitPeer,
	}

	progMap := make(map[ebpf.ProgramID]AttachedProgInfo)

	for _, iface := range ifaces {
		for _, at := range attachTypes {
			res, err := link.QueryPrograms(link.QueryOptions{
				Target: iface.Index,
				Attach: at,
			})
			if err != nil {
				continue
			}
			for _, prog := range res.Programs {
				progMap[prog.ID] = AttachedProgInfo{
					IfaceIndex: iface.Index,
					IfaceName:  iface.Name,
					AttachType: at,
				}
			}
		}
	}

	return progMap, nil
}

// queryPrograms collects stats for BPF programs.
func queryPrograms(epMap map[int]string, targetIfindexes map[int]struct{}, iterateAll bool) ([]types.BpfProgramStats, error) {
	progs, err := GetAttachedPrograms()
	if err != nil {
		return nil, fmt.Errorf("failed to get attached programs: %w", err)
	}
	type attachInfo struct {
		ifaceName string
		podName   string
	}

	progAttachMap := make(map[ebpf.ProgramID]attachInfo)
	for id, info := range progs {
		if !iterateAll && targetIfindexes != nil {
			if _, found := targetIfindexes[info.IfaceIndex]; !found {
				continue
			}
		}
		podName, isPod := epMap[info.IfaceIndex]
		ai := attachInfo{
			ifaceName: info.IfaceName,
		}
		if isPod {
			ai.podName = podName
		}
		progAttachMap[id] = ai
	}

	var res []types.BpfProgramStats

	appendResult := func(prog *ebpf.Program, id ebpf.ProgramID) {
		info, err := prog.Info()
		if err != nil {
			return
		}

		if !strings.HasPrefix(info.Name, "cil_") ||
			strings.HasPrefix(info.Name, "cil_lxc_policy") ||
			strings.HasPrefix(info.Name, "cil_host_policy") {
			return
		}

		stats, err := prog.Stats()
		if err != nil {
			return
		}

		pInfo := types.BpfProgramStats{
			ID:           id,
			Name:         info.Name,
			Type:         info.Type.String(),
			TotalRuns:    stats.RunCount,
			TotalRuntime: stats.Runtime,
		}

		if attach, found := progAttachMap[id]; found {
			pInfo.IfaceName = attach.ifaceName
			pInfo.PodName = attach.podName
		}

		res = append(res, pInfo)
	}

	if !iterateAll {
		for id := range progAttachMap {
			prog, err := ebpf.NewProgramFromID(id)
			if err != nil {
				continue
			}
			appendResult(prog, id)
			prog.Close()
		}
	} else {
		var id ebpf.ProgramID
		for {
			id, err = ebpf.ProgramGetNextID(id)
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			if err != nil {
				return nil, fmt.Errorf("failed to get next program ID: %w", err)
			}

			prog, err := ebpf.NewProgramFromID(id)
			if err != nil {
				continue
			}

			appendResult(prog, id)
			prog.Close()
		}
	}

	return res, nil
}

// QueryProgramStats queries BPF programs and maps them to BpfProgramStats.
func QueryProgramStats(epMap map[int]string, targetIfindexes map[int]struct{}, iterateAll bool, cgroupOnly bool, programs []string) ([]types.BpfProgramStats, error) {
	rawInfos, err := queryPrograms(epMap, targetIfindexes, iterateAll)
	if err != nil {
		return nil, err
	}

	stats := make([]types.BpfProgramStats, 0, len(rawInfos))
	for _, info := range rawInfos {
		attachment := ""
		if info.PodName != "" {
			attachment = info.PodName
		} else if info.IfaceName != "" {
			attachment = fmt.Sprintf("(host:%s)", info.IfaceName)
		} else {
			attachment = "cgroup:root"
		}

		if cgroupOnly && attachment != "cgroup:root" {
			continue
		}

		if len(programs) > 0 && !matchesAny(info.Type, programs) {
			continue
		}

		if info.TotalRuns > 0 {
			info.AvgLatencyNs = info.TotalRuntime / time.Duration(info.TotalRuns)
		}
		info.Attachment = attachment

		stats = append(stats, info)
	}

	return stats, nil
}

func matchesAny(name string, filters []string) bool {
	for _, f := range filters {
		if strings.Contains(strings.ToLower(name), strings.ToLower(f)) {
			return true
		}
	}
	return false
}
