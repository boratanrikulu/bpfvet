package version

import "github.com/cilium/ebpf"

// Sourced from https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
var MapTypeVersion = map[ebpf.MapType]KernelVersion{
	ebpf.Hash:                V(3, 19),
	ebpf.Array:               V(3, 19),
	ebpf.ProgramArray:        V(4, 2),
	ebpf.PerfEventArray:      V(4, 3),
	ebpf.PerCPUHash:          V(4, 6),
	ebpf.PerCPUArray:         V(4, 6),
	ebpf.StackTrace:          V(4, 6),
	ebpf.CGroupArray:         V(4, 8),
	ebpf.LRUHash:             V(4, 10),
	ebpf.LRUCPUHash:          V(4, 10),
	ebpf.LPMTrie:             V(4, 11),
	ebpf.ArrayOfMaps:         V(4, 12),
	ebpf.HashOfMaps:          V(4, 12),
	ebpf.DevMap:              V(4, 14),
	ebpf.SockMap:             V(4, 14),
	ebpf.CPUMap:              V(4, 15),
	ebpf.XSKMap:              V(4, 18),
	ebpf.SockHash:            V(4, 18),
	ebpf.CGroupStorage:       V(4, 19),
	ebpf.ReusePortSockArray:  V(4, 19),
	ebpf.PerCPUCGroupStorage: V(4, 20),
	ebpf.Queue:               V(4, 20),
	ebpf.Stack:               V(4, 20),
	ebpf.SkStorage:           V(5, 2),
	ebpf.DevMapHash:          V(5, 4),
	ebpf.StructOpsMap:        V(5, 6),
	ebpf.RingBuf:             V(5, 8),
	ebpf.InodeStorage:        V(5, 10),
	ebpf.TaskStorage:         V(5, 11),
}

// LookupMapType returns the kernel version for a map type.
func LookupMapType(mt ebpf.MapType) (KernelVersion, bool) {
	v, ok := MapTypeVersion[mt]
	return v, ok
}
