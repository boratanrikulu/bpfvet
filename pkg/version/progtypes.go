package version

import "github.com/cilium/ebpf"

// Sourced from https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md
var ProgTypeVersion = map[ebpf.ProgramType]KernelVersion{
	ebpf.SocketFilter:          V(3, 19),
	ebpf.Kprobe:                V(4, 1),
	ebpf.SchedCLS:              V(4, 1),
	ebpf.SchedACT:              V(4, 1),
	ebpf.TracePoint:            V(4, 7),
	ebpf.XDP:                   V(4, 8),
	ebpf.PerfEvent:             V(4, 9),
	ebpf.CGroupSKB:             V(4, 10),
	ebpf.CGroupSock:            V(4, 10),
	ebpf.LWTIn:                 V(4, 10),
	ebpf.LWTOut:                V(4, 10),
	ebpf.LWTXmit:               V(4, 10),
	ebpf.SockOps:               V(4, 13),
	ebpf.SkSKB:                 V(4, 14),
	ebpf.CGroupDevice:          V(4, 15),
	ebpf.SkMsg:                 V(4, 17),
	ebpf.RawTracepoint:         V(4, 17),
	ebpf.CGroupSockAddr:        V(4, 17),
	ebpf.LWTSeg6Local:          V(4, 18),
	ebpf.LircMode2:             V(4, 18),
	ebpf.SkReuseport:           V(4, 19),
	ebpf.FlowDissector:         V(4, 20),
	ebpf.CGroupSysctl:          V(5, 2),
	ebpf.RawTracepointWritable: V(5, 2),
	ebpf.CGroupSockopt:         V(5, 3),
	ebpf.Tracing:               V(5, 5),
	ebpf.StructOps:             V(5, 6),
	ebpf.Extension:             V(5, 6),
	ebpf.LSM:                   V(5, 7),
	ebpf.SkLookup:              V(5, 9),
	ebpf.Syscall:               V(5, 14),
	ebpf.Netfilter:             V(6, 4),
}

// LookupProgType returns the kernel version for a program type.
func LookupProgType(pt ebpf.ProgramType) (KernelVersion, bool) {
	v, ok := ProgTypeVersion[pt]
	return v, ok
}
