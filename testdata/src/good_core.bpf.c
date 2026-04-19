// Proper CO-RE usage: BPF_CORE_READ for kernel struct access.
// Expected: CO-RE relocations > 0, 0 KERNEL-DIRECT, 0 warnings.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int good_probe(struct pt_regs *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	__u32 pid = BPF_CORE_READ(task, pid);
	__u32 tgid = BPF_CORE_READ(task, tgid);

	__u64 val = ((__u64)tgid << 32) | pid;
	bpf_ringbuf_output(&events, &val, sizeof(val), 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
