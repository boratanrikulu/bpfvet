// Mixed CO-RE: one access uses BPF_CORE_READ (via vmlinux.h), the other
// uses a manual struct without preserve_access_index.
// Expected: CO-RE relocations > 0, KERNEL-DIRECT > 0, ERROR warning.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Manual struct without preserve_access_index - accesses won't be CO-RE.
struct task_struct_raw {
	int pad[374];
	int pid;
	int tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int mixed_probe(struct pt_regs *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	// correct - CO-RE via vmlinux.h preserve_access_index
	__u32 pid = BPF_CORE_READ(task, pid);

	// wrong - cast to raw struct, hardcoded offset, no CO-RE
	struct task_struct_raw *raw = (struct task_struct_raw *)task;
	__u32 tgid = raw->tgid;

	__u64 val = ((__u64)tgid << 32) | pid;
	bpf_ringbuf_output(&events, &val, sizeof(val), 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
