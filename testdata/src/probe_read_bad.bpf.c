// Uses bpf_probe_read with direct kernel struct pointer (non-CO-RE).
// Expected: KERNEL-DIRECT > 0, bpf_probe_read warning.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct task_struct_raw {
	int pad[374];
	int pid;
	int tgid;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int probe_read_bad(struct pt_regs *ctx)
{
	struct task_struct_raw *task = (struct task_struct_raw *)bpf_get_current_task();

	// wrong - direct access without CO-RE
	__u32 pid = task->pid;

	// also using deprecated bpf_probe_read
	__u32 tgid;
	bpf_probe_read(&tgid, sizeof(tgid), &task->tgid);

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &pid, sizeof(pid));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
