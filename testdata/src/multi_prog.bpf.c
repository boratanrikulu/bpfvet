// Multiple programs in one file: one uses CO-RE, one doesn't.
// Expected: warnings only for bad_prog, not good_prog.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct task_struct_raw {
	int pad[374];
	int pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int good_prog(struct pt_regs *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 pid = BPF_CORE_READ(task, pid);
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &pid, sizeof(pid));
	return 0;
}

SEC("kprobe/do_sys_openat2")
int bad_prog(struct pt_regs *ctx)
{
	struct task_struct_raw *task = (struct task_struct_raw *)bpf_get_current_task();
	__u32 pid = task->pid;
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &pid, sizeof(pid));
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
