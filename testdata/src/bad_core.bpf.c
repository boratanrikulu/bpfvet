// Bad example: direct kernel struct access without CO-RE.
// This program reads task_struct->pid directly, which breaks
// when the kernel changes task_struct layout between versions.

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct task_struct {
	int pad[374];  // offset 1496 on x86_64 6.x
	int pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int bad_open_probe(struct pt_regs *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	// WRONG — direct access, no BPF_CORE_READ
	__u32 pid = task->pid;

	bpf_ringbuf_output(&events, &pid, sizeof(pid), 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
