// Nested kernel struct access via vmlinux.h without BPF_CORE_READ.
// Verifies that preserve_access_index makes this CO-RE automatically.
// Expected: CO-RE relocations > 0, 0 KERNEL-DIRECT, 0 warnings.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/do_sys_openat2")
int nested_vmlinux(struct pt_regs *ctx)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	// no BPF_CORE_READ, but vmlinux.h makes it CO-RE anyway
	struct mm_struct *mm = task->mm;
	__u64 pgd = (__u64)mm->pgd;

	bpf_ringbuf_output(&events, &pgd, sizeof(pgd), 0);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
