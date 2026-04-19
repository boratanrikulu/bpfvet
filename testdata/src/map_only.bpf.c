// Simple tracepoint program with only map operations. No kernel struct access.
// Expected: 0 CO-RE relocations, 0 KERNEL-DIRECT, 0 warnings.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);
	__type(value, __u64);
} counts SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_read")
int count_reads(void *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	__u64 *val = bpf_map_lookup_elem(&counts, &pid);
	if (val) {
		__sync_fetch_and_add(val, 1);
	} else {
		__u64 one = 1;
		bpf_map_update_elem(&counts, &pid, &one, BPF_ANY);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
