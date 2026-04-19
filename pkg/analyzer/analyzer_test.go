package analyzer

import (
	"testing"

	"github.com/boratanrikulu/bpfvet/pkg/report"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestCamelToSnake(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"RingbufOutput", "ringbuf_output"},
		{"MapLookupElem", "map_lookup_elem"},
		{"GetCurrentPidTgid", "get_current_pid_tgid"},
		{"XdpAdjustHead", "xdp_adjust_head"},
		{"Setsockopt", "setsockopt"},
	}
	for _, tt := range tests {
		if got := camelToSnake(tt.in); got != tt.want {
			t.Errorf("camelToSnake(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestHelperName(t *testing.T) {
	tests := []struct {
		fn   asm.BuiltinFunc
		want string
	}{
		{asm.FnRingbufOutput, "bpf_ringbuf_output"},
		{asm.FnMapLookupElem, "bpf_map_lookup_elem"},
		{asm.FnSetsockopt, "bpf_setsockopt"},
		{asm.FnGetCurrentTask, "bpf_get_current_task"},
	}
	for _, tt := range tests {
		if got := helperName(tt.fn); got != tt.want {
			t.Errorf("helperName(%v) = %q, want %q", tt.fn, got, tt.want)
		}
	}
}

// TestAnalyzeDirectKernelAccess tests a synthetic program that accesses a kernel struct
// without CO-RE - simulates: task = bpf_get_current_task(); pid = task->pid;
func TestAnalyzeDirectKernelAccess(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"bad_prog": {
				Name:        "bad_prog",
				Type:        ebpf.Kprobe,
				SectionName: "kprobe/sys_enter",
				Instructions: asm.Instructions{
					// r0 = bpf_get_current_task()
					asm.FnGetCurrentTask.Call(),
					// r6 = r0  (save task pointer)
					asm.Mov.Reg(asm.R6, asm.R0),
					// r1 = *(u32 *)(r6 + 8)  - direct struct access, NO CO-RE!
					{
						OpCode: asm.LoadMemOp(asm.Word),
						Dst:    asm.R1,
						Src:    asm.R6,
						Offset: 8, // hardcoded offset to task->pid
					},
					// exit 0
					asm.Mov.Imm(asm.R0, 0),
					asm.Return(),
				},
			},
		},
	}

	r, err := AnalyzeSpec(spec)
	if err != nil {
		t.Fatalf("AnalyzeSpec: %v", err)
	}

	// Should detect the non-CO-RE kernel struct access.
	if len(r.Warnings) == 0 {
		t.Fatal("expected warnings for non-CO-RE kernel struct access")
	}

	w := r.Warnings[0]
	if w.Severity != report.SeverityError {
		t.Errorf("severity = %s, want error", w.Severity)
	}
	if w.Program != "bad_prog" {
		t.Errorf("program = %s, want bad_prog", w.Program)
	}

	// Memory access summary should show kernel-direct.
	prog := r.Programs[0]
	if prog.MemoryAccesses.KernelDirect != 1 {
		t.Errorf("kernel-direct = %d, want 1", prog.MemoryAccesses.KernelDirect)
	}
	if prog.MemoryAccesses.COREProtected != 0 {
		t.Errorf("CO-RE protected = %d, want 0", prog.MemoryAccesses.COREProtected)
	}
}

// TestAnalyzeSafe tests a synthetic program that only accesses context and
// map values - should produce zero warnings.
func TestAnalyzeSafe(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"safe_prog": {
				Name:        "safe_prog",
				Type:        ebpf.XDP,
				SectionName: "xdp",
				Instructions: asm.Instructions{
					// r2 = *(u32 *)(r1 + 0)  - context access (xdp_md->data)
					{
						OpCode: asm.LoadMemOp(asm.Word),
						Dst:    asm.R2,
						Src:    asm.R1,
						Offset: 0,
					},
					// r3 = *(u32 *)(r1 + 4)  - context access (xdp_md->data_end)
					{
						OpCode: asm.LoadMemOp(asm.Word),
						Dst:    asm.R3,
						Src:    asm.R1,
						Offset: 4,
					},
					// exit XDP_PASS
					asm.Mov.Imm(asm.R0, 2),
					asm.Return(),
				},
			},
		},
	}

	r, err := AnalyzeSpec(spec)
	if err != nil {
		t.Fatalf("AnalyzeSpec: %v", err)
	}

	if len(r.Warnings) != 0 {
		for _, w := range r.Warnings {
			t.Errorf("unexpected warning: %s", w.Message)
		}
	}

	prog := r.Programs[0]
	if prog.MemoryAccesses.ContextSafe != 2 {
		t.Errorf("context-safe = %d, want 2", prog.MemoryAccesses.ContextSafe)
	}
	if prog.MemoryAccesses.KernelDirect != 0 {
		t.Errorf("kernel-direct = %d, want 0", prog.MemoryAccesses.KernelDirect)
	}
}

// TestAnalyzeMapValueSafe tests that map lookup return values are classified as safe.
func TestAnalyzeMapValueSafe(t *testing.T) {
	spec := &ebpf.CollectionSpec{
		Programs: map[string]*ebpf.ProgramSpec{
			"map_prog": {
				Name:        "map_prog",
				Type:        ebpf.XDP,
				SectionName: "xdp",
				Instructions: asm.Instructions{
					// r0 = bpf_map_lookup_elem(...)
					asm.FnMapLookupElem.Call(),
					// r6 = r0  (save map value pointer)
					asm.Mov.Reg(asm.R6, asm.R0),
					// r1 = *(u64 *)(r6 + 0)  - map value access (safe)
					{
						OpCode: asm.LoadMemOp(asm.DWord),
						Dst:    asm.R1,
						Src:    asm.R6,
						Offset: 0,
					},
					// exit
					asm.Mov.Imm(asm.R0, 0),
					asm.Return(),
				},
			},
		},
	}

	r, err := AnalyzeSpec(spec)
	if err != nil {
		t.Fatalf("AnalyzeSpec: %v", err)
	}

	if len(r.Warnings) != 0 {
		for _, w := range r.Warnings {
			t.Errorf("unexpected warning: %s", w.Message)
		}
	}

	prog := r.Programs[0]
	if prog.MemoryAccesses.MapValueSafe != 1 {
		t.Errorf("map-value-safe = %d, want 1", prog.MemoryAccesses.MapValueSafe)
	}
}
