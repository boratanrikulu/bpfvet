package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/boratanrikulu/bpfvet/pkg/version"
)

func testReport() *Report {
	return &Report{
		HasBTF: true,
		Programs: []ProgramReport{
			{
				Name:        "my_prog",
				SectionName: "kprobe/sys_enter",
				Type:        "Kprobe",
				NumInsns:    50,
				CORERelocs:  3,
				Helpers: []HelperRequirement{
					{Name: "bpf_ringbuf_output", Version: version.V(5, 8)},
					{Name: "bpf_get_current_pid_tgid", Version: version.V(4, 2)},
				},
				MemoryAccesses: MemoryAccessSummary{
					Total:         10,
					COREProtected: 3,
					ContextSafe:   2,
					MapValueSafe:  3,
					KernelDirect:  1,
					Uncategorized: 1,
				},
			},
		},
		Warnings: []Warning{
			{
				Severity: SeverityError,
				Program:  "my_prog",
				File:     "prog.bpf.c",
				Line:     42,
				Message:  "Direct access to kernel struct field at offset 8",
				Detail:   "Use BPF_CORE_READ() for portability across kernel versions",
			},
		},
		Helpers: []HelperRequirement{
			{Name: "bpf_ringbuf_output", Version: version.V(5, 8)},
			{Name: "bpf_get_current_pid_tgid", Version: version.V(4, 2)},
		},
		ProgTypes: []ProgTypeRequirement{
			{Name: "Kprobe", Version: version.V(4, 1)},
		},
		CORERelocations: 3,
		MinKernel:       version.V(5, 8),
	}
}

func TestWriteText(t *testing.T) {
	var buf bytes.Buffer
	r := testReport()

	if err := WriteText(&buf, r, false); err != nil {
		t.Fatal(err)
	}

	out := buf.String()

	mustContain := []string{
		"Minimum kernel: 5.8",
		"BTF: yes, CO-RE relocations: 3 (vmlinux.h likely used)",
		"WARNINGS:",
		"ERROR prog.bpf.c:42",
		"Direct access to kernel struct field at offset 8",
		"BPF_CORE_READ()",
		"bpf_ringbuf_output",
		"5.8+",
		"Kprobe program type",
		"4.1+",
		"Programs:",
		"10 total",
		"3 CO-RE",
		"1 KERNEL-DIRECT",
	}
	for _, s := range mustContain {
		if !strings.Contains(out, s) {
			t.Errorf("output missing %q\n\nGot:\n%s", s, out)
		}
	}
}

func TestWriteTextVerbose(t *testing.T) {
	var buf bytes.Buffer
	r := testReport()

	if err := WriteText(&buf, r, true); err != nil {
		t.Fatal(err)
	}

	out := buf.String()
	if !strings.Contains(out, "Programs:") {
		t.Error("verbose output should contain Programs section")
	}
	if !strings.Contains(out, "my_prog") {
		t.Error("verbose output should contain program name")
	}
	// Verbose shows per-program helpers
	if !strings.Contains(out, "helper: bpf_ringbuf_output") {
		t.Errorf("verbose output should contain per-program helpers\n\nGot:\n%s", out)
	}
}

func TestWriteJSON(t *testing.T) {
	var buf bytes.Buffer
	r := testReport()

	if err := WriteJSON(&buf, r); err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n\nGot:\n%s", err, buf.String())
	}

	if decoded["minKernel"] != "5.8" {
		t.Errorf("minKernel = %v, want \"5.8\"", decoded["minKernel"])
	}

	coreRelocs, ok := decoded["coreRelocations"].(float64)
	if !ok || int(coreRelocs) != 3 {
		t.Errorf("coreRelocations = %v, want 3", decoded["coreRelocations"])
	}
}
