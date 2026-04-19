package bpfvet_test

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/boratanrikulu/bpfvet/pkg/analyzer"
	"github.com/boratanrikulu/bpfvet/pkg/report"
)

// TestE2E_GoodCORE tests a proper CO-RE program using vmlinux.h + BPF_CORE_READ.
func TestE2E_GoodCORE(t *testing.T) {
	r := analyzeFixture(t, "testdata/good_core.bpf.o")

	if !r.HasBTF {
		t.Error("expected BTF")
	}
	if r.CORERelocations == 0 {
		t.Error("expected CO-RE relocations")
	}
	if len(r.Warnings) != 0 {
		t.Errorf("expected 0 warnings, got %d", len(r.Warnings))
	}
	if r.Programs[0].MemoryAccesses.KernelDirect != 0 {
		t.Errorf("expected 0 KERNEL-DIRECT, got %d", r.Programs[0].MemoryAccesses.KernelDirect)
	}
	assertTransportContains(t, r, "event streaming via RingBuf")
	assertValidJSON(t, r)
}

// TestE2E_DirectKernelAccess tests direct kernel struct access without CO-RE.
func TestE2E_DirectKernelAccess(t *testing.T) {
	r := analyzeFixture(t, "testdata/direct_access.bpf.o")

	if r.CORERelocations != 0 {
		t.Errorf("expected 0 CO-RE relocations, got %d", r.CORERelocations)
	}
	assertHasError(t, r, "bad_open_probe")
	if r.Programs[0].MemoryAccesses.KernelDirect != 1 {
		t.Errorf("expected 1 KERNEL-DIRECT, got %d", r.Programs[0].MemoryAccesses.KernelDirect)
	}
	assertTransportContains(t, r, "event streaming via RingBuf")
}

// TestE2E_MixedAccess tests a program with both CO-RE and non-CO-RE accesses.
func TestE2E_MixedAccess(t *testing.T) {
	r := analyzeFixture(t, "testdata/mixed_access.bpf.o")

	if r.CORERelocations == 0 {
		t.Error("expected CO-RE relocations for the good access")
	}
	assertHasError(t, r, "mixed_probe")

	m := r.Programs[0].MemoryAccesses
	if m.KernelDirect == 0 {
		t.Error("expected KERNEL-DIRECT for the bad access")
	}
}

// TestE2E_MapOnly tests a program with only map operations, no kernel struct access.
func TestE2E_MapOnly(t *testing.T) {
	r := analyzeFixture(t, "testdata/map_only.bpf.o")

	if r.CORERelocations != 0 {
		t.Errorf("expected 0 CO-RE relocations, got %d", r.CORERelocations)
	}
	if len(r.Warnings) != 0 {
		t.Errorf("expected 0 warnings, got %d", len(r.Warnings))
	}
	if r.Programs[0].MemoryAccesses.KernelDirect != 0 {
		t.Errorf("expected 0 KERNEL-DIRECT, got %d", r.Programs[0].MemoryAccesses.KernelDirect)
	}
	assertTransportContains(t, r, "shared state via maps")

	if r.MinKernel.String() != "4.7" {
		t.Errorf("min kernel = %s, want 4.7", r.MinKernel)
	}
}

// TestE2E_MultiProg tests that warnings are attributed to the correct program.
func TestE2E_MultiProg(t *testing.T) {
	r := analyzeFixture(t, "testdata/multi_prog.bpf.o")

	if len(r.Programs) != 2 {
		t.Fatalf("expected 2 programs, got %d", len(r.Programs))
	}

	// Find each program's report.
	var good, bad *report.ProgramReport
	for i := range r.Programs {
		switch r.Programs[i].Name {
		case "good_prog":
			good = &r.Programs[i]
		case "bad_prog":
			bad = &r.Programs[i]
		}
	}
	if good == nil || bad == nil {
		t.Fatal("expected good_prog and bad_prog")
	}

	if good.MemoryAccesses.KernelDirect != 0 {
		t.Errorf("good_prog: expected 0 KERNEL-DIRECT, got %d", good.MemoryAccesses.KernelDirect)
	}
	if bad.MemoryAccesses.KernelDirect == 0 {
		t.Error("bad_prog: expected KERNEL-DIRECT > 0")
	}

	assertHasError(t, r, "bad_prog")
	assertTransportContains(t, r, "event streaming via PerfEventArray")
}

// TestE2E_ProbeReadBad tests bpf_probe_read with non-CO-RE kernel struct access.
// TestE2E_ProbeReadBad tests bpf_probe_read with direct kernel struct access.
// Min kernel is 4.8 (< 5.5), so no deprecated warning - only KERNEL-DIRECT error.
func TestE2E_ProbeReadBad(t *testing.T) {
	r := analyzeFixture(t, "testdata/probe_read_bad.bpf.o")

	assertHasError(t, r, "probe_read_bad")

	// No deprecated warning because min kernel < 5.5 (bpf_probe_read is the right choice)
	for _, w := range r.Warnings {
		if w.Severity == report.SeverityWarning {
			t.Errorf("unexpected warning: %s", w.Message)
		}
	}

	assertTransportContains(t, r, "event streaming via PerfEventArray")
}

// TestE2E_NestedVmlinux verifies that nested pointer access via vmlinux.h
// gets automatic CO-RE relocations (preserve_access_index).
func TestE2E_NestedVmlinux(t *testing.T) {
	r := analyzeFixture(t, "testdata/nested_vmlinux.bpf.o")

	if r.CORERelocations == 0 {
		t.Error("expected CO-RE relocations from vmlinux.h preserve_access_index")
	}
	if len(r.Warnings) != 0 {
		t.Errorf("expected 0 warnings, got %d", len(r.Warnings))
	}

	prog := r.Programs[0]
	if prog.MemoryAccesses.KernelDirect != 0 {
		t.Errorf("expected 0 KERNEL-DIRECT (vmlinux.h should make it CO-RE), got %d", prog.MemoryAccesses.KernelDirect)
	}
}

// TestE2E_JSONStructure validates JSON fields that CI scripts depend on.
func TestE2E_JSONStructure(t *testing.T) {
	r := analyzeFixture(t, "testdata/good_core.bpf.o")

	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, r); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var doc struct {
		HasBTF          bool   `json:"hasBTF"`
		CORERelocations int    `json:"coreRelocations"`
		MinKernel       string `json:"minKernel"`
		Transport []string `json:"transport"`
		Programs        []struct {
			Name           string `json:"name"`
			MemoryAccesses struct {
				KernelDirect int `json:"kernelDirect"`
			} `json:"memoryAccesses"`
		} `json:"programs"`
		Warnings []struct {
			Severity string `json:"severity"`
		} `json:"warnings"`
		Helpers []struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"helpers"`
		Maps []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"maps"`
	}

	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}

	if !doc.HasBTF {
		t.Error("hasBTF should be true")
	}
	if doc.MinKernel == "" {
		t.Error("minKernel is empty")
	}
	if len(doc.Transport) == 0 {
		t.Error("transport is empty")
	}
	if len(doc.Programs) == 0 {
		t.Error("programs is empty")
	}
	if len(doc.Helpers) == 0 {
		t.Error("helpers is empty")
	}
	if len(doc.Maps) == 0 {
		t.Error("maps is empty")
	}
}

// helpers

func analyzeFixture(t *testing.T, path string) *report.Report {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("fixture not found: %v", err)
	}
	defer f.Close()

	r, err := analyzer.Analyze(f)
	if err != nil {
		t.Fatalf("Analyze(%s): %v", path, err)
	}
	return r
}

func assertHasError(t *testing.T, r *report.Report, progName string) {
	t.Helper()
	for _, w := range r.Warnings {
		if w.Severity == report.SeverityError && w.Program == progName {
			return
		}
	}
	t.Errorf("expected ERROR warning for program %s", progName)
}

func assertTransportContains(t *testing.T, r *report.Report, substr string) {
	t.Helper()
	for _, flow := range r.Transport {
		if contains(flow, substr) {
			return
		}
	}
	t.Errorf("expected data flow containing %q, got %v", substr, r.Transport)
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && containsStr(s, sub))
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func assertValidJSON(t *testing.T, r *report.Report) {
	t.Helper()
	var buf bytes.Buffer
	if err := report.WriteJSON(&buf, r); err != nil {
		t.Errorf("WriteJSON failed: %v", err)
		return
	}
	var decoded map[string]any
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Errorf("invalid JSON: %v", err)
	}
}
