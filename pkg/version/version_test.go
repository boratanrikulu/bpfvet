package version

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestKernelVersionString(t *testing.T) {
	tests := []struct {
		v    KernelVersion
		want string
	}{
		{V(5, 8), "5.8"},
		{V(4, 1), "4.1"},
		{V(3, 18), "3.18"},
	}
	for _, tt := range tests {
		if got := tt.v.String(); got != tt.want {
			t.Errorf("V(%d,%d).String() = %q, want %q", tt.v.Major, tt.v.Minor, got, tt.want)
		}
	}
}

func TestKernelVersionLess(t *testing.T) {
	tests := []struct {
		a, b KernelVersion
		want bool
	}{
		{V(4, 1), V(5, 0), true},
		{V(5, 0), V(4, 1), false},
		{V(5, 1), V(5, 8), true},
		{V(5, 8), V(5, 1), false},
		{V(5, 8), V(5, 8), false},
	}
	for _, tt := range tests {
		if got := tt.a.Less(tt.b); got != tt.want {
			t.Errorf("%s.Less(%s) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestKernelVersionMarshalJSON(t *testing.T) {
	v := V(5, 8)
	got, err := v.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `"5.8"` {
		t.Errorf("MarshalJSON() = %s, want %q", got, "5.8")
	}
}

func TestLookupHelper(t *testing.T) {
	v, ok := LookupHelper(asm.FnRingbufOutput)
	if !ok {
		t.Fatal("FnRingbufOutput not found")
	}
	if v != V(5, 8) {
		t.Errorf("FnRingbufOutput = %s, want 5.8", v)
	}

	v, ok = LookupHelper(asm.FnMapLookupElem)
	if !ok {
		t.Fatal("FnMapLookupElem not found")
	}
	if v != V(3, 18) {
		t.Errorf("FnMapLookupElem = %s, want 3.18", v)
	}

	_, ok = LookupHelper(asm.FnUnspec)
	if ok {
		t.Error("FnUnspec should not be in map")
	}
}

func TestLookupProgType(t *testing.T) {
	v, ok := LookupProgType(ebpf.SockOps)
	if !ok {
		t.Fatal("SockOps not found")
	}
	if v != V(4, 13) {
		t.Errorf("SockOps = %s, want 4.13", v)
	}

	v, ok = LookupProgType(ebpf.LSM)
	if !ok {
		t.Fatal("LSM not found")
	}
	if v != V(5, 7) {
		t.Errorf("LSM = %s, want 5.7", v)
	}
}

func TestLookupMapType(t *testing.T) {
	v, ok := LookupMapType(ebpf.RingBuf)
	if !ok {
		t.Fatal("RingBuf not found")
	}
	if v != V(5, 8) {
		t.Errorf("RingBuf = %s, want 5.8", v)
	}

	v, ok = LookupMapType(ebpf.LRUHash)
	if !ok {
		t.Fatal("LRUHash not found")
	}
	if v != V(4, 10) {
		t.Errorf("LRUHash = %s, want 4.10", v)
	}
}
