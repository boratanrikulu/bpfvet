package report

import (
	"encoding/json"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/boratanrikulu/bpfvet/pkg/version"
)

// Severity indicates the importance of a warning.
type Severity string

const (
	SeverityWarning Severity = "warning"
	SeverityError   Severity = "error"
)

// Warning represents a portability issue found during analysis.
type Warning struct {
	Severity Severity `json:"severity"`
	Program  string   `json:"program"`
	File     string   `json:"file,omitempty"`
	Line     uint32   `json:"line,omitempty"`
	Message  string   `json:"message"`
	Detail   string   `json:"detail,omitempty"`
}

// Report is the complete analysis result for a BPF object file.
type Report struct {
	MinKernel       version.KernelVersion `json:"minKernel"`
	License         string                `json:"license"`
	HasBTF          bool                  `json:"hasBTF"`
	CORERelocations int                   `json:"coreRelocations"`
	Transport       []string              `json:"transport"`
	Programs        []ProgramReport       `json:"programs"`
	Maps            []MapInfo             `json:"maps"`
	Helpers         []HelperRequirement   `json:"helpers"`
	ProgTypes       []ProgTypeRequirement `json:"progTypes"`
	Warnings        []Warning             `json:"warnings"`
}

// MapInfo describes a BPF map defined in the object file.
type MapInfo struct {
	Name       string                `json:"name"`
	Type       string                `json:"type"`
	KeySize    uint32                `json:"keySize"`
	ValueSize  uint32                `json:"valueSize"`
	MaxEntries uint32                `json:"maxEntries"`
	Version    version.KernelVersion `json:"version"`
}

// ProgramReport holds analysis results for a single BPF program.
type ProgramReport struct {
	Name           string              `json:"name"`
	SectionName    string              `json:"sectionName"`
	Type           string              `json:"type"`
	NumInsns       int                 `json:"numInsns"`
	CORERelocs     int                 `json:"coreRelocs"`
	Helpers        []HelperRequirement `json:"helpers"`
	MemoryAccesses MemoryAccessSummary `json:"memoryAccesses"`
}

// MemoryAccessSummary categorizes all non-stack memory loads in a BPF program.
type MemoryAccessSummary struct {
	Total         int `json:"total"`
	COREProtected int `json:"coreProtected"`
	ContextSafe   int `json:"contextSafe"`
	MapValueSafe  int `json:"mapValueSafe"`
	KernelDirect  int `json:"kernelDirect"`
	Uncategorized int `json:"uncategorized"`
}

// HelperRequirement pairs a helper name with its kernel version.
type HelperRequirement struct {
	Name    string                `json:"name"`
	Version version.KernelVersion `json:"version"`
}

// ProgTypeRequirement pairs a program type name with its kernel version.
type ProgTypeRequirement struct {
	Name    string                `json:"name"`
	Version version.KernelVersion `json:"version"`
}

// WriteText renders a human-readable report.
func WriteText(w io.Writer, r *Report, verbose bool) error {
	fmt.Fprintf(w, "Minimum kernel: %s\n", r.MinKernel)
	if r.License != "" {
		fmt.Fprintf(w, "License: %s\n", r.License)
	}

	if !r.HasBTF {
		fmt.Fprintln(w, "BTF: no (CO-RE is not possible without BTF)")
	} else if r.CORERelocations > 0 {
		fmt.Fprintf(w, "BTF: yes, CO-RE relocations: %d (vmlinux.h likely used)\n", r.CORERelocations)
	} else {
		fmt.Fprintln(w, "BTF: yes, CO-RE relocations: 0 (vmlinux.h may not be used)")
	}

	if len(r.Transport) > 0 {
		fmt.Fprintf(w, "Transport: %s\n", joinSlice(r.Transport))
	}

	fmt.Fprintln(w)

	if len(r.Warnings) > 0 {
		fmt.Fprintln(w, "WARNINGS:")
		for _, warn := range r.Warnings {
			prefix := "  "
			if warn.Severity == SeverityError {
				prefix = "  ERROR "
			}
			if warn.File != "" && warn.Line > 0 {
				fmt.Fprintf(w, "%s%s:%d  %s\n", prefix, warn.File, warn.Line, warn.Message)
			} else if warn.Program != "" {
				fmt.Fprintf(w, "%s[%s]  %s\n", prefix, warn.Program, warn.Message)
			} else {
				fmt.Fprintf(w, "%s%s\n", prefix, warn.Message)
			}
			if warn.Detail != "" {
				fmt.Fprintf(w, "    %s\n", warn.Detail)
			}
		}
		fmt.Fprintln(w)
	}

	if len(r.Helpers) > 0 || len(r.ProgTypes) > 0 {
		fmt.Fprintln(w, "Kernel Requirements:")
		tw := tabwriter.NewWriter(w, 2, 0, 2, ' ', 0)
		for _, h := range r.Helpers {
			fmt.Fprintf(tw, "  %s\t-> %s+\n", h.Name, h.Version)
		}
		for _, p := range r.ProgTypes {
			fmt.Fprintf(tw, "  %s program type\t-> %s+\n", p.Name, p.Version)
		}
		tw.Flush()
		fmt.Fprintln(w)
	}

	if len(r.Maps) > 0 {
		fmt.Fprintln(w, "Maps:")
		tw := tabwriter.NewWriter(w, 2, 0, 2, ' ', 0)
		for _, m := range r.Maps {
			vStr := ""
			if m.Version.Major > 0 {
				vStr = fmt.Sprintf("(%s+)", m.Version)
			}
			fmt.Fprintf(tw, "  %s\t%s\tkey=%dB val=%dB max=%d\t%s\n",
				m.Name, m.Type, m.KeySize, m.ValueSize, m.MaxEntries, vStr)
		}
		tw.Flush()
		fmt.Fprintln(w)
	}

	if len(r.Programs) > 0 {
		fmt.Fprintln(w, "Programs:")
		for _, p := range r.Programs {
			m := p.MemoryAccesses
			fmt.Fprintf(w, "  %s (%s, %s, %d insns)\n",
				p.Name, p.SectionName, p.Type, p.NumInsns)
			if m.Total > 0 {
				parts := formatMemoryParts(m)
				fmt.Fprintf(w, "    Memory accesses: %d total (%s)\n", m.Total, joinSlice(parts))
			}
			if verbose {
				for _, h := range p.Helpers {
					fmt.Fprintf(w, "    helper: %s -> %s+\n", h.Name, h.Version)
				}
			}
		}
		fmt.Fprintln(w)
	}

	return nil
}

// WriteJSON renders the report as JSON.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func formatMemoryParts(m MemoryAccessSummary) []string {
	var parts []string
	if m.COREProtected > 0 {
		parts = append(parts, fmt.Sprintf("%d CO-RE", m.COREProtected))
	}
	if m.ContextSafe > 0 {
		parts = append(parts, fmt.Sprintf("%d context", m.ContextSafe))
	}
	if m.MapValueSafe > 0 {
		parts = append(parts, fmt.Sprintf("%d map-value", m.MapValueSafe))
	}
	if m.KernelDirect > 0 {
		parts = append(parts, fmt.Sprintf("%d KERNEL-DIRECT", m.KernelDirect))
	}
	if m.Uncategorized > 0 {
		parts = append(parts, fmt.Sprintf("%d uncategorized", m.Uncategorized))
	}
	return parts
}

func joinSlice(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += ", "
		}
		result += p
	}
	return result
}
