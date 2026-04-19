package analyzer

import (
	"fmt"
	"io"
	"sort"

	"github.com/boratanrikulu/bpfvet/pkg/report"
	"github.com/boratanrikulu/bpfvet/pkg/version"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
)

// Analyze parses a BPF ELF from the given reader and produces a Report.
func Analyze(r io.ReaderAt) (*report.Report, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(r)
	if err != nil {
		return nil, fmt.Errorf("load collection spec: %w", err)
	}
	return AnalyzeSpec(spec)
}

// AnalyzeSpec analyzes a CollectionSpec directly.
func AnalyzeSpec(spec *ebpf.CollectionSpec) (*report.Report, error) {
	var (
		rpt         report.Report
		helpersSeen = make(map[asm.BuiltinFunc]bool)
		ptSeen      = make(map[ebpf.ProgramType]bool)
		maxVersion  version.KernelVersion
	)

	rpt.HasBTF = spec.Types != nil

	// License is the same across all programs, take from first.
	for _, prog := range spec.Programs {
		if prog.License != "" {
			rpt.License = prog.License
			break
		}
	}

	mapNames := make([]string, 0, len(spec.Maps))
	for name := range spec.Maps {
		mapNames = append(mapNames, name)
	}
	sort.Strings(mapNames)
	for _, name := range mapNames {
		m := spec.Maps[name]
		v, _ := version.LookupMapType(m.Type)
		rpt.Maps = append(rpt.Maps, report.MapInfo{
			Name:       name,
			Type:       m.Type.String(),
			KeySize:    m.KeySize,
			ValueSize:  m.ValueSize,
			MaxEntries: m.MaxEntries,
			Version:    v,
		})
		if maxVersion.Less(v) {
			maxVersion = v
		}
	}

	names := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		prog := spec.Programs[name]
		pr, warnings := analyzeProgram(name, prog, helpersSeen)
		rpt.Programs = append(rpt.Programs, pr)
		rpt.Warnings = append(rpt.Warnings, warnings...)
		rpt.CORERelocations += pr.CORERelocs

		if !ptSeen[prog.Type] {
			ptSeen[prog.Type] = true
		}
	}

	for fn := range helpersSeen {
		v, ok := version.LookupHelper(fn)
		if !ok {
			v = version.V(0, 0)
		}
		rpt.Helpers = append(rpt.Helpers, report.HelperRequirement{
			Name:    helperName(fn),
			Version: v,
		})
		if maxVersion.Less(v) {
			maxVersion = v
		}
	}
	sort.Slice(rpt.Helpers, func(i, j int) bool {
		return rpt.Helpers[j].Version.Less(rpt.Helpers[i].Version)
	})

	for pt := range ptSeen {
		v, ok := version.LookupProgType(pt)
		if !ok {
			v = version.V(0, 0)
		}
		rpt.ProgTypes = append(rpt.ProgTypes, report.ProgTypeRequirement{
			Name:    pt.String(),
			Version: v,
		})
		if maxVersion.Less(v) {
			maxVersion = v
		}
	}
	sort.Slice(rpt.ProgTypes, func(i, j int) bool {
		return rpt.ProgTypes[j].Version.Less(rpt.ProgTypes[i].Version)
	})

	rpt.DataFlow = detectDataFlow(rpt.Maps, helpersSeen)
	rpt.MinKernel = maxVersion
	rpt.Warnings = append(rpt.Warnings, checkDeprecatedHelpers(helpersSeen, maxVersion)...)

	return &rpt, nil
}

// Sourced from https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
// and https://docs.kernel.org/bpf/helpers.html
func checkDeprecatedHelpers(helpers map[asm.BuiltinFunc]bool, minKernel version.KernelVersion) []report.Warning {
	var warnings []report.Warning

	// bpf_probe_read / bpf_probe_read_str (4.1) -> kernel/user variants (5.5)
	usesOld := helpers[asm.FnProbeRead] || helpers[asm.FnProbeReadStr]
	usesModern := helpers[asm.FnProbeReadKernel] || helpers[asm.FnProbeReadUser] ||
		helpers[asm.FnProbeReadKernelStr] || helpers[asm.FnProbeReadUserStr]

	if usesOld {
		if usesModern {
			warnings = append(warnings, report.Warning{
				Severity: report.SeverityWarning,
				Message:  "bpf_probe_read/bpf_probe_read_str are deprecated, migrate remaining calls to kernel/user variants",
				Detail:   "Program already uses the modern variants but still has deprecated calls",
			})
		} else if !minKernel.Less(version.V(5, 5)) {
			warnings = append(warnings, report.Warning{
				Severity: report.SeverityWarning,
				Message:  "bpf_probe_read/bpf_probe_read_str are deprecated on 5.5+, use bpf_probe_read_kernel or bpf_probe_read_user",
			})
		}
	}

	// bpf_perf_event_read (4.8) -> bpf_perf_event_read_value (4.15)
	if helpers[asm.FnPerfEventRead] {
		if helpers[asm.FnPerfEventReadValue] {
			warnings = append(warnings, report.Warning{
				Severity: report.SeverityWarning,
				Message:  "bpf_perf_event_read is superseded by bpf_perf_event_read_value, migrate remaining calls",
			})
		} else if !minKernel.Less(version.V(4, 15)) {
			warnings = append(warnings, report.Warning{
				Severity: report.SeverityWarning,
				Message:  "bpf_perf_event_read is superseded, use bpf_perf_event_read_value (4.15+)",
				Detail:   "Old helper has ABI issues where error and counter value ranges overlap",
			})
		}
	}

	// bpf_get_current_task (4.8) -> bpf_get_current_task_btf (5.11)
	if helpers[asm.FnGetCurrentTask] && !helpers[asm.FnGetCurrentTaskBtf] {
		if !minKernel.Less(version.V(5, 11)) {
			warnings = append(warnings, report.Warning{
				Severity: report.SeverityWarning,
				Message:  "consider bpf_get_current_task_btf (5.11+) for direct CO-RE field access",
				Detail:   "BTF variant returns a typed pointer, no BPF_CORE_READ needed",
			})
		}
	}

	return warnings
}

func detectDataFlow(maps []report.MapInfo, helpers map[asm.BuiltinFunc]bool) []string {
	var flows []string

	hasPerf := false
	hasRingBuf := false
	hasDataMaps := false

	for _, m := range maps {
		switch m.Type {
		case "PerfEventArray":
			hasPerf = true
		case "RingBuf":
			hasRingBuf = true
		case "Hash", "LRUHash", "PerCPUHash", "Array", "PerCPUArray", "LPMTrie":
			// skip internal sections
			if m.Name != ".bss" && m.Name != ".rodata" && m.Name != ".rodata.str1.1" && m.Name != ".data" {
				hasDataMaps = true
			}
		}
	}

	if hasRingBuf {
		flows = append(flows, "kernel -> userspace via RingBuf")
	}
	if hasPerf {
		flows = append(flows, "kernel -> userspace via PerfEventArray")
	}
	if hasDataMaps {
		flows = append(flows, "shared state via maps")
	}

	return flows
}

type regOrigin uint8

const (
	regUnknown   regOrigin = iota
	regContext             // R1 at entry, program context struct (safe)
	regMapValue            // return from bpf_map_lookup_elem etc. (safe)
	regKernelPtr           // return from bpf_get_current_task etc. (needs CO-RE)
)

var helpersReturningKernelPtrs = map[asm.BuiltinFunc]bool{
	asm.FnGetCurrentTask:       true,
	asm.FnGetCurrentTaskBtf:    true,
	asm.FnTaskPtRegs:           true,
	asm.FnSkcToTcpSock:         true,
	asm.FnSkcToTcp6Sock:        true,
	asm.FnSkcToUdp6Sock:        true,
	asm.FnSkcToTcpTimewaitSock: true,
	asm.FnSkcToTcpRequestSock:  true,
	asm.FnSkcToUnixSock:        true,
	asm.FnSkcToMptcpSock:       true,
	asm.FnTcpSock:              true,
	asm.FnSkFullsock:           true,
	asm.FnGetListenerSock:      true,
	asm.FnSkcLookupTcp:         true,
	asm.FnSkLookupTcp:          true,
	asm.FnSkLookupUdp:          true,
	asm.FnSockFromFile:         true,
}

var helpersReturningMapValues = map[asm.BuiltinFunc]bool{
	asm.FnMapLookupElem:       true,
	asm.FnMapLookupPercpuElem: true,
	asm.FnSkStorageGet:        true,
	asm.FnInodeStorageGet:     true,
	asm.FnTaskStorageGet:      true,
	asm.FnCgrpStorageGet:      true,
	asm.FnGetLocalStorage:     true,
	asm.FnRingbufReserve:      true,
}

func analyzeProgram(name string, prog *ebpf.ProgramSpec, helpersSeen map[asm.BuiltinFunc]bool) (report.ProgramReport, []report.Warning) {
	pr := report.ProgramReport{
		Name:        name,
		SectionName: prog.SectionName,
		Type:        prog.Type.String(),
		NumInsns:    len(prog.Instructions),
	}

	coreOffsets := make(map[int]bool)
	var regs [11]regOrigin
	stackSlots := map[int16]regOrigin{}
	regs[1] = regContext

	var warnings []report.Warning

	for i := range prog.Instructions {
		ins := &prog.Instructions[i]

		if btf.CORERelocationMetadata(ins) != nil {
			pr.CORERelocs++
			coreOffsets[i] = true
		}

		if ins.IsBuiltinCall() {
			trackHelperCall(ins, helpersSeen, &pr, &regs)
			continue
		}

		trackRegisterState(ins, &regs, stackSlots)

		if !isMemoryLoad(ins) || ins.Src == asm.R10 {
			if isStackLoad(ins) && ins.Dst <= 10 {
				restoreStackOrigin(ins, &regs, stackSlots)
			}
			continue
		}

		classifyAccess(ins, i, name, coreOffsets, &regs, &pr, &warnings)
	}

	return pr, warnings
}

func trackHelperCall(ins *asm.Instruction, helpersSeen map[asm.BuiltinFunc]bool, pr *report.ProgramReport, regs *[11]regOrigin) {
	fn := asm.BuiltinFunc(ins.Constant)
	if fn != asm.FnUnspec {
		helpersSeen[fn] = true
		if v, ok := version.LookupHelper(fn); ok {
			pr.Helpers = append(pr.Helpers, report.HelperRequirement{
				Name:    helperName(fn),
				Version: v,
			})
		}
	}

	switch {
	case helpersReturningKernelPtrs[fn]:
		regs[0] = regKernelPtr
	case helpersReturningMapValues[fn]:
		regs[0] = regMapValue
	default:
		regs[0] = regUnknown
	}
	for r := 1; r <= 5; r++ {
		regs[r] = regUnknown
	}
}

func trackRegisterState(ins *asm.Instruction, regs *[11]regOrigin, stackSlots map[int16]regOrigin) {
	// mov dst, src
	if ins.OpCode == asm.Mov.Op(asm.RegSource) && ins.Src <= 10 && ins.Dst <= 10 {
		regs[ins.Dst] = regs[ins.Src]
		return
	}

	// ALU64 (add, sub, etc.) preserves pointer origin.
	// BPF semantics: one operand is pointer, other is scalar.
	if ins.OpCode.Class() == asm.ALU64Class && ins.Dst <= 10 {
		return
	}

	// Stack spill: STX to R10
	if ins.OpCode.Class() == asm.StXClass && ins.Dst == asm.R10 && ins.Src <= 10 {
		if origin := regs[ins.Src]; origin != regUnknown {
			stackSlots[ins.Offset] = origin
		}
	}
}

func isMemoryLoad(ins *asm.Instruction) bool {
	return ins.OpCode.Class() == asm.LdXClass
}

func isStackLoad(ins *asm.Instruction) bool {
	return ins.OpCode.Class() == asm.LdXClass && ins.Src == asm.R10
}

func restoreStackOrigin(ins *asm.Instruction, regs *[11]regOrigin, stackSlots map[int16]regOrigin) {
	if origin, ok := stackSlots[ins.Offset]; ok {
		regs[ins.Dst] = origin
	} else {
		regs[ins.Dst] = regUnknown
	}
}

func classifyAccess(ins *asm.Instruction, idx int, progName string, coreOffsets map[int]bool, regs *[11]regOrigin, pr *report.ProgramReport, warnings *[]report.Warning) {
	pr.MemoryAccesses.Total++

	if coreOffsets[idx] {
		pr.MemoryAccesses.COREProtected++
		return
	}

	srcOrigin := regUnknown
	if ins.Src <= 10 {
		srcOrigin = regs[ins.Src]
	}

	switch srcOrigin {
	case regContext:
		pr.MemoryAccesses.ContextSafe++
	case regMapValue:
		pr.MemoryAccesses.MapValueSafe++
	case regKernelPtr:
		pr.MemoryAccesses.KernelDirect++
		warn := report.Warning{
			Severity: report.SeverityError,
			Program:  progName,
			Message:  fmt.Sprintf("Direct access to kernel struct field at offset %d", ins.Offset),
			Detail:   "Use BPF_CORE_READ() for portability across kernel versions",
		}
		if source := ins.Source(); source != nil {
			if line, ok := source.(*btf.Line); ok {
				warn.File = line.FileName()
				warn.Line = line.LineNumber()
			}
		}
		*warnings = append(*warnings, warn)
	default:
		pr.MemoryAccesses.Uncategorized++
	}
}

func helperName(fn asm.BuiltinFunc) string {
	s := fn.String()
	if len(s) > 2 && s[:2] == "Fn" {
		s = s[2:]
	}
	return "bpf_" + camelToSnake(s)
}

func camelToSnake(s string) string {
	var result []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			if i > 0 {
				result = append(result, '_')
			}
			result = append(result, c+'a'-'A')
		} else {
			result = append(result, c)
		}
	}
	return string(result)
}
