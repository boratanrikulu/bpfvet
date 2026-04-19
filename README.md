# bpfvet

BPF portability analyzer for compiled eBPF object files.

Takes a `.bpf.o` and tells you: what kernel version you need, what helpers and maps you depend on, how data flows between kernel and userspace, and whether your CO-RE usage is correct.

Works on compiled ELF, not source code. Language-agnostic - C, Rust, Go, Zig all produce BPF ELF with BTF.

## Quick start

```bash
go install github.com/boratanrikulu/bpfvet/cmd/bpfvet@latest
bpfvet program.bpf.o
```

## Example output

```
$ bpfvet program.bpf.o

Minimum kernel: 5.8
License: GPL
BTF: yes, CO-RE relocations: 2 (vmlinux.h likely used)
Data flow: kernel -> userspace via RingBuf

Kernel Requirements:
  bpf_ringbuf_output     -> 5.8+
  bpf_probe_read_kernel  -> 5.5+
  bpf_get_current_task   -> 4.8+
  Kprobe program type    -> 4.1+

Maps:
  events  RingBuf  key=0B val=0B max=262144  (5.8+)

Programs:
  my_probe (kprobe/do_sys_openat2, Kprobe, 29 insns)
```

## Multiple files

Analyze multiple variants side by side. Useful for projects that compile different versions for different kernel tiers:

```
$ bpfvet *.bpf.o

==> good_core.bpf.o <==
Minimum kernel: 5.8
...

==> map_only.bpf.o <==
Minimum kernel: 4.7
...

=============================
Summary
=============================
  good_core.bpf.o                          5.8+
  map_only.bpf.o                           4.7+

Minimum kernel version (all files): 5.8
```

## Portability warnings

When a program accesses kernel structs without CO-RE relocations, bpfvet flags it:

```
$ bpfvet trace.bpf.o

Minimum kernel: 5.8
License: GPL
BTF: yes, CO-RE relocations: 0 (vmlinux.h may not be used)

WARNINGS:
  ERROR trace.bpf.c:24  Direct access to kernel struct field at offset 1496
    Use BPF_CORE_READ() for portability across kernel versions

Programs:
  bad_probe (kprobe/do_sys_openat2, Kprobe, 11 insns)
    Memory accesses: 1 total (1 KERNEL-DIRECT)
```

> Note: programs built with vmlinux.h (which includes `preserve_access_index` on all kernel structs) get automatic CO-RE relocations even for direct field access like `task->pid`. This warning only fires for programs using manually defined structs without CO-RE attributes.

## What it analyzes

- **Minimum kernel version** - computed from helpers, program types, and map types
- **Kernel helpers** - each helper mapped to its introduction version
- **Program types** - kprobe (4.1+), sock_ops (4.13+), LSM (5.7+), etc.
- **Map types** - RingBuf (5.8+), LRUHash (4.10+), PerfEventArray (4.3+), etc.
- **BTF and CO-RE** - BTF presence, CO-RE relocation count, vmlinux.h usage hint
- **Data flow** - how the program ships data to userspace (PerfEventArray, RingBuf, shared maps)
- **Memory access classification** - CO-RE protected, context, map-value, kernel-direct, uncategorized
- **License** - extracted from the BPF object

## CLI

```bash
bpfvet program.bpf.o              # text report
bpfvet --json program.bpf.o       # JSON (for CI)
bpfvet --verbose program.bpf.o    # per-program helper details
bpfvet *.bpf.o                    # multi-file with summary
```

## CI

Use `--json` to enforce kernel version targets in CI pipelines. See [docs/ci.md](docs/ci.md) for GitHub Actions, GitLab CI, and Makefile examples.

```bash
bpfvet --json program.bpf.o | jq -e '.minKernel == "5.4"'
```

## How it works

Parses BPF ELF using [cilium/ebpf](https://github.com/cilium/ebpf). Only reads the ELF - never loads into the kernel. Runs on macOS, Linux, and Windows without root.

## Building from source

Requires Go 1.24+.

```bash
git clone https://github.com/boratanrikulu/bpfvet.git && cd bpfvet
make build
./bin/bpfvet program.bpf.o
```

## Roadmap

- [x] Minimum kernel version from helpers, program types, map types
- [x] CO-RE relocation counting and memory access classification
- [x] BTF presence detection with vmlinux.h hint
- [x] Data flow detection (PerfEventArray, RingBuf, maps)
- [x] Non-CO-RE kernel struct access detection
- [x] Source line mapping via BTF
- [x] License reporting
- [x] JSON output for CI
- [x] Multi-file analysis with summary
- [ ] Deprecated helper warnings (`bpf_probe_read` -> `bpf_probe_read_kernel`)
- [ ] License + GPL-only helper cross-check
- [ ] Exit with error when issues found (for CI)
- [ ] GitHub Action

## License

MIT. See [LICENSE](LICENSE).

Copyright (c) 2026 Bora Tanrikulu \<me@bora.sh\>
