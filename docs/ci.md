# CI Integration

Use bpfvet in CI to catch kernel version regressions before they reach production. If a PR adds a helper or map type that bumps the minimum kernel, the pipeline fails.

## GitHub Actions

```yaml
name: eBPF Portability Check
on: [push, pull_request]

jobs:
  bpfvet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build BPF
        run: make bpf

      - name: Install bpfvet
        run: |
          curl -L https://github.com/boratanrikulu/bpfvet/releases/latest/download/bpfvet-linux-amd64 -o bpfvet
          chmod +x bpfvet

      - name: Check kernel compatibility
        run: |
          ./bpfvet --json program.bpf.o > report.json
          MIN=$(jq -r '.minKernel' report.json)
          ERRORS=$(jq '.warnings | map(select(.severity == "error")) | length' report.json)

          echo "Minimum kernel: $MIN"
          echo "CO-RE errors: $ERRORS"

          # Fail if minimum kernel exceeds your target
          if [ "$MIN" != "5.4" ]; then
            echo "::error::Minimum kernel changed to $MIN (expected 5.4)"
            ./bpfvet program.bpf.o
            exit 1
          fi

          # Fail on non-CO-RE kernel struct accesses
          if [ "$ERRORS" -gt 0 ]; then
            echo "::error::Found $ERRORS non-CO-RE kernel struct accesses"
            ./bpfvet program.bpf.o
            exit 1
          fi
```

## GitLab CI

```yaml
bpfvet:
  stage: test
  script:
    - make bpf
    - ./bpfvet --json program.bpf.o | jq -e '.minKernel == "5.4"'
```

## Makefile

```makefile
check: build-bpf
	@./bpfvet program.bpf.o
	@echo "---"
	@MIN=$$(./bpfvet --json program.bpf.o | jq -r '.minKernel'); \
	if [ "$$MIN" != "5.4" ]; then \
		echo "ERROR: minimum kernel is $$MIN, expected 5.4"; exit 1; \
	fi
```

## JSON fields for scripting

| Field | Type | Description |
|-------|------|-------------|
| `minKernel` | `string` | Minimum kernel version, e.g. `"5.8"` |
| `coreRelocations` | `int` | Total CO-RE relocations across all programs |
| `warnings` | `array` | Each has `severity` (`"error"` or `"warning"`), `program`, `file`, `line`, `message` |
| `helpers` | `array` | Each has `name` and `version` |
| `progTypes` | `array` | Each has `name` and `version` |
| `maps` | `array` | Each has `name`, `type`, `keySize`, `valueSize`, `maxEntries`, `version` |
| `programs` | `array` | Each has `name`, `type`, `memoryAccesses` breakdown |
