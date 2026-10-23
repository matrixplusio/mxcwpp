//go:build linux

package collector

// Generate Go bindings from BPF C source using bpf2go.
//
// Prerequisites (on the Linux build machine):
//   - clang >= 11 (for BPF target)
//   - libbpf headers (bpf/bpf_helpers.h, bpf/bpf_tracing.h, bpf/bpf_core_read.h)
//     Install: apt install libbpf-dev  OR  dnf install libbpf-devel
//   - go install github.com/cilium/ebpf/cmd/bpf2go@latest
//
// Run:
//   cd internal/agent/edr/collector && go generate ./...
//
// Output:
//   process_bpfel.go  / process_bpfel.o   (little-endian: amd64, arm64)
//   process_bpfeb.go  / process_bpfeb.o   (big-endian: s390x, mips — rare)
//   file_bpfel.go     / file_bpfel.o
//   file_bpfeb.go     / file_bpfeb.o
//
// The generated Go files embed the compiled BPF bytecode and provide
// type-safe loading functions (loadProcessObjects, loadFileObjects, etc.).

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type process_event process bpf/process.c -- -I bpf -Wall -Werror -O2 -g -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type file_event file bpf/file.c -- -I bpf -Wall -Werror -O2 -g -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type network_event network bpf/network.c -- -I bpf -Wall -Werror -O2 -g -D__TARGET_ARCH_x86
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel,bpfeb -type privilege_event privilege bpf/privilege.c -- -I bpf -Wall -Werror -O2 -g -D__TARGET_ARCH_x86
