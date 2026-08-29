// mayhem/go_runtime_ready.c — libFuzzer init-ordering shim for the Go c-archive targets.
//
// Same fix as savantenvs/cert-manager (QA #1118, HARNESS-20): all 4 binaries build.sh produces
// (the fuzz targets /mayhem/fuzz_bucketconfig and /mayhem/FuzzExprSelect, and test.sh's KAT
// probes /mayhem/kfp_bucketconfig_kat and /mayhem/kfp_exprselect_kat) are Go
// -buildmode=c-archive archives (go-118-fuzz-build) linked into libFuzzer with clang++, and
// go-118-fuzz-build defines no LLVMFuzzerInitialize (build.sh fails if this shim is missing). In
// a c-archive the Go runtime starts ASYNCHRONOUSLY on its own thread from a load-time
// constructor, and Go's runtime/libfuzzer.go init() registers the Go coverage counters with
// libFuzzer from THAT thread while libFuzzer's main thread may already be clearing them
// (TracePC::ClearInlineCounters). When the two overlap the binary SEGVs inside libFuzzer before
// any input runs, or starts with no coverage counters registered.
//
// libFuzzer calls LLVMFuzzerInitialize first thing in FuzzerDriver, before it touches any
// coverage module. Blocking here until the Go runtime has finished its init tasks (which include
// the counter registration) makes the ordering deterministic. This is the same wait the cgo
// export wrapper of LLVMFuzzerTestOneInput performs on its first call from C; we only move it
// earlier. No input is executed, no target code runs, and no signal or crash is intercepted.
#include <stdint.h>

// Go runtime/cgo (gcc_libinit.c / gcc_context.c), exported by every cgo-enabled Go c-archive.
extern uintptr_t _cgo_wait_runtime_init_done(void);
extern void _cgo_release_context(uintptr_t ctxt);

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc;
  (void)argv;
  _cgo_release_context(_cgo_wait_runtime_init_done());
  return 0;
}
