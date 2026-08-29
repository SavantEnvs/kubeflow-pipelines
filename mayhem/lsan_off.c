// mayhem/lsan_off.c — build-time LeakSanitizer off-switch (SPEC §6.2 item 15, PORTING.md).
// Linked into all 4 ASan-linked binaries build.sh produces: the fuzz targets
// /mayhem/fuzz_bucketconfig and /mayhem/FuzzExprSelect, and test.sh's KAT probes
// /mayhem/kfp_bucketconfig_kat and /mayhem/kfp_exprselect_kat (build.sh fails if the symbol is
// missing from any of them). ASan's memory-error checks stay fully active; only the
// at-exit leak scan is disabled. Leak detection is not the bug class this fleet fuzzes for, and
// the Go heap is invisible to LSan, so cgo blocks reachable only from Go memory would otherwise
// be reported as leaks.
int __lsan_is_turned_off(void) { return 1; }
