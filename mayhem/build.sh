#!/usr/bin/env bash
#
# mayhem/build.sh — build Kubeflow Pipelines' object-store bucket-URI parser
# (backend/src/v2/objectstore/config.go: ParseBucketPathToConfig, SplitObjectURI,
# the S3/GCS param decoders) and OSS-Fuzz's FuzzExprSelect (backend/src/v2/expression)
# as sanitized libFuzzer binaries (OSS-Fuzz Go path: go-118-fuzz-build c-archive +
# clang++ ASan/libFuzzer link), plus the two known-answer probes mayhem/test.sh runs.
# Each probe lives IN THE SAME Go PACKAGE (same staged directory, same import path)
# as its fuzz target and is built by the same go-118-fuzz-build call and link line;
# only -func and the output name differ. The one thing that does differ is the main
# file go-118-fuzz-build generates (main.*.go, written into its working directory,
# naming the -func function). So go-118-fuzz-build runs OUTSIDE the directory of
# every agent-editable package: a `//go:embed` in config.go (or in any in-tree
# package) cannot see that -func-specific main (embed patterns cannot contain
# `..`). With that, the agent-editable library is compiled ONCE, as one package,
# into both binaries: no build tag, cgo flag, ${SRCDIR}, file set, embedded file or
# package path differs between the graded binary and the oracle, and a patch cannot
# gate code on the fuzz build only at compile time (#1460 A, #1122).
#
# Runs inside the commit image (GO mayhem/Dockerfile) as `mayhem` in /mayhem.
# GOROOT/GOPATH/GOMODCACHE are pinned by the Dockerfile ENV under /opt/toolchains
# (absolute, $HOME-independent — so the offline PATCH re-run finds the cache).
#
# AIR-GAPPED CONTRACT (SPEC §6.5): the PATCH tier re-runs THIS script OFFLINE.
#   - This FIRST build (online) fills $GOMODCACHE (go get of the /testing shim).
#   - GOPROXY points at the in-image module cache's file proxy FIRST, network
#     LAST, so the offline re-run resolves entirely from the cache; GOFLAGS=-mod=mod
#     + GOSUMDB=off keep go.sum verification local (no sum.golang.org round trip).
#
# HARNESS STAGING (netnew §6 Go / port-go): the real kubeflow/pipelines module
# drags the FULL Kubernetes api-machinery + gRPC + cloud-storage-SDK closure (and
# a moving `go` directive) through go.mod. config.go needs nothing but the stdlib,
# so we copy JUST that file (verbatim) into ONE fresh STANDALONE Go module,
# _mayhem_harness/bucketconfig (the package in its objectstore/ subdirectory),
# together with the fuzz harness AND the KAT probe, and build both binaries from
# it; its only non-stdlib dep is the go-118-fuzz-build /testing shim. The upstream go.mod is never read for this target, so it does not
# depend on a particular upstream commit's toolchain pin.
set -euo pipefail

: "${SRC:=/mayhem}"

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${CC:=clang}"
: "${CXX:=clang++}"
: "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

# Sanitizers (§6.1): the OSS-Fuzz Go path is ASan-only for the libFuzzer link.
# Honor the knob — an explicit empty SANITIZER_FLAGS yields an un-sanitized build.
: "${SANITIZER_FLAGS=-fsanitize=address}"
export SANITIZER_FLAGS
GO_SAN="-fsanitize=address"
[ -n "${SANITIZER_FLAGS}" ] || GO_SAN=""

# Debug-info contract (§6.2 item 10): gc always emits DWARF4 with no knob, so we
# force the clang-compiled cgo C shims to DWARF3 (CGO_CFLAGS/CGO_CXXFLAGS) AND
# prepend a DWARF3 anchor.o at the final clang++ link so the FIRST .debug_info CU
# (what the gate reads) is DWARF < 4. $GO_DEBUG_FLAGS threads any base pins.
export GO_DEBUG_FLAGS="${GO_DEBUG_FLAGS:--gdwarf-3}"
export CGO_CFLAGS="${CGO_CFLAGS:-} ${GO_DEBUG_FLAGS}"
export CGO_CXXFLAGS="${CGO_CXXFLAGS:-} ${GO_DEBUG_FLAGS}"

# Resolve modules offline-first from the in-image cache; network only as fallback.
export GOFLAGS="${GOFLAGS:--mod=mod}"
export GOSUMDB="${GOSUMDB:-off}"
export GOPROXY="${GOPROXY:-file://$(go env GOMODCACHE)/cache/download,https://proxy.golang.org,direct}"

go version

TARGET="fuzz_bucketconfig"          # Mayhem target (keep the name: corpus continuity)
KAT="kfp_bucketconfig_kat"          # test.sh's known-answer probe (never a Mayhem target)
OUT="$SRC/mayhem-build"

# Pseudo-version of the go-118-fuzz-build /testing shim that the Dockerfile's
# `go install ...@a70c2aa677fa...` already resolved + cached. A raw commit hash
# forces a proxy.golang.org round trip to resolve it — fatal on the air-gapped
# PATCH re-run; the pseudo-version resolves straight from the file cache.
GO118_SHIM_VERSION="v0.0.0-20250520111509-a70c2aa677fa"

# ── Stage ONE standalone mini-module: config.go (verbatim) + harness + KAT probe ──
# The fuzz target and the KAT probe are two entry points of the SAME package
# (github.com/kubeflow/pipelines/_mayhem_harness/bucketconfig/objectstore): one copy
# of the agent-editable config.go, one directory, one import path. go-118-fuzz-build
# rewrites (testing -> its shim) and moves aside, for the duration of the build,
# ONLY the file that holds -func; every other file is compiled as it is on disk.
# Both entry points (FuzzBucketConfig, FuzzKATBucketConfig) are therefore kept in
# harness_bucketconfig.go and the probe's logic in kat_bucketconfig.go has no
# `testing` import: both builds see the same package files with the same contents.
# go-118-fuzz-build also writes its generated main.*.go, which names the -func
# function, into its working directory. The package therefore lives in the
# objectstore/ SUBDIRECTORY of the module and go-118-fuzz-build runs from the module
# root (./objectstore): the -func-specific main is deliberately placed OUTSIDE the
# package directory, because a `//go:embed *.go` (or any embed pattern) in config.go
# would otherwise see it and compile config.go differently for target and probe.
# So reflect PkgPath, cgo ${SRCDIR}/__has_include, the file set, the embeddable
# files and the build flags are identical in the graded binary and in the oracle,
# and the second build reuses the first one's compiled package from the Go build
# cache (#1460 A / #1122).
stage() { # <module dir> <.go.src file under mayhem/>... (package goes in <module dir>/objectstore)
  local dir="$1" src
  shift
  rm -rf "$dir"
  mkdir -p "$dir/objectstore"
  cp "$SRC/backend/src/v2/objectstore/config.go" "$dir/objectstore/config.go"
  for src in "$@"; do cp "$SRC/mayhem/$src" "$dir/objectstore/${src%.src}"; done
  (
    cd "$dir"
    go mod init "github.com/kubeflow/pipelines/_mayhem_harness/$(basename "$dir")"
    go mod tidy
    # Add the go-118-fuzz-build /testing shim AFTER tidy (a trailing tidy would
    # prune it); resolves from the file-proxy cache offline on the PATCH re-run.
    go get "github.com/AdamKorcz/go-118-fuzz-build/testing@${GO118_SHIM_VERSION}"
  )
}
stage "$SRC/_mayhem_harness/bucketconfig" harness_bucketconfig.go.src kat_bucketconfig.go.src

# ── C objects shared by every link: DWARF3 anchor FIRST, Go init shim, LSan off ─
mkdir -p "$OUT"
printf 'int __mayhem_dwarf3_anchor;\n' > "$OUT/anchor.c"
$CC $GO_DEBUG_FLAGS -c "$OUT/anchor.c" -o "$OUT/anchor.o"
# Init-ordering shim (HARNESS-20, as in savantenvs/cert-manager): LLVMFuzzerInitialize
# waits for the Go runtime of the c-archive before libFuzzer touches coverage.
$CC $GO_DEBUG_FLAGS -c "$SRC/mayhem/go_runtime_ready.c" -o "$OUT/go_runtime_ready.o"
# Build-time LeakSanitizer off-switch (§6.2 item 15); ASan stays on.
$CC $GO_SAN $GO_DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.c" -o "$OUT/lsan_off.o"

# ── go-118-fuzz-build + clang++ ASan/libFuzzer link — ONE recipe, ONE package per pair ─
# go-118-fuzz-build runs in <dir> and writes its generated main.*.go there; <package>
# (relative to <dir>) is what it builds. For the bucket pair <dir> is the module root
# and <package> ./objectstore, so the generated main never sits in config.go's directory.
build_go_fuzzer() { # <dir> <func> <output binary> [package, relative to <dir>]
  local dir="$1" func="$2" bin="$3" pkg="${4:-.}"
  echo "=== go-118-fuzz-build -func $func ($dir $pkg) -> $bin ==="
  ( cd "$dir" && go-118-fuzz-build -func "$func" -o "$OUT/$(basename "$bin").a" "$pkg" )
  $CXX $GO_SAN $LIB_FUZZING_ENGINE $GO_DEBUG_FLAGS \
       "$OUT/anchor.o" "$OUT/go_runtime_ready.o" "$OUT/lsan_off.o" \
       "$OUT/$(basename "$bin").a" -o "$bin"
  # (No `grep -q` here: under pipefail it closes the pipe early and nm dies of SIGPIPE.)
  nm "$bin" | grep ' T LLVMFuzzerInitialize$' >/dev/null \
    || { echo "FATAL: $bin lacks the LLVMFuzzerInitialize init-ordering shim"; exit 1; }
  nm "$bin" | grep ' T __lsan_is_turned_off$' >/dev/null \
    || { echo "FATAL: $bin lacks the __lsan_is_turned_off hook"; exit 1; }
  echo "built $bin"
}
build_go_fuzzer "$SRC/_mayhem_harness/bucketconfig" FuzzBucketConfig    "/mayhem/$TARGET" ./objectstore
build_go_fuzzer "$SRC/_mayhem_harness/bucketconfig" FuzzKATBucketConfig "/mayhem/$KAT"    ./objectstore

# ── FuzzExprSelect: OSS-Fuzz's harness (SPEC §6.2 item 12), built IN the repo's module ─
# backend/src/v2/expression needs the module's real dependency graph (cel-go, protobuf,
# backend/src/common/util), so its harness and probe are staged TOGETHER as one package,
# _mayhem_harness/exprselect, inside the module tree (_mayhem_harness/ is skipped by ./...
# wildcards) and both binaries are built from that package against the in-tree sources.
# As for the bucket pair, both entry points (FuzzExprSelect, FuzzKATExprSelect) sit in
# harness_exprselect.go, so go-118-fuzz-build rewrites the same single file for both builds
# and the in-tree expression package is one identical compile in target and oracle.
# Here the generated main.*.go lands in _mayhem_harness/exprselect (the harness package's
# own, non-agent-editable directory). No agent-editable package can embed it: embed
# patterns cannot contain `..`, and the repo has no Go package at its root (the only
# ancestor of _mayhem_harness/). Re-check that if upstream ever adds a root-level .go file.
# The go-118-fuzz-build shim is added to a private COPY of go.mod/go.sum (-modfile), so
# upstream's go.mod and go.sum are never modified.
EXPR_TARGET="FuzzExprSelect"
EXPR_KAT="kfp_exprselect_kat"
FUZZMOD="$OUT/go.fuzz.mod"
cp "$SRC/go.mod" "$FUZZMOD"
cp "$SRC/go.sum" "${FUZZMOD%.mod}.sum"
stage_in_module() { # <dir> <.go.src file under mayhem/>...
  local dir="$1" src
  shift
  rm -rf "$dir"
  mkdir -p "$dir"
  for src in "$@"; do cp "$SRC/mayhem/$src" "$dir/${src%.src}"; done
}
stage_in_module "$SRC/_mayhem_harness/exprselect" harness_exprselect.go.src kat_exprselect.go.src
(
  export GOFLAGS="$GOFLAGS -modfile=$FUZZMOD"
  cd "$SRC"
  go get "github.com/AdamKorcz/go-118-fuzz-build/testing@${GO118_SHIM_VERSION}"
  build_go_fuzzer "$SRC/_mayhem_harness/exprselect" FuzzExprSelect    "/mayhem/$EXPR_TARGET"
  build_go_fuzzer "$SRC/_mayhem_harness/exprselect" FuzzKATExprSelect "/mayhem/$EXPR_KAT"
)

# The probes must stay dynamically linked so the gate's LD_PRELOAD neuter reaches them.
for kat in "$KAT" "$EXPR_KAT"; do
  file "/mayhem/$kat" | grep 'dynamically linked' >/dev/null \
    || { echo "FATAL: /mayhem/$kat is not dynamically linked — oracle would be reward-hackable"; exit 1; }
done
echo "built /mayhem/$KAT and /mayhem/$EXPR_KAT (dynamically linked, same package and build as their targets)"

echo "build.sh complete"
