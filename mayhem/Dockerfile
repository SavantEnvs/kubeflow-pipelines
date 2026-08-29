# syntax=docker/dockerfile:1.7
#
# Commit-image Dockerfile — kubeflow/pipelines (Go, Kubernetes ML-pipeline engine).
# Builds ON TOP of the org C/C++ base (clang links the go-118-fuzz-build libFuzzer
# archive) + a pinned Go toolchain and go-118-fuzz-build under /opt/toolchains/go,
# then runs mayhem/build.sh.
#
# WHY caches at fixed /opt/toolchains paths (SPEC §6.2 item 8 / §6.5): Go's
# GOPATH/GOMODCACHE default to $HOME/go, and the commit build vs. the PATCH RL
# re-run use DIFFERENT $HOMEs — an unpinned cache vanishes under the re-run
# identity and the offline build dies. Pinning them (below) is what makes the
# air-gapped re-run find the module cache the first online build filled.
#
# HARNESS SCOPE: two targets. fuzz_bucketconfig fuzzes
# backend/src/v2/objectstore (the pipeline-root / artifact bucket-URI parser:
# "gs://bucket/prefix?query" -> {Scheme,BucketName,Prefix,QueryString}, plus
# SplitObjectURI and the S3/GCS param decoders); config.go is stdlib-only, so
# mayhem/build.sh stages a verbatim copy into standalone mini-modules. FuzzExprSelect
# is OSS-Fuzz's harness for backend/src/v2/expression (CEL Select, SPEC §6.2 item
# 12); it is built inside the repo's own module, so the FIRST build below downloads
# that package's module closure into GOMODCACHE for the offline re-run.
#
# Build (from repo root, on the `mayhem` branch):
#   DOCKER_BUILDKIT=1 docker build -f mayhem/Dockerfile \
#       --build-arg COMMIT=$(git rev-parse HEAD) -t kubeflow-pipelines-commit:test .

FROM ghcr.io/savantenvs/base:20260621

ARG COMMIT
ARG REPO_URL
ARG SOURCE_DATE_EPOCH
ARG SANITIZER_FLAGS

# Pinned Go (version AND tarball sha256 — reproducible fetch). kubeflow/pipelines'
# go.mod requires go 1.27.0 (toolchain go1.27.1) and GOTOOLCHAIN=local never
# downloads another toolchain, so this pin must stay >= upstream's `go` directive.
# go-118-fuzz-build is pinned by COMMIT (its release tag is a stale 2022 snapshot
# predating the /testing shim).
ARG GO_VERSION=1.27.1
ARG GO_SHA256=63d339f0da5ab53635a56f2490a7984dfe12dfcff22ad749f63edaf590168445
ARG GO_118_FUZZ_BUILD_COMMIT=a70c2aa677fa43583571959478decabe02a96cd6

ENV GOROOT=/opt/toolchains/go \
    GOPATH=/opt/toolchains/go-path \
    GOMODCACHE=/opt/toolchains/go-path/pkg/mod \
    GOCACHE=/opt/toolchains/go-path/build-cache \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=mod \
    GOSUMDB=off \
    PATH=/opt/toolchains/go/bin:/opt/toolchains/go-path/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

USER root
RUN install -d /opt/toolchains/go-path \
 && curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tgz \
 && echo "${GO_SHA256}  /tmp/go.tgz" | sha256sum -c - \
 && tar -C /opt/toolchains -xzf /tmp/go.tgz && rm -f /tmp/go.tgz \
 # Install go-118-fuzz-build (the OSS-Fuzz native testing.F path). This also seeds
 # its module — incl. the /testing shim + go-fuzz-headers — into GOMODCACHE, which
 # build.sh's `go get .../testing` then resolves OFFLINE at the PATCH re-run.
 && go install "github.com/AdamKorcz/go-118-fuzz-build@${GO_118_FUZZ_BUILD_COMMIT}" \
 # The commit build AND the air-gapped re-run run as `mayhem` (2000): it must read
 # the toolchain and read/refresh the module cache, so hand GOPATH to 2000.
 && chown -R 2000:2000 /opt/toolchains/go-path

USER mayhem
WORKDIR /mayhem
COPY --chown=2000:2000 . /mayhem

# Populates $GOMODCACHE + $GOCACHE (online, this first build) and builds the libFuzzer
# targets and their KAT probes.
RUN bash mayhem/build.sh

RUN if [ -f mayhem/test.sh ]; then bash mayhem/test.sh; else echo "no mayhem/test.sh"; fi

LABEL org.opencontainers.image.source="${REPO_URL}" \
      org.opencontainers.image.revision="${COMMIT}" \
      rlenv.tier="commit" \
      rlenv.source_date_epoch="${SOURCE_DATE_EPOCH}" \
      rlenv.user="mayhem"

USER mayhem
WORKDIR /mayhem
