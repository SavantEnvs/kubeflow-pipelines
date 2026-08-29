#!/usr/bin/env bash
#
# mayhem/test.sh — BEHAVIORAL oracle for Kubeflow Pipelines' object-store bucket-
# URI parser (backend/src/v2/objectstore/config.go) and CEL expression selector
# (backend/src/v2/expression). Runs only; build.sh builds.
#
# Each probe is built FROM THE SAME Go PACKAGE as its graded target, with the same
# go-118-fuzz-build call and link line (#1460 A / #1122): /mayhem/kfp_bucketconfig_kat
# and /mayhem/fuzz_bucketconfig both from _mayhem_harness/bucketconfig/objectstore
# (one copy of config.go), /mayhem/kfp_exprselect_kat and /mayhem/FuzzExprSelect both
# from _mayhem_harness/exprselect (the in-tree expression package); only -func and
# go-118-fuzz-build's generated main.*.go differ. build.sh deliberately writes that
# -func-specific main OUTSIDE every agent-editable package directory, because a
# `//go:embed` in config.go (or an in-tree package) would otherwise see it. So
# whatever a patch compiles into the fuzz build is what is tested here. Each
# probe is a dynamically linked libFuzzer binary: test.sh feeds it ONE input file
# per case and it prints one line of computed values. Every case, every expected
# value and every PASS/FAIL decision lives in THIS file; the probes never print a
# verdict or a tally, so nothing the patched library prints counts as a pass.
#
# Cases and expected values: upstream's own tests (expression_test.go TestSelect;
# config_test.go Test_ParseBucketPathToConfig, TestSplitObjectURI_*,
# TestHasStructuredS3Settings, TestConfigHash_UsesLengthDelimitedEncoding,
# *_RejectsEncodedQueryDelimiters*), the earlier Test_parseCloudBucket golden URIs,
# and the documented semantics of PrefixedBucket / bucketURL / SessionInfoPath /
# Hash / IsWithinBucketRoot / StructuredS3Params / StructuredGCSParams.
# Config.Hash() expectations are computed here with coreutils sha256sum from
# Hash()'s length-delimited encoding.
#
# Each case runs in its own process, so one crashing case fails only that case.
# The repo ships two fuzz targets but ONE suite grades both, so every CTRF test is
# a PAIR: bucket-URI case k and CEL-select case k, passing only if both match. A
# patch that disables either library therefore loses every test instead of
# keeping the other library's share (count each program once, #1460 mac). A
# missing probe is a FAILURE, never a skip. Emits a CTRF summary; exits non-zero
# iff failed>0.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
export LC_ALL=C
cd "${SRC:-/mayhem}"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-${SRC:-/mayhem}/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

TOOL="kfp-kat"
BUCKET_PROBE=/mayhem/kfp_bucketconfig_kat   # same package + build as /mayhem/fuzz_bucketconfig
EXPR_PROBE=/mayhem/kfp_exprselect_kat       # same package + build as /mayhem/FuzzExprSelect
passed=0; failed=0

for p in "$BUCKET_PROBE" "$EXPR_PROBE"; do
  if [ ! -x "$p" ]; then
    echo "FAIL: KAT probe $p missing or not executable (build.sh should have produced it)" >&2
    emit_ctrf "$TOOL" 0 1
    exit 1
  fi
done
WORK="$(mktemp -d "${TMPDIR:-/tmp}/kfp-kat.XXXXXX")" || { echo "FAIL: mktemp" >&2; emit_ctrf "$TOOL" 0 1; exit 1; }
trap 'rm -rf "$WORK"' EXIT

# run_case <case-line>: OUT = stdout of $PROBE (the section's probe), RC = its exit status. The input is
# the go-fuzz-headers string encoding the probe's f.Fuzz decodes: a 4-byte big-endian
# length, then the case bytes. -detect_leaks=0 is a libFuzzer flag for this probe run
# only: without it libFuzzer re-executes any input whose run left more mallocs than frees
# (the Go runtime starting a thread is enough) to look for leaks, so the case would run,
# and print, twice. It does not touch the graded fuzz targets or their Mayhemfiles.
run_case() {
  local c="$1" n
  n=${#c}
  printf "$(printf '\\%03o\\%03o\\%03o\\%03o' $(( n>>24 & 255 )) $(( n>>16 & 255 )) $(( n>>8 & 255 )) $(( n & 255 )))" > "$WORK/case"
  printf '%s' "$c" >> "$WORK/case"
  OUT="$("$PROBE" -detect_leaks=0 "$WORK/case" 2>"$WORK/stderr")"; RC=$?
}
# Case verdicts are recorded per library and combined into pairs at the end.
B_DESC=(); B_OK=(); E_DESC=(); E_OK=()
record() { # <desc> <0|1>
  if [ "$PROBE" = "$BUCKET_PROBE" ]; then B_DESC+=("$1"); B_OK+=("$2"); else E_DESC+=("$1"); E_OK+=("$2"); fi
}
# expect <desc> <case> <exact expected output line>
expect() {
  run_case "$2"
  if [ "$RC" -eq 0 ] && [ "$OUT" = "$3" ]; then record "$1" 1
  else echo "  case mismatch: $1 -- rc=$RC got [$OUT] want [$3]"; record "$1" 0; fi
}
# expect_err <desc> <case> <required output prefix> <required substring>
expect_err() {
  run_case "$2"
  if [ "$RC" -eq 0 ] && [ "${OUT#"$3"}" != "$OUT" ] && [ "${OUT#*"$4"}" != "$OUT" ] && [ "${OUT//$'\n'/}" = "$OUT" ]; then
    record "$1" 1
  else echo "  case mismatch: $1 -- rc=$RC got [$OUT] want prefix [$3] containing [$4]"; record "$1" 0; fi
}
# kfp_hash <scheme> <bucket> <prefix> <query>: Config.Hash() — sha256 over
# "%d:%s|%d:%s|%d:%s|%d:%s" of (len, value) for each field, hex-encoded.
kfp_hash() {
  printf '%d:%s|%d:%s|%d:%s|%d:%s' "${#1}" "$1" "${#2}" "$2" "${#3}" "$3" "${#4}" "$4" | sha256sum | cut -d' ' -f1
}
# parsed <scheme> <bucket> <prefix> <query> <prefixed> <bucketurl> <sessionpath>
parsed() {
  printf 'ok scheme=%s bucket=%s prefix=%s query=%s prefixed=%s bucketurl=%s sessionpath=%s hash=%s' \
    "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$(kfp_hash "$1" "$2" "$3" "$4")"
}
T=$'\t'

PROBE="$BUCKET_PROBE"
# ── ParseBucketPathToConfig + Config accessors ──────────────────────────────────
expect "parse minio://my-bucket (no prefix)" "parse${T}minio://my-bucket" \
  "$(parsed minio:// my-bucket '' '' minio://my-bucket minio://my-bucket minio://my-bucket)"
expect "parse gs prefix normalized to trailing slash" "parse${T}gs://my-bucket/my-path/123" \
  "$(parsed gs:// my-bucket my-path/123/ '' gs://my-bucket/my-path/123 'gs://my-bucket?prefix=my-path/123/' gs://my-bucket/my-path/123)"
expect "parse trailing slash not doubled" "parse${T}gs://my-bucket/my-path/" \
  "$(parsed gs:// my-bucket my-path/ '' gs://my-bucket/my-path 'gs://my-bucket?prefix=my-path/' gs://my-bucket/my-path)"
expect "parse s3 pipeline root (upstream Test_ParseBucketPathToConfig)" "parse${T}s3://mlpipeline/v2/artifacts/" \
  "$(parsed s3:// mlpipeline v2/artifacts/ '' s3://mlpipeline/v2/artifacts 's3://mlpipeline?prefix=v2/artifacts/' s3://mlpipeline/v2/artifacts)"
expect "parse query string kept; bucketURL appends &prefix; SessionInfoPath keeps query" "parse${T}s3://bkt/obj?region=us-east-1" \
  "$(parsed s3:// bkt obj/ '?region=us-east-1' s3://bkt/obj 's3://bkt?region=us-east-1&prefix=obj/' 's3://bkt/obj?region=us-east-1')"
expect "parse mem:// bucket" "parse${T}mem://membucket" \
  "$(parsed mem:// membucket '' '' mem://membucket mem://membucket mem://membucket)"
expect_err "parse unrecognized format -> error" "parse${T}not-a-uri" "err " "unrecognized pipeline root format"
expect_err "parse unsupported scheme -> error" "parse${T}ftp://bucket/x" "err " "unsupported Cloud bucket"
expect_err "parse rejects encoded query delimiters in path" \
  "parse${T}s3://bucket/other/%3Fendpoint=attacker.example:9000%26disableSSL=true/" "err " "encoded query delimiters"
expect "Hash is length-delimited (abc+def/ vs abcd+ef/ differ)" "hashne${T}s3://abc/def${T}s3://abcd/ef" "distinct"

# ── SplitObjectURI (upstream TestSplitObjectURI_*) ──────────────────────────────
expect "split decodes %20"              "split${T}s3://bucket/path/my%20model"     "ok prefix=s3://bucket/path base=my model"
expect "split decodes %25"              "split${T}s3://bucket/path/100%25complete" "ok prefix=s3://bucket/path base=100%complete"
expect "split decodes UTF-8 escapes"    "split${T}s3://bucket/path/caf%C3%A9"      "ok prefix=s3://bucket/path base=café"
expect "split decodes alternate ASCII"  "split${T}s3://bucket/path/discount%50off"  "ok prefix=s3://bucket/path base=discountPoff"
expect "split decodes lowercase escapes" "split${T}s3://bucket/path/caf%c3%a9"     "ok prefix=s3://bucket/path base=café"
expect "split object at bucket root"    "split${T}gs://bucket/file"                "ok prefix=gs://bucket base=file"
expect "split trims trailing slash"     "split${T}gs://bucket/a/b/"                "ok prefix=gs://bucket/a base=b"
expect_err "split rejects encoded query delimiters" \
  "split${T}s3://bucket/other/%3Fendpoint=attacker.example:9000%26disableSSL=true/file" "err " "encoded query delimiters"
expect_err "split rejects malformed raw percent" "split${T}s3://bucket/path/100%complete" "err " "invalid URL escape"

# ── ParseProviderFromPath ───────────────────────────────────────────────────────
expect "provider s3"     "provider${T}s3://bucket/x" "ok s3"
expect "provider minio"  "provider${T}minio://b"     "ok minio"
expect_err "provider unsupported scheme -> error" "provider${T}ftp://bucket/x" "err " "unsupported Cloud bucket"

# ── IsWithinBucketRoot ──────────────────────────────────────────────────────────
expect "within: sub-path of root"            "within${T}s3://b/root/${T}s3://b/root/sub/x" "true"
expect "within: sibling sharing a prefix"    "within${T}s3://b/root/${T}s3://b/rootless/x" "false"
expect "within: different scheme"            "within${T}s3://b/root/${T}gs://b/root/sub"   "false"
expect "within: unparsable root (nil)"       "within${T}not-a-uri${T}s3://b/x"             "false"
expect "within: bucket root covers any key"  "within${T}s3://b${T}s3://b/anything"         "true"

# ── HasStructuredS3Settings + StructuredS3Params (upstream TestHasStructuredS3Settings) ─
# The params come from a parsed bucket URI's query string, as in the fuzz harness.
s3ok() { # <has> <fromEnv> <secretName> <accessKeyKey> <secretKeyKey> <region> <endpoint> <disableSSL> <forcePathStyle> <maxRetries>
  printf 'has=%s ok fromEnv=%s secretName=%s accessKeyKey=%s secretKeyKey=%s region=%s endpoint=%s disableSSL=%s forcePathStyle=%s maxRetries=%s' "$@"
}
expect "s3 params: no query -> empty map, forcePathStyle defaults true" "s3${T}s3://bkt/p" \
  "$(s3ok false false '' '' '' '' '' false true 0)"
expect "s3 params: credentials only are not structured settings" \
  "s3${T}s3://bkt/p?fromEnv=true&secretName=secret&accessKeyKey=access&secretKeyKey=key" \
  "$(s3ok false true secret access key '' '' false true 0)"
expect "s3 params: region makes structured settings" "s3${T}s3://bkt/p?fromEnv=true&region=us-east-1" \
  "$(s3ok true true '' '' '' us-east-1 '' false true 0)"
expect "s3 params: endpoint makes structured settings" "s3${T}s3://bkt/p?endpoint=x" \
  "$(s3ok true false '' '' '' '' x false true 0)"
expect "s3 params: all typed fields decoded" "s3${T}minio://bkt/p?disableSSL=true&forcePathStyle=false&maxRetries=3&endpoint=minio:9000" \
  "$(s3ok true false '' '' '' '' minio:9000 true false 3)"
expect_err "s3 params: bad disableSSL bool -> error"     "s3${T}s3://bkt/p?disableSSL=x"     "has=true err " "invalid syntax"
expect_err "s3 params: bad forcePathStyle bool -> error" "s3${T}s3://bkt/p?forcePathStyle=x" "has=true err " "invalid syntax"
expect_err "s3 params: bad maxRetries int -> error"      "s3${T}s3://bkt/p?maxRetries=x"     "has=true err " "invalid syntax"

# ── StructuredGCSParams ─────────────────────────────────────────────────────────
expect "gcs params decoded"   "gcs${T}gs://bkt/p?fromEnv=true&secretName=s&tokenKey=k" "ok fromEnv=true secretName=s tokenKey=k"
expect "gcs params: no query -> empty map" "gcs${T}gs://bkt/p"            "ok fromEnv=false secretName= tokenKey="
expect_err "gcs params: bad fromEnv bool -> error" "gcs${T}gs://bkt/p?fromEnv=maybe" "err " "invalid syntax"

PROBE="$EXPR_PROBE"
# ── (*Expr).Select — upstream expression_test.go TestSelect (input value as JSON) ─
STRUCT1='{"a":"A","b":"B"}'
STRUCT2='{"nested":{"a":"A","b":"B"},"bool":true,"double":1.3,"int":10,"str":"abcdefg","list":[1.1,1.2,1.3]}'
S="select${T}"
expect "select string_value"                "${S}\"Hello,World!\"${T}string_value"                 'ok "Hello,World!"'
expect "select parseJson(string_value)[0]"  "${S}\"[1.1,1.2,1.3]\"${T}parseJson(string_value)[0]"  'ok 1.1'
expect_err "select parseJson of invalid JSON -> error" "${S}\"invalidjson\"${T}parseJson(string_value)" "err " "failed to unmarshal JSON"
expect "select string_value of null is empty" "${S}null${T}string_value"                             'ok ""'
expect_err "select struct_value of a string -> error" "${S}\"Hello\"${T}struct_value" "err " "no such attribute"
expect "select struct field"                "${S}${STRUCT1}${T}struct_value.a"                     'ok "A"'
expect_err "select missing struct key -> error" "${S}${STRUCT1}${T}struct_value.c" "err " "no such key: c"
expect "select list field from struct"      "${S}${STRUCT2}${T}struct_value.list"                  'ok [1.1,1.2,1.3]'
expect "select nested struct"               "${S}${STRUCT2}${T}struct_value.nested"                'ok {"a":"A","b":"B"}'
expect "select nested field"                "${S}${STRUCT2}${T}struct_value.nested.b"              'ok "B"'
# CEL language semantics through Select (standard operators, macros and functions):
expect "select string concatenation"        "${S}${STRUCT2}${T}struct_value.str + \"!\""            'ok "abcdefg!"'
expect "select size() of a list"            "${S}${STRUCT2}${T}size(struct_value.list)"            'ok 3'
expect "select equality"                    "${S}{\"a\":\"A\"}${T}struct_value.a == \"A\""          'ok true'
expect "select double arithmetic"           "${S}{\"n\":2}${T}struct_value.n * 3.0"                 'ok 6'
expect "select ternary"                     "${S}{\"n\":2}${T}struct_value.n > 1.0 ? \"big\" : \"small\"" 'ok "big"'
expect "select size() of a string"          "${S}\"abcdefg\"${T}size(string_value)"                 'ok 7'
expect "select startsWith"                  "${S}\"abcdefg\"${T}string_value.startsWith(\"abc\")"   'ok true'
expect "select contains"                    "${S}\"abcdefg\"${T}string_value.contains(\"cde\")"     'ok true'
expect "select endsWith (false)"            "${S}\"abcdefg\"${T}string_value.endsWith(\"x\")"       'ok false'
expect "select list index"                  "${S}{\"list\":[1,2,3]}${T}struct_value.list[1]"        'ok 2'
expect "select in operator"                 "${S}{\"list\":[1,2,3]}${T}2.0 in struct_value.list"    'ok true'
expect "select has() present"               "${S}{\"m\":{\"k\":\"v\"}}${T}has(struct_value.m.k)"    'ok true'
expect "select has() absent"                "${S}{\"m\":{\"k\":\"v\"}}${T}has(struct_value.m.z)"    'ok false'
expect "select size(parseJson(...))"        "${S}\"[1,2,3]\"${T}size(parseJson(string_value))"      'ok 3'
expect "select parseJson nested field"      "${S}\"{\\\"x\\\":{\\\"y\\\":\\\"z\\\"}}\"${T}parseJson(string_value).x.y" 'ok "z"'
expect "select number_value arithmetic"     "${S}5${T}number_value + 1.0"                           'ok 6'
expect "select string_value of a number"    "${S}5${T}string_value"                                 'ok "5"'
expect "select bool_value logic"            "${S}true${T}bool_value && true"                        'ok true'
expect "select list_value"                  "${S}[1,\"two\",null]${T}list_value"                    'ok [1,"two",null]'
expect "select int() conversion"            "${S}\"x\"${T}int(\"42\")"                              'ok 42'
expect "select string() conversion"         "${S}\"x\"${T}string(42)"                               'ok "42"'
expect "select matches() (RE2)"             "${S}\"x\"${T}\"abc\".matches(\"^a.c\$\")"              'ok true'
expect "select size() of a struct"          "${S}${STRUCT1}${T}size(struct_value)"                 'ok 2'
expect "select all() macro"                 "${S}\"x\"${T}[1, 2, 3].all(x, x > 0)"                  'ok true'
expect_err "select division by zero -> error"   "${S}\"x\"${T}1/0"            "err " "division by zero"
expect_err "select type error -> error"         "${S}\"x\"${T}\"a\" + 1"      "err " "found no matching overload"
expect_err "select undeclared name -> error"    "${S}\"x\"${T}undefined_var"  "err " "undeclared reference"
expect_err "select syntax error -> error"       "${S}\"x\"${T}((("            "err " "Syntax error"

# ── Combine: CTRF test k = bucket-URI case k AND CEL-select case k ──────────────
nb=${#B_OK[@]}; ne=${#E_OK[@]}
if [ "$nb" -eq 0 ] || [ "$ne" -eq 0 ]; then
  echo "FAIL: no cases recorded (bucket=$nb select=$ne)"; emit_ctrf "$TOOL" 0 1; exit 1
fi
n=$(( nb > ne ? nb : ne ))
for (( k = 0; k < n; k++ )); do
  i=$(( k % nb )); j=$(( k % ne ))
  if [ "${B_OK[$i]}" = 1 ] && [ "${E_OK[$j]}" = 1 ]; then
    echo "PASS: [$k] ${B_DESC[$i]} + ${E_DESC[$j]}"; passed=$((passed+1))
  else
    echo "FAIL: [$k] ${B_DESC[$i]} (${B_OK[$i]}) + ${E_DESC[$j]} (${E_OK[$j]})"; failed=$((failed+1))
  fi
done

emit_ctrf "$TOOL" "$passed" "$failed"
