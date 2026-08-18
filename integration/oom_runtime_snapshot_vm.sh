#!/usr/bin/env bash

# Copyright 2026 The HuaTuo Authors.
# Licensed under the Apache License, Version 2.0.

# Reproducible VM regression for the OOM runtime snapshot providers. This is
# intentionally separate from integration/run.sh: it installs/selects runtime
# toolchains and reads live process memory, while the regular integration lane
# must remain hermetic.

set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PROFILE=${HUATUO_SNAPSHOT_TEST_PROFILE:-change}
RUNTIME_ROOT=${HUATUO_RUNTIME_ROOT:-/opt/huatuo-runtime-matrix}
RUN_UNIT=${HUATUO_SNAPSHOT_RUN_UNIT:-1}
RUN_MATRIX=${HUATUO_SNAPSHOT_RUN_MATRIX:-1}
RUN_MEMCG_OOM=${HUATUO_SNAPSHOT_RUN_MEMCG_OOM:-0}
LANGUAGES=,${HUATUO_SNAPSHOT_LANGUAGES:-go,python,java},

GO_VERSIONS=(1.20.14 1.21.13 1.22.12 1.23.12 1.24.6 1.25.0)
PYTHON_VERSIONS=(3.8 3.9 3.10 3.11 3.12 3.13 3.14)
JAVA_VERSIONS=(8 11 17 21 25)
TEST_GO=${HUATUO_TEST_GO_BINARY:-${RUNTIME_ROOT}/go1.25.0/bin/go}

case "${PROFILE}" in
change)
	SMALL_OBJECTS=${HUATUO_FIXTURE_SMALL_OBJECTS:-50000}
	LARGE_OBJECTS=${HUATUO_FIXTURE_LARGE_OBJECTS:-128}
	PY_CHECKOUT=${HUATUO_FIXTURE_CHECKOUT:-2048}
	PY_CACHE=${HUATUO_FIXTURE_CACHE:-4096}
	PY_IMAGE=${HUATUO_FIXTURE_IMAGE:-1024}
	;;
extreme)
	SMALL_OBJECTS=${HUATUO_FIXTURE_SMALL_OBJECTS:-1000000}
	LARGE_OBJECTS=${HUATUO_FIXTURE_LARGE_OBJECTS:-4096}
	PY_CHECKOUT=${HUATUO_FIXTURE_CHECKOUT:-100000}
	PY_CACHE=${HUATUO_FIXTURE_CACHE:-200000}
	PY_IMAGE=${HUATUO_FIXTURE_IMAGE:-50000}
	export HUATUO_FIXTURE_ALLOW_PARTIAL=1
	;;
mixed)
	SMALL_OBJECTS=${HUATUO_FIXTURE_SMALL_OBJECTS:-50000}
	LARGE_OBJECTS=${HUATUO_FIXTURE_LARGE_OBJECTS:-128}
	PY_CHECKOUT=${HUATUO_FIXTURE_CHECKOUT:-2048}
	PY_CACHE=${HUATUO_FIXTURE_CACHE:-4096}
	PY_IMAGE=${HUATUO_FIXTURE_IMAGE:-1024}
	export HUATUO_FIXTURE_MODE=mixed
	export HUATUO_FIXTURE_HOT_OBJECTS=${HUATUO_FIXTURE_HOT_OBJECTS:-700000}
	export HUATUO_FIXTURE_WARM_OBJECTS=${HUATUO_FIXTURE_WARM_OBJECTS:-200000}
	export HUATUO_FIXTURE_COLD_OBJECTS=${HUATUO_FIXTURE_COLD_OBJECTS:-100000}
	export HUATUO_FIXTURE_FILLER_OBJECTS=${HUATUO_FIXTURE_FILLER_OBJECTS:-2048}
	export HUATUO_FIXTURE_HUMONGOUS_OBJECTS=${HUATUO_FIXTURE_HUMONGOUS_OBJECTS:-32}
	export HUATUO_FIXTURE_PY_HOT=${HUATUO_FIXTURE_PY_HOT:-30000}
	export HUATUO_FIXTURE_PY_WARM=${HUATUO_FIXTURE_PY_WARM:-9000}
	export HUATUO_FIXTURE_PY_COLD=${HUATUO_FIXTURE_PY_COLD:-3000}
	export HUATUO_FIXTURE_MAX_ERROR=${HUATUO_FIXTURE_MAX_ERROR:-0.20}
	export HUATUO_FIXTURE_ALLOW_PARTIAL=1
	;;
*)
	echo "unknown profile: ${PROFILE}; expected change, extreme, or mixed" >&2
	exit 2
	;;
esac

export HUATUO_FIXTURE_WORKERS=${HUATUO_FIXTURE_WORKERS:-8}
export HUATUO_FIXTURE_SMALL_OBJECTS=${SMALL_OBJECTS}
export HUATUO_FIXTURE_LARGE_OBJECTS=${LARGE_OBJECTS}
export HUATUO_FIXTURE_CHECKOUT=${PY_CHECKOUT}
export HUATUO_FIXTURE_CACHE=${PY_CACHE}
export HUATUO_FIXTURE_IMAGE=${PY_IMAGE}

log() {
	printf '[oom-runtime-snapshot] %s\n' "$*"
}

language_enabled() {
	[[ ${LANGUAGES} == *,$1,* ]]
}

require_root() {
	if [[ ${EUID} -ne 0 ]]; then
		echo "the VM runtime matrix requires root for cross-process memory reads" >&2
		exit 1
	fi
}

version_key() {
	printf '%s' "$1" | tr '.' '_'
}

runtime_path() {
	local family=$1 version=$2
	local key
	key=$(version_key "${version}")
	local variable="HUATUO_${family}_${key}"
	printf '%s' "${!variable:-}"
}

go_binary() {
	local configured
	configured=$(runtime_path GO "$1")
	if [[ -n ${configured} ]]; then
		printf '%s' "${configured}"
		return
	fi
	printf '%s/go%s/bin/go' "${RUNTIME_ROOT}" "$1"
}

python_binary() {
	local configured
	configured=$(runtime_path PYTHON "$1")
	if [[ -n ${configured} ]]; then
		printf '%s' "${configured}"
		return
	fi
	printf '%s/python%s/bin/python3' "${RUNTIME_ROOT}" "$1"
}

java_home() {
	local configured
	configured=$(runtime_path JAVA "$1")
	if [[ -n ${configured} ]]; then
		printf '%s' "${configured}"
		return
	fi
	printf '%s/jdk%s' "${RUNTIME_ROOT}" "$1"
}

assert_runtime_matrix() {
	local missing=0 version binary home
	for version in "${GO_VERSIONS[@]}"; do
		binary=$(go_binary "${version}")
		if [[ ! -x ${binary} ]]; then
			echo "missing Go ${version}: ${binary}" >&2
			missing=1
		fi
	done
	for version in "${PYTHON_VERSIONS[@]}"; do
		binary=$(python_binary "${version}")
		if [[ ! -x ${binary} ]]; then
			echo "missing CPython ${version}: ${binary}" >&2
			missing=1
		fi
	done
	for version in "${JAVA_VERSIONS[@]}"; do
		home=$(java_home "${version}")
		if [[ ! -x ${home}/bin/java ]]; then
			echo "missing JDK ${version}: ${home}" >&2
			missing=1
		fi
	done
	if ((missing)); then
		echo "install the missing runtimes or set HUATUO_<FAMILY>_<VERSION> overrides" >&2
		exit 1
	fi
}

run_unit_tests() {
	log "fast unit tests"
	"${TEST_GO}" test ./core/events ./internal/goheap ./internal/memsnap/... \
		-count=1 -timeout=5m
}

run_go_matrix() {
	local version go fixture
	for version in "${GO_VERSIONS[@]}"; do
		go=$(go_binary "${version}")
		fixture="${TMPDIR}/go-${version}-fixture"
		log "Go ${version}: build fixture and capture live heap"
		GO111MODULE=off GOTOOLCHAIN=local "${go}" build -o "${fixture}" \
			"${ROOT_DIR}/integration/fixtures/oom_runtime_snapshot/go/main.go"
		HUATUO_TEST_GO_FIXTURE="${fixture}" \
			"${TEST_GO}" test ./internal/memsnap/providers/golang \
			-run '^TestExternalReaderAgainstVersionedFixture$' -count=1 -v -timeout=2m
	done
}

run_python_matrix() {
	local version python
	for version in "${PYTHON_VERSIONS[@]}"; do
		python=$(python_binary "${version}")
		log "CPython ${version}: capture live multi-thread object heap"
		HUATUO_TEST_PYTHON_EXTERNAL=1 HUATUO_TEST_GATE_MILLISECONDS=50 \
			HUATUO_TEST_PYTHON_BINARY="${python}" \
			"${TEST_GO}" test ./internal/memsnap/providers/python \
			-run '^TestExternalReaderAgainstRealLegacyCPython$' -count=1 -v -timeout=2m
	done
}

compile_java_fixture() {
	local home javac=""
	for version in "${JAVA_VERSIONS[@]}"; do
		home=$(java_home "${version}")
		if [[ -x ${home}/bin/javac ]]; then
			javac=${home}/bin/javac
			break
		fi
	done
	if [[ -z ${javac} ]]; then
		echo "no javac is available in the configured Java matrix" >&2
		exit 1
	fi
	mkdir -p "${TMPDIR}/java-fixture"
	"${javac}" -source 8 -target 8 -d "${TMPDIR}/java-fixture" \
		"${ROOT_DIR}/integration/fixtures/oom_runtime_snapshot/java/HuatuoSnapshotFixture.java"
}

run_java_matrix() {
	local version home options
	compile_java_fixture
	for version in "${JAVA_VERSIONS[@]}"; do
		home=$(java_home "${version}")
		log "JDK ${version}: capture live G1 heap"
		HUATUO_TEST_JAVA_HOME="${home}" HUATUO_TEST_GATE_MILLISECONDS=50 \
		HUATUO_TEST_JAVA_FIXTURE_DIR="${TMPDIR}/java-fixture" \
			"${TEST_GO}" test ./internal/memsnap/providers/java \
			-run '^TestExternalReaderAgainstVersionedG1Fixture$' -count=1 -v -timeout=2m
	done
	home=$(java_home 21)
	for options in \
		"-XX:+UseG1GC -XX:G1HeapRegionSize=1m -Xms256m -Xmx2g" \
		"-XX:+UseG1GC -XX:G1HeapRegionSize=16m -Xms256m -Xmx2g" \
		"-XX:+UseG1GC -XX:+UseCompressedOops -XX:-UseCompressedClassPointers -Xms256m -Xmx2g" \
		"-XX:+UseG1GC -XX:-UseCompressedOops -XX:-UseCompressedClassPointers -Xms256m -Xmx2g"
	do
		log "JDK 21: capture G1 heap with ${options}"
		HUATUO_TEST_JAVA_HOME="${home}" HUATUO_TEST_GATE_MILLISECONDS=50 \
		HUATUO_TEST_JAVA_FIXTURE_DIR="${TMPDIR}/java-fixture" \
		HUATUO_TEST_JAVA_OPTIONS="${options}" \
			"${TEST_GO}" test ./internal/memsnap/providers/java \
			-run '^TestExternalReaderAgainstVersionedG1Fixture$' -count=1 -v -timeout=2m
	done
	for options in \
		"-XX:+UseParallelGC -Xms256m -Xmx2g" \
		"-XX:+UseSerialGC -Xms256m -Xmx2g"
	do
		log "JDK 21: reject unsupported collector ${options}"
		HUATUO_TEST_JAVA_HOME="${home}" HUATUO_TEST_GATE_MILLISECONDS=50 \
		HUATUO_TEST_JAVA_FIXTURE_DIR="${TMPDIR}/java-fixture" \
		HUATUO_TEST_JAVA_OPTIONS="${options}" \
		HUATUO_TEST_JAVA_EXPECT_UNSUPPORTED=1 \
			"${TEST_GO}" test ./internal/memsnap/providers/java \
			-run '^TestExternalReaderAgainstVersionedG1Fixture$' -count=1 -v -timeout=2m
	done
	if [[ ${PROFILE} == mixed ]]; then
		home=$(java_home 21)
		log "JDK 21: repeat interleaved-size Region bias capture"
		HUATUO_FIXTURE_JAVA_LAYOUT=interleaved \
		HUATUO_TEST_JAVA_HOME="${home}" HUATUO_TEST_GATE_MILLISECONDS=50 \
		HUATUO_TEST_JAVA_FIXTURE_DIR="${TMPDIR}/java-fixture" \
			"${TEST_GO}" test ./internal/memsnap/providers/java \
			-run '^TestExternalReaderAgainstVersionedG1Fixture$' -count=3 -v -timeout=2m
	fi
}

run_memcg_oom_smoke() {
	log "real memcg OOM gate/ACK/fail-open smoke"
	bash "${ROOT_DIR}/integration/test_oom_runtime_snapshot_memcg.sh"
}

list_tests() {
	cat <<'EOF'
fast unit tests:
  core/events: gate config, ACK/backoff, busy/cooldown, JSON merge, signal context
  internal/goheap: Go 1.20-1.25 layout/discovery/symbolization
  internal/memsnap: bounds, coordinator, identity, atomic store
  providers/golang: sample scaling, Top-K, deadlines, external current-process read
  providers/python: GC layouts, dictionary layouts, pymalloc strata/estimate/batching
  providers/java: G1 strata/estimate/variance, humongous regions, HotSpot metadata

VM runtime matrix:
  Go 1.20-1.25: live external mbucket read, small+large objects, multi-goroutine
  CPython 3.8-3.14: live external/remote census, small+large objects, multi-thread
  HotSpot 8/11/17/21/25: live external G1 read, small+large objects, multi-thread
  HotSpot JDK 21: 1/16 MiB Regions, compressed pointers on/off
  HotSpot JDK 21: explicit fail-closed rejection for Parallel/Serial GC

optional destructive system E2E (HUATUO_SNAPSHOT_RUN_MEMCG_OOM=1):
  Go/CPython/HotSpot: real memcg OOM, exit 137, BPF gate/ACK and persisted snapshot
EOF
}

main() {
	cd "${ROOT_DIR}"
	if [[ ${1:-} == --list ]]; then
		list_tests
		exit 0
	fi
	require_root
	if [[ ! -x ${TEST_GO} ]]; then
		echo "current-project Go toolchain is unavailable: ${TEST_GO}" >&2
		exit 1
	fi
	TMPDIR=$(mktemp -d /tmp/huatuo-oom-runtime-test.XXXXXX)
	readonly TMPDIR
	trap 'rm -rf -- "${TMPDIR}"' EXIT
	log "profile=${PROFILE} small=${SMALL_OBJECTS} large=${LARGE_OBJECTS} workers=${HUATUO_FIXTURE_WORKERS}"
	if [[ ${RUN_UNIT} == 1 ]]; then
		run_unit_tests
	fi
	if [[ ${RUN_MATRIX} == 1 ]]; then
		assert_runtime_matrix
		language_enabled go && run_go_matrix
		language_enabled python && run_python_matrix
		language_enabled java && run_java_matrix
	fi
	if [[ ${RUN_MEMCG_OOM} == 1 ]]; then
		run_memcg_oom_smoke
	fi
	log "all requested tests passed"
}

main "$@"
