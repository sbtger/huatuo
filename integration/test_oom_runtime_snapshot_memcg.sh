#!/usr/bin/env bash

# Copyright 2026 The HuaTuo Authors.
# Licensed under the Apache License, Version 2.0.

# Destructive system E2E: creates isolated memory cgroups and intentionally
# OOM-kills one Go, CPython and HotSpot process. Run only in a disposable VM.

set -euo pipefail

ROOT_DIR=${ROOT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
RUNTIME_ROOT=${HUATUO_RUNTIME_ROOT:-/opt/huatuo-runtime-matrix}
TEST_GO=${HUATUO_TEST_GO_BINARY:-${RUNTIME_ROOT}/go1.25.0/bin/go}
CGROUP_ROOT=/sys/fs/cgroup/memory
WORKSPACE=$(mktemp -d /tmp/huatuo-oom-memcg.XXXXXX)
RESULTS=${WORKSPACE}/results
CONFIG=${WORKSPACE}/huatuo-bamai.conf
HUATUO_BIN=${HUATUO_BAMAI_BIN:-${WORKSPACE}/huatuo-bamai}
JAVA_HOME=${HUATUO_JAVA_21:-${RUNTIME_ROOT}/jdk21}
PYTHON=${HUATUO_PYTHON_3_12:-${RUNTIME_ROOT}/python3.12/bin/python3}
GO_FIXTURE=${WORKSPACE}/go-fixture
JAVA_FIXTURE=${WORKSPACE}/java-fixture
SMALL_OBJECTS=${HUATUO_MEMCG_SMALL_OBJECTS:-10000}
LARGE_OBJECTS=${HUATUO_MEMCG_LARGE_OBJECTS:-32}
PYTHON_OBJECTS=${HUATUO_MEMCG_PYTHON_OBJECTS:-10000}
PYTHON_PAYLOAD_BYTES=${HUATUO_MEMCG_PYTHON_PAYLOAD_BYTES:-4096}
PYTHON_MIXED=${HUATUO_MEMCG_PYTHON_MIXED:-0}
LANGUAGES=${HUATUO_MEMCG_LANGUAGES:-go,python,java}
GATE_TIMEOUT_MS=${HUATUO_MEMCG_GATE_TIMEOUT_MS:-50}
EXPECT_GATE_ACK=${HUATUO_MEMCG_EXPECT_GATE_ACK:-1}
STOP_DAEMON_BEFORE_OOM=${HUATUO_MEMCG_STOP_DAEMON_BEFORE_OOM:-0}
STORM_CASES=${HUATUO_MEMCG_STORM_CASES:-0}
FAULT_INJECTION=${HUATUO_MEMCG_FAULT_INJECTION:-1}
# Stopping the daemon before the OOM forces the kernel to release the gate by
# its deadline; the later ACK necessarily misses, so the assertion must expect
# the fail-open snapshot rather than an acknowledged capture.
if [[ ${STOP_DAEMON_BEFORE_OOM} == 1 ]]; then
	EXPECT_GATE_ACK=0
fi
HUATUO_PID=""
ACTIVE_CGROUP=""
ACTIVE_CGROUPS=()
ACTIVE_PIDS=()
RELEASE_MAP_IDS_BEFORE="[]"
RELEASE_MAP_ID=""

log() { printf '[oom-runtime-memcg] %s\n' "$*"; }
fail() { printf '[oom-runtime-memcg] ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
	local status=$?
	for pid in "${ACTIVE_PIDS[@]}"; do
		kill -KILL "${pid}" 2>/dev/null || true
		wait "${pid}" 2>/dev/null || true
	done
	if [[ -n ${HUATUO_PID} ]]; then
		kill -CONT "${HUATUO_PID}" 2>/dev/null || true
		kill -TERM "${HUATUO_PID}" 2>/dev/null || true
		wait "${HUATUO_PID}" 2>/dev/null || true
	fi
	if [[ -n ${ACTIVE_CGROUP} ]]; then
		rmdir "${ACTIVE_CGROUP}" 2>/dev/null || true
	fi
	for cgroup in "${ACTIVE_CGROUPS[@]}"; do
		rmdir "${cgroup}" 2>/dev/null || true
	done
	if ((status == 0)); then
		rm -rf -- "${WORKSPACE}"
	else
		printf '[oom-runtime-memcg] artifacts retained at %s\n' "${WORKSPACE}" >&2
	fi
}
trap cleanup EXIT

[[ ${EUID} -eq 0 ]] || fail "requires root"
[[ -f ${CGROUP_ROOT}/memory.limit_in_bytes ]] || fail "requires cgroup v1 memory controller"
[[ -x ${TEST_GO} && -x ${JAVA_HOME}/bin/java && -x ${PYTHON} ]] ||
	fail "runtime matrix is incomplete"
mkdir -p "${RESULTS}" "${JAVA_FIXTURE}"
RELEASE_MAP_IDS_BEFORE=$(bpftool -j map show | jq -c \
	'[.[] | select(.name == "oom_snapshot_re") | .id]')
FAULT_MAP_IDS_BEFORE=$(bpftool -j map show | jq -c \
	'[.[] | select(.name == "oom_snapshot_fa") | .id]')

if [[ ! -x ${HUATUO_BIN} ]]; then
	log "building current huatuo-bamai"
	"${TEST_GO}" build -o "${HUATUO_BIN}" ./cmd/huatuo-bamai
fi
GO111MODULE=off GOTOOLCHAIN=local "${RUNTIME_ROOT}/go1.25.0/bin/go" build \
	-o "${GO_FIXTURE}" "${ROOT_DIR}/integration/fixtures/oom_runtime_snapshot/go/main.go"
"${JAVA_HOME}/bin/javac" -source 8 -target 8 -d "${JAVA_FIXTURE}" \
	"${ROOT_DIR}/integration/fixtures/oom_runtime_snapshot/java/HuatuoSnapshotFixture.java"

cat > "${CONFIG}" <<EOF
BlackList = ["arp", "ascend_npu", "cpu_stat", "cpu_util", "cpuidle", "cpusys", "dload", "dropwatch", "hungtask", "iolatency", "iotracing", "loadavg", "memburst", "memory_buddyinfo", "memory_events", "memory_free", "memory_others", "memory_reclaim", "memory_reclaim_events", "memory_vmstat", "metax_gpu", "mountpoint_perm", "net_rx_latency", "netdev", "netdev_bonding_lacp", "netdev_dcb", "netdev_events", "netdev_hw", "netdev_qdisc", "netdev_rdma_link", "netdev_txqueue_timeout", "netstat", "ras", "runqlat", "sockstat", "softirq", "softirq_tracing", "softlockup", "tcp_memory", "tcp_retransmit", "tracing_status"]

[Storage.LocalFile]
Path = "${RESULTS}"

[EventTracing.OOMRuntimeSnapshot]
Enabled = true
GateTimeoutMilliseconds = ${GATE_TIMEOUT_MS}
CaptureCooldownMilliseconds = 0
FailureCooldownMilliseconds = 1000
MaxFailureCooldownMilliseconds = 1000
MaxConcurrentGates = 1
MaxOutputBytes = 1048576
MaxObjects = 200000
MaxStacks = 4096
MaxStackDepth = 64
EOF

log "starting current huatuo-bamai"
"${HUATUO_BIN}" --config-dir "${WORKSPACE}" --config "$(basename "${CONFIG}")" \
	--bpf-dir "${ROOT_DIR}/bpf" --region oom-runtime-test --disable-kubelet \
	--log-debug > "${WORKSPACE}/huatuo.log" 2>&1 &
HUATUO_PID=$!
for _ in $(seq 1 100); do
	if ! kill -0 "${HUATUO_PID}" 2>/dev/null; then
		fail "huatuo-bamai exited during startup"
	fi
	if curl -fsS --max-time 1 http://127.0.0.1:19704/metrics >/dev/null 2>&1; then
		break
	fi
	sleep 0.1
done
curl -fsS --max-time 1 http://127.0.0.1:19704/metrics >/dev/null ||
	fail "huatuo-bamai did not become ready"
for _ in $(seq 1 150); do
	if ! kill -0 "${HUATUO_PID}" 2>/dev/null; then
		fail "huatuo-bamai exited before the OOM BPF event pipe became ready"
	fi
	if rg -q 'failed to initialize OOM runtime snapshot|start tracing oom:' \
		"${WORKSPACE}/huatuo.log"; then
		fail "OOM runtime snapshot failed to start"
	fi
	if rg -q 'attached BPF and created event pipe.*map_name="oom_perf_events"' \
		"${WORKSPACE}/huatuo.log"; then
		break
	fi
	sleep 0.1
done
rg -q 'attached BPF and created event pipe.*map_name="oom_perf_events"' \
	"${WORKSPACE}/huatuo.log" || fail "OOM BPF event pipe did not become ready"
RELEASE_MAP_ID=$(bpftool -j map show | jq -r \
	--argjson before "${RELEASE_MAP_IDS_BEFORE}" '
    [.[] | select(.name == "oom_snapshot_re") | .id
      | select(. as $id | ($before | index($id) | not))]
    | if length == 1 then .[0] else empty end')
[[ -n ${RELEASE_MAP_ID} ]] ||
	fail "could not uniquely identify this Huatuo instance's release map"
FAULT_MAP_ID=$(bpftool -j map show | jq -r \
	--argjson before "${FAULT_MAP_IDS_BEFORE}" '
    [.[] | select(.name == "oom_snapshot_fa") | .id
      | select(. as $id | ($before | index($id) | not))]
    | if length == 1 then .[0] else empty end')
[[ -n ${FAULT_MAP_ID} ]] ||
	fail "could not uniquely identify this Huatuo instance's fault injection map"

event_count() {
	[[ -s ${RESULTS}/oom ]] || { echo 0; return; }
	jq -s 'length' "${RESULTS}/oom"
}

language_enabled() {
	[[ ",${LANGUAGES}," == *",$1,"* ]]
}

wait_for_event() {
	local previous=$1
	for _ in $(seq 1 100); do
		if (( $(event_count) > previous )); then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

wait_for_events() {
	local expected=$1
	for _ in $(seq 1 200); do
		if (( $(event_count) >= expected )); then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

wait_for_process_exit() {
	local pid=$1 label=$2 state
	for _ in $(seq 1 400); do
		state=$(ps -o stat= -p "${pid}" 2>/dev/null || true)
		if [[ -z ${state} || ${state} == Z* ]]; then
			return 0
		fi
		sleep 0.05
	done
	kill -KILL "${pid}" 2>/dev/null || true
	fail "${label} did not exit within 20 seconds"
}

assert_latest_event() {
	local language=$1
	if [[ ${EXPECT_GATE_ACK} == 0 ]]; then
		jq -se '
          .[-1].tracer_data.runtime_memory_snapshot as $snapshot
          | ($snapshot.gate_release == "timeout_or_ack_missed")
            and ($snapshot.status
              | test("^(GATE_TIMEOUT|CAPTURE_FAILED|PARTIAL_)") )
        ' "${RESULTS}/oom" >/dev/null || fail "invalid fail-open OOM snapshot"
		jq -sr --arg language "${language}" '
          .[-1].tracer_data.runtime_memory_snapshot
          | "language=\($language) status=\(.status) entries=\(.entry_count) duration_ms=\(.capture_duration_ms) gate_release=\(.gate_release)"
        ' "${RESULTS}/oom"
		return
	fi
	jq -se --arg language "${language}" --arg python_mixed "${PYTHON_MIXED}" \
		--argjson python_objects "${PYTHON_OBJECTS}" '
      .[-1].tracer_data as $data
      | $data.runtime_memory_snapshot as $snapshot
      | (if $language == "go" then
          ($snapshot.runtime_version | startswith("go"))
        elif $language == "python" then
          ($snapshot.coverage.consistency | startswith("cpython_"))
        else
          ($snapshot.coverage.consistency == "best_effort_external_hotspot_heap_scan")
        end)
        and ($snapshot.gate_release == "ack")
        and ($snapshot.status
          | test("^(COMPLETE|PARTIAL_)") )
        and ($snapshot.entry_count > 0)
		and ($snapshot.capture_duration_ms <= 50)
        and (($snapshot.entries | length) > 0)
        and (if $language == "go" then
          any($snapshot.entries[]; .kind == "allocation_site")
        elif $language == "python" and $python_mixed == "1" then
          def count($name): first($snapshot.entries[]
            | select(.kind == "object_type" and .name == $name)
            | .inuse_objects);
          (count("__main__.HotPayload") as $hot
            | count("__main__.WarmPayload") as $warm
            | count("__main__.ColdPayload") as $cold
            | ($hot >= $python_objects * 6 * 0.8
              and $hot <= $python_objects * 6 * 1.2)
            and ($warm >= $python_objects * 3 * 0.8
              and $warm <= $python_objects * 3 * 1.2)
            and ($cold >= $python_objects * 0.8
              and $cold <= $python_objects * 1.2))
        else
          any($snapshot.entries[]; .kind == "object_type")
        end)
    ' "${RESULTS}/oom" >/dev/null ||
		fail "invalid ${language} OOM snapshot"
	jq -sr --arg language "${language}" '
      .[-1].tracer_data.runtime_memory_snapshot
	  | "language=\($language) status=\(.status) entries=\(.entry_count) duration_ms=\(.capture_duration_ms) runtime=\(.runtime_version // "") raw_coverage=\(.coverage.raw_coverage // 0) scanned_bytes=\(.coverage.scanned_bytes // 0) heap_bytes=\(.coverage.heap_used_bytes // 0) top=\(.entries[0].name // "")"
    ' "${RESULTS}/oom"
}

run_case() {
	local language=$1 limit_mib=$2
	shift 2
	local before status release_json gate_ns reason cookie release i
	local -a release_bytes
	before=$(event_count)
	ACTIVE_CGROUP="${CGROUP_ROOT}/huatuo-oom-runtime-${language}-$$"
	mkdir "${ACTIVE_CGROUP}"
	echo $((limit_mib * 1024 * 1024)) > "${ACTIVE_CGROUP}/memory.limit_in_bytes"
	echo 0 > "${ACTIVE_CGROUP}/memory.swappiness"
	log "triggering ${language} memcg OOM at ${limit_mib} MiB"
	if [[ ${STOP_DAEMON_BEFORE_OOM} == 1 ]]; then
		kill -STOP "${HUATUO_PID}"
	fi
	set +e
	bash -c 'echo $$ > "$1/tasks"; shift; exec "$@"' bash "${ACTIVE_CGROUP}" "$@"
	status=$?
	set -e
	[[ ${status} -eq 137 ]] || fail "${language} victim exit=${status}, want 137"
	if [[ ${STOP_DAEMON_BEFORE_OOM} == 1 ]]; then
		release_json=$(bpftool -j map dump id "${RELEASE_MAP_ID}" | jq -c '
          [.[] | select(.value[16] == "0x02" or .value[16] == "02")]
          | last // empty')
		[[ -n ${release_json} ]] || fail "deadline release record is unavailable"
		mapfile -t release_bytes < <(jq -r '.value[] | ltrimstr("0x")' \
			<<<"${release_json}")
		reason=$((16#${release_bytes[16]}))
		((reason == 2)) ||
			fail "gate was not released by its monotonic deadline: ${release_json}"
		cookie=0
		release=0
		for ((i = 0; i < 8; i++)); do
			((cookie |= 16#${release_bytes[i]} << (8 * i)))
			((release |= 16#${release_bytes[i + 8]} << (8 * i)))
		done
		gate_ns=$((release - cookie))
		((gate_ns >= 45000000 && gate_ns <= 60000000)) ||
			fail "gate duration ${gate_ns}ns is outside the 45-60ms deadline window"
		log "kernel fail-open reason=deadline duration_ns=${gate_ns}"
		kill -CONT "${HUATUO_PID}"
	fi
	rmdir "${ACTIVE_CGROUP}"
	ACTIVE_CGROUP=""
	wait_for_event "${before}" || fail "${language} OOM event was not persisted"
	assert_latest_event "${language}"
}

run_storm_case() {
	local before expected cgroup status i pid pid_csv
	local -a pids=() logs=()
	((STORM_CASES >= 2)) || fail "storm case count must be at least 2"
	before=$(event_count)
	log "triggering ${STORM_CASES} concurrent memcg OOMs with the daemon live"
	for i in $(seq 1 "${STORM_CASES}"); do
		cgroup="${CGROUP_ROOT}/huatuo-oom-runtime-storm-${i}-$$"
		mkdir "${cgroup}"
		echo $((96 * 1024 * 1024)) > "${cgroup}/memory.limit_in_bytes"
		echo 0 > "${cgroup}/memory.swappiness"
		ACTIVE_CGROUPS+=("${cgroup}")
		logs+=("${WORKSPACE}/storm-${i}.log")
		bash -c 'echo $$ > "$1/tasks"; shift; exec "$@"' bash "${cgroup}" \
			env HUATUO_FIXTURE_OOM=1 HUATUO_FIXTURE_WORKERS=1 \
			HUATUO_FIXTURE_WAIT_SIGNAL=1 \
			HUATUO_FIXTURE_SMALL_OBJECTS=1000 \
			HUATUO_FIXTURE_LARGE_OBJECTS=1 \
			"${GO_FIXTURE}" \
			> "${logs[i - 1]}" 2>&1 &
		pids+=("$!")
		ACTIVE_PIDS+=("$!")
	done
	for i in $(seq 0 $((STORM_CASES - 1))); do
		for _ in $(seq 1 100); do
			rg -q '^READY ' "${logs[i]}" 2>/dev/null && break
			kill -0 "${pids[i]}" 2>/dev/null ||
				fail "storm victim ${pids[i]} exited before READY"
			sleep 0.05
		done
		rg -q '^READY ' "${logs[i]}" || fail "storm victim ${pids[i]} was not ready"
	done
	for pid in "${pids[@]}"; do
		kill -USR1 "${pid}"
	done
	for pid in "${pids[@]}"; do
		wait_for_process_exit "${pid}" "storm victim ${pid}"
		set +e
		wait "${pid}"
		status=$?
		set -e
		[[ ${status} -eq 137 ]] || fail "storm victim ${pid} exit=${status}, want 137"
	done
	ACTIVE_PIDS=()
	expected=$((before + STORM_CASES))
	wait_for_events "${expected}" || fail "storm OOM events were not persisted"
	pid_csv=$(IFS=,; echo "${pids[*]}")
	jq -se --arg pids "${pid_csv}" --argjson before "${before}" \
		--argjson count "${STORM_CASES}" '
		($pids | split(",") | map(tonumber)) as $want
		| [.[$before:][]
		    | select(.tracer_data.victim.pid as $pid | $want | index($pid))] as $events
		| ($events | length) == $count
		  and ([$events[].tracer_data.victim.pid] | unique | length) == $count
		  and (any($events[].tracer_data.runtime_memory_snapshot;
		    .gate_release == "ack"))
		  and all($events[].tracer_data.runtime_memory_snapshot;
		    if .gate_release == "ack" then
		      (.status | test("^(COMPLETE|PARTIAL_)"))
		      and .entry_count > 0
		      and (.runtime_version | startswith("go"))
		    else
		      (.status | test("^(SKIPPED_BUSY|SKIPPED_COOLDOWN)"))
		      and .entry_count == 0
		    end)
	' "${RESULTS}/oom" >/dev/null || fail "storm events were missing, cross-wired, or mislabeled"
	log "storm passed victims=${STORM_CASES} with first-wins admission and clean skips"
	for cgroup in "${ACTIVE_CGROUPS[@]}"; do
		rmdir "${cgroup}"
	done
	ACTIVE_CGROUPS=()
}

# run_fault_case arms a kernel-side fail-open path, OOM-kills a Go victim, and
# asserts that the expected reason was recorded. Fault injection is test-only:
# the BPF fault map defaults to zero and is re-armed then disarmed around each
# victim so production gate behavior is unchanged.
run_fault_case() {
	local fault_code=$1 want_reason=$2 label=$3
	local release_json status cgroup i
	cgroup="${CGROUP_ROOT}/huatuo-oom-runtime-fault-${fault_code}-$$"
	mkdir "${cgroup}"
	echo $((192 * 1024 * 1024)) > "${cgroup}/memory.limit_in_bytes"
	echo 0 > "${cgroup}/memory.swappiness"
	bpftool map update id "${FAULT_MAP_ID}" key 0 0 0 0 \
		value "${fault_code}" 0 0 0 2>/dev/null ||
		fail "could not arm OOM snapshot fault ${label}"
	log "triggering fault=${label} code=${fault_code}"
	set +e
	bash -c 'echo $$ > "$1/tasks"; shift; exec "$@"' bash "${cgroup}" \
		env HUATUO_FIXTURE_OOM=1 HUATUO_FIXTURE_WORKERS=1 \
		HUATUO_FIXTURE_SMALL_OBJECTS=1000 "${GO_FIXTURE}"
	status=$?
	set -e
	[[ ${status} -eq 137 ]] || fail "fault ${label} victim exit=${status}, want 137"
	bpftool map update id "${FAULT_MAP_ID}" key 0 0 0 0 \
		value 0 0 0 0 2>/dev/null ||
		fail "could not disarm OOM snapshot fault ${label}"
	rmdir "${cgroup}"

	if [[ ${fault_code} == 1 ]]; then
		# PERF_OUTPUT fault never delivers the event, so the release record
		# remains in the map for a kernel-side assertion.
		release_json=$(bpftool -j map dump id "${RELEASE_MAP_ID}" | jq -c \
			--arg want "0x0${want_reason}" --arg want_plain "0${want_reason}" '
          [.[] | select(.value[16] == $want or .value[16] == $want_plain)]
          | last // empty')
		[[ -n ${release_json} ]] ||
			fail "fault ${label} release reason ${want_reason} was not recorded"
	else
		# WORK_LIMIT delivers the event, so userspace consumes the release
		# record and logs the observed release reason.
		for i in $(seq 1 50); do
			rg -q "BPF released OOM Runtime snapshot gate via ${label}" \
				"${WORKSPACE}/huatuo.log" && break
			sleep 0.1
		done
		rg -q "BPF released OOM Runtime snapshot gate via ${label}" \
			"${WORKSPACE}/huatuo.log" ||
			fail "fault ${label} was not observed in the daemon log"
	fi
	log "kernel fail-open reason=${label} confirmed"
}

if language_enabled go; then
	run_case go 192 env HUATUO_FIXTURE_OOM=1 \
		HUATUO_FIXTURE_SMALL_OBJECTS="${SMALL_OBJECTS}" \
		HUATUO_FIXTURE_LARGE_OBJECTS="${LARGE_OBJECTS}" "${GO_FIXTURE}"
fi
if language_enabled python; then
	run_case python 192 env HUATUO_FIXTURE_OBJECTS="${PYTHON_OBJECTS}" \
		HUATUO_MEMCG_PYTHON_MIXED="${PYTHON_MIXED}" \
		HUATUO_FIXTURE_PAYLOAD_BYTES="${PYTHON_PAYLOAD_BYTES}" "${PYTHON}" -c '
import os,time
class Payload:
 def __init__(self): self.data=bytearray(int(os.environ["HUATUO_FIXTURE_PAYLOAD_BYTES"]))
class HotPayload: pass
class WarmPayload: pass
class ColdPayload: pass
if os.getenv("HUATUO_MEMCG_PYTHON_MIXED") == "1":
 n=int(os.environ["HUATUO_FIXTURE_OBJECTS"])
 items=[HotPayload() for _ in range(n*6)]
 items += [WarmPayload() for _ in range(n*3)]
 items += [ColdPayload() for _ in range(n)]
else:
 items=[Payload() for _ in range(int(os.environ["HUATUO_FIXTURE_OBJECTS"]))]
while True:
 value=bytearray(8*1024*1024);value[::4096]=b"x"*(len(value)//4096);items.append(value);time.sleep(.01)'
fi
if language_enabled java; then
	run_case java 384 env HUATUO_FIXTURE_OOM=1 \
		HUATUO_FIXTURE_SMALL_OBJECTS="${SMALL_OBJECTS}" \
		HUATUO_FIXTURE_LARGE_OBJECTS="${LARGE_OBJECTS}" \
		"${JAVA_HOME}/bin/java" -XX:+UseG1GC \
		-XX:-UseContainerSupport -Xms64m -Xmx2g -cp "${JAVA_FIXTURE}" HuatuoSnapshotFixture
fi

if ((STORM_CASES > 0)); then
	run_storm_case
fi

if [[ ${EXPECT_GATE_ACK} == 1 ]]; then
	! rg -q 'ack OOM Runtime snapshot cookie' "${WORKSPACE}/huatuo.log" || \
		fail "one or more OOM Runtime snapshot ACKs missed the gate deadline"
else
	rg -q 'ack OOM Runtime snapshot cookie' "${WORKSPACE}/huatuo.log" || \
		fail "expected the OOM Runtime snapshot ACK to miss the gate deadline"
fi

if [[ ${FAULT_INJECTION} == 1 ]]; then
	run_fault_case 1 4 perf_output_failed
	# PERF_OUTPUT failure arms the failure cooldown. Wait for it to expire so
	# the next fault is admitted rather than skipped as SKIPPED_COOLDOWN.
	sleep 1.5
	run_fault_case 2 3 work_limit
fi

log "all real memcg OOM cases passed"
