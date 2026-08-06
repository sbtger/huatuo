#!/usr/bin/env bash

# Copyright 2026 The HuaTuo Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Verify only a real memcg OOM SIGKILL produces a correlated Java stack profile.

set -euo pipefail

source "${ROOT_DIR}/integration/lib.sh"

readonly FIXTURE_SOURCE="${ROOT_DIR}/integration/testdata/JavaOOMStackFixture.java"
readonly CGROUP_PARENT="/sys/fs/cgroup/memory"
readonly CGROUP_DIR="${CGROUP_PARENT}/huatuo-java-stack-$$"
readonly OUTPUT_DIR="${HUATUO_BAMAI_TEST_TMPDIR}/events"
readonly FIXTURE_DIR="${HUATUO_BAMAI_TEST_TMPDIR}/java"

command -v java > /dev/null || skip "java command is not installed"
command -v javac > /dev/null || skip "javac command is not installed"
command -v jq > /dev/null || skip "jq command is not installed"
[[ -w "${CGROUP_PARENT}" ]] || skip "writable cgroup v1 memory controller is unavailable"
[[ -w "${CGROUP_PARENT}/tasks" ]] || skip "cgroup v1 memory tasks file is unavailable"

java_pid=""

cleanup() {
	if [[ -n "${java_pid}" ]] && kill -0 "${java_pid}" 2> /dev/null; then
		kill -KILL "${java_pid}" 2> /dev/null || true
		wait "${java_pid}" 2> /dev/null || true
	fi
	if [[ -d "${CGROUP_DIR}" ]]; then
		rmdir "${CGROUP_DIR}" 2> /dev/null || true
	fi
	huatuo_bamai_stop
}
trap cleanup EXIT

write_java_oom_config() {
	cat > "${HUATUO_BAMAI_TEST_TMPDIR}/bamai.conf" << EOF
BlackList = ["arp", "ascend_npu", "cpu_stat", "cpu_util", "cpuidle", "cpusys", "dload", "dropwatch", "hungtask", "iolatency", "iotracing", "loadavg", "memburst", "memory_buddyinfo", "memory_events", "memory_free", "memory_others", "memory_reclaim", "memory_reclaim_events", "memory_vmstat", "metax_gpu", "mountpoint_perm", "net_rx_latency", "netdev", "netdev_bonding_lacp", "netdev_dcb", "netdev_events", "netdev_hw", "netdev_qdisc", "netdev_rdma_link", "netdev_txqueue_timeout", "netstat", "ras", "runqlat", "sockstat", "softirq", "softirq_tracing", "softlockup", "tcp_memory", "tracing_status"]

[HTTPServer]
    ListenAddress = "127.0.0.1:19704"

[Storage.LocalFile]
    Path = "${OUTPUT_DIR}"
    RotationSizeMiB = 32
    MaxRotatedFiles = 2

[EventTracing.OOMJavaStack]
    Enabled = true
    ReconcileIntervalSeconds = 1
    MaxTargets = 16
EOF
}

java_capture_count() {
	huatuo_bamai_metrics | awk '
        /^huatuo_bamai_oom_java_stack_capture_total{/ { print int($2); found = 1 }
        END { if (!found) print 0 }
    '
}

java_error_count() {
	huatuo_bamai_metrics | awk '
        /^huatuo_bamai_oom_java_stack_error_total{/ { print int($2); found = 1 }
        END { if (!found) print 0 }
    '
}

profile_written() {
	[[ -s "${OUTPUT_DIR}/oom" && -s "${OUTPUT_DIR}/oom-java-stack" ]]
}

start_java() {
	local mode=$1
	java -Xms32m -Xmx1g -XX:+PreserveFramePointer \
		-cp "${FIXTURE_DIR}" JavaOOMStackFixture "${mode}" \
		> "${HUATUO_BAMAI_TEST_TMPDIR}/java-${mode}.log" 2>&1 &
	java_pid=$!
}

mkdir -p "${OUTPUT_DIR}" "${FIXTURE_DIR}"
javac -d "${FIXTURE_DIR}" "${FIXTURE_SOURCE}"

integration_huatuo_bamai_start write_java_oom_config \
	--bpf-dir "${ROOT_DIR}/_output/bpf" \
	--disable-kubelet \
	--disable-cgroup \
	--region integration \
	--log-debug

start_java 30
sleep 3
kill -KILL "${java_pid}"
wait "${java_pid}" 2> /dev/null || true
java_pid=""
[[ "$(java_capture_count)" -eq 0 ]] \
	|| fatal "ordinary SIGKILL was incorrectly captured as an OOM stack"

mkdir "${CGROUP_DIR}"
printf '%s\n' 134217728 > "${CGROUP_DIR}/memory.limit_in_bytes"
start_java oom
printf '%s\n' "${java_pid}" > "${CGROUP_DIR}/tasks"
set +e
wait "${java_pid}"
java_status=$?
set -e
java_pid=""
[[ ${java_status} -eq 137 ]] || fatal "Java OOM victim exited with status ${java_status}, want 137"
grep -q '^oom_kill_local 1$' "${CGROUP_DIR}/memory.oom_control" \
	|| fatal "memory cgroup did not report one local OOM kill"

wait_until 10 1 profile_written || fatal "correlated Java OOM profile was not persisted"
[[ "$(java_capture_count)" -eq 1 ]] || fatal "expected one Java OOM stack capture"
[[ "$(java_error_count)" -eq 0 ]] || fatal "Java OOM stack capture reported an error"

base_id=$(jq -r '.tracer_id' "${OUTPUT_DIR}/oom")
stack_id=$(jq -r '.tracer_id' "${OUTPUT_DIR}/oom-java-stack")
[[ -n "${base_id}" && "${base_id}" == "${stack_id}" ]] \
	|| fatal "base OOM and Java stack profile correlation IDs differ"
jq -e '
    .tracer_name == "oom-java-stack" and
    .tracer_type == "event" and
    .tracer_data.flamedata.profile_type == "event:samples:count:event:count" and
    .tracer_data.oom_correlation.victim_pid > 0 and
    .tracer_data.capture.raw_depth > 0 and
    .tracer_data.capture.hotspot_direct_available == true and
    .tracer_data.capture.hotspot_direct_errors <= 16 and
    .tracer_data.capture.hotspot_unwound == true and
    .tracer_data.capture.bpf_capture_duration_ns > 0 and
    ((.tracer_data.capture.thread_group_scanned == true and
      .tracer_data.capture.snapshot_semantics == "selected_thread_group_member") or
     (.tracer_data.capture.thread_group_scanned == false and
      .tracer_data.capture.snapshot_semantics == "current_signal_thread")) and
    .tracer_data.capture.complete == false and
    (.tracer_data.frames | length) == .tracer_data.capture.resolved_frames and
    .tracer_data.capture.resolved_frames > 0 and
    all(.tracer_data.frames[]; .kind == "java") and
    any(.tracer_data.frames[]; .name | contains("JavaOOMStackFixture"))
' "${OUTPUT_DIR}/oom-java-stack" > /dev/null \
	|| fatal "Java OOM stack profile metadata is incomplete"
