#!/usr/bin/env bash

# Copyright 2026 The HuaTuo Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Verify the complete cgroup v1/v2 path: memory pressure notification, victim
# selection, Go heap capture, cooldown, and local persistence.
# Go is the representative runtime for this shared event path.

set -euo pipefail

source "${ROOT_DIR}/integration/lib.sh"
source "${ROOT_DIR}/integration/config.sh"

readonly FIXTURE_SOURCE="${ROOT_DIR}/integration/testdata/test_before_oom_heap.go"
readonly MEMORY_LIMIT_MIB=48
readonly THRESHOLD_PERCENT=60
readonly INITIAL_ALLOCATION_MIB=8
readonly ALLOCATION_STEP_MIB=2
readonly PRESSURE_MARGIN_MIB=4
readonly MIB=$((1 << 20))

[[ $EUID -eq 0 ]] || skip "requires root"
if [[ -r /sys/fs/cgroup/memory/memory.usage_in_bytes &&
	-w /sys/fs/cgroup/memory/cgroup.event_control ]]; then
	readonly CGROUP_MODE=v1
	readonly CGROUP_ROOT=/sys/fs/cgroup/memory
	readonly MEMORY_USAGE_FILE=memory.usage_in_bytes
	readonly MEMORY_LIMIT_FILE=memory.limit_in_bytes
elif [[ -r /sys/fs/cgroup/cgroup.controllers ]]; then
	readonly CGROUP_MODE=v2
	readonly CGROUP_ROOT=/sys/fs/cgroup
	readonly MEMORY_USAGE_FILE=memory.current
	readonly MEMORY_LIMIT_FILE=memory.max
else
	skip "requires a supported cgroup v1/v2 memory hierarchy"
fi
[[ -x "${HUATUO_BAMAI_BIN}" ]] \
	|| fatal "huatuo-bamai binary not found: ${HUATUO_BAMAI_BIN}"
for object in cgroup_css_events.o cgroup_css_sync.o; do
	[[ -r "${ROOT_DIR}/_output/bpf/${object}" ]] \
		|| fatal "BPF object not found: ${ROOT_DIR}/_output/bpf/${object}"
done

WORK_DIR=$(mktemp -d "${HUATUO_BAMAI_TEST_TMPDIR}/before-oom.XXXXXX")
FIXTURE_BIN="${WORK_DIR}/test-before-oom-heap"
PODS_FILE="${WORK_DIR}/pods.json"
KUBELET_CERT="${WORK_DIR}/kubelet.crt"
KUBELET_KEY="${WORK_DIR}/kubelet.key"
KUBELET_LOG="${WORK_DIR}/kubelet.log"
RUNTIME_ROOT="${WORK_DIR}/docker"
RUNTIME_SOCKET="${WORK_DIR}/docker.sock"
RUNTIME_LOG="${WORK_DIR}/runtime.log"
WORKLOAD_OUT="${WORK_DIR}/workload.out"
CONTROL_FIFO="${WORK_DIR}/control.fifo"
EVENT_FILE="${HUATUO_BAMAI_TEST_TMPDIR}/events/before_oom_memory_snapshot"
printf -v CONTAINER_ID '%064x' "${BASHPID}"
readonly CONTAINER_ID
KUBELET_PID=""
RUNTIME_PID=""
WORKLOAD_PID=""
CONTROL_FD_OPEN=false
CGROUP_DIR=""

cleanup() {
	huatuo_bamai_stop || true
	if [[ -n "${WORKLOAD_PID}" ]]; then
		stop_by_pid "${WORKLOAD_PID}" 3 || true
	fi
	if [[ "${CONTROL_FD_OPEN}" == true ]]; then
		exec 9>&-
		CONTROL_FD_OPEN=false
	fi
	if [[ -n "${KUBELET_PID}" ]]; then
		stop_by_pid "${KUBELET_PID}" 3 || true
	fi
	if [[ -n "${RUNTIME_PID}" ]]; then
		stop_by_pid "${RUNTIME_PID}" 3 || true
	fi
	if [[ -n "${CGROUP_DIR}" && -d "${CGROUP_DIR}" ]]; then
		rmdir "${CGROUP_DIR}" 2> /dev/null || true
	fi
}
trap cleanup EXIT

log_info "building low-memory Go fixture"
GO111MODULE=off go build -o "${FIXTURE_BIN}" "${FIXTURE_SOURCE}"

cgroup_path="/huatuo-before-oom-${CONTAINER_ID}"
CGROUP_DIR="${CGROUP_ROOT}${cgroup_path}"
mkdir "${CGROUP_DIR}" || skip "cannot create a cgroup ${CGROUP_MODE} test group"
memory_limit_bytes=$((MEMORY_LIMIT_MIB * MIB))
echo "${memory_limit_bytes}" > "${CGROUP_DIR}/${MEMORY_LIMIT_FILE}" \
	|| fatal "failed to set the cgroup memory limit"
[[ -w "${CGROUP_DIR}/cgroup.procs" &&
	-r "${CGROUP_DIR}/${MEMORY_USAGE_FILE}" &&
	-r "${CGROUP_DIR}/${MEMORY_LIMIT_FILE}" ]] \
	|| fatal "test memory cgroup is not writable: ${CGROUP_DIR}"
if [[ ${CGROUP_MODE} == v1 ]]; then
	[[ -w "${CGROUP_DIR}/cgroup.event_control" ]] \
		|| fatal "cgroup v1 event control is not writable: ${CGROUP_DIR}"
else
	[[ -w "${CGROUP_DIR}/memory.high" ]] \
		|| fatal "cgroup v2 memory.high is not writable: ${CGROUP_DIR}"
	if [[ -r "${CGROUP_DIR}/memory.events.local" ]]; then
		MEMORY_EVENTS_FILE="${CGROUP_DIR}/memory.events.local"
	elif [[ -r "${CGROUP_DIR}/memory.events" ]]; then
		MEMORY_EVENTS_FILE="${CGROUP_DIR}/memory.events"
	else
		fatal "cgroup v2 memory events are unavailable: ${CGROUP_DIR}"
	fi
	readonly MEMORY_EVENTS_FILE
fi

memory_max=$(< "${CGROUP_DIR}/${MEMORY_LIMIT_FILE}")
[[ "${memory_max}" =~ ^[0-9]+$ ]] \
	|| fatal "cgroup has no finite memory limit: ${memory_max}"
threshold_bytes=$((memory_max * THRESHOLD_PERCENT / 100))
pressure_target_bytes=$((threshold_bytes + PRESSURE_MARGIN_MIB * MIB))
((pressure_target_bytes < memory_max)) \
	|| fatal "cgroup limit leaves no room above the notification threshold"
if [[ ${CGROUP_MODE} == v2 ]]; then
	# Cgroup v2 cannot notify an arbitrary memory.current/memory.max ratio.
	# Align memory.high with the configured percentage so crossing it updates
	# memory.events(.local), which is the event source used by the watcher.
	echo "${threshold_bytes}" > "${CGROUP_DIR}/memory.high"
fi

mkfifo "${CONTROL_FIFO}"
exec 9<> "${CONTROL_FIFO}"
CONTROL_FD_OPEN=true
"${FIXTURE_BIN}" workload < "${CONTROL_FIFO}" > "${WORKLOAD_OUT}" 2>&1 &
WORKLOAD_PID=$!

workload_reached() {
	local wanted=$1
	grep -q "^allocated_mib=${wanted}$" "${WORKLOAD_OUT}"
}
wait_until 5 0.2 grep -q '^ready$' "${WORKLOAD_OUT}" \
	|| fatal "Go workload did not become ready"

echo "${WORKLOAD_PID}" > "${CGROUP_DIR}/cgroup.procs"
echo 900 > "/proc/${WORKLOAD_PID}/oom_score_adj"
sleep 0.2

# The pod manager only needs Docker's /info response plus the on-disk init PID
# state. A local stub preserves that production path without a Docker daemon.
mkdir -p "${RUNTIME_ROOT}/containers/${CONTAINER_ID}"
cat > "${RUNTIME_ROOT}/containers/${CONTAINER_ID}/config.v2.json" << EOF
{"State":{"Pid":${WORKLOAD_PID}}}
EOF
"${FIXTURE_BIN}" runtime \
	--socket "${RUNTIME_SOCKET}" \
	--root "${RUNTIME_ROOT}" \
	> "${RUNTIME_LOG}" 2>&1 &
RUNTIME_PID=$!
wait_until 5 0.2 test -S "${RUNTIME_SOCKET}" \
	|| fatal "container runtime stub did not become ready"

DOCKER_HOST="unix://${RUNTIME_SOCKET}"
BEFORE_OOM_DOCKER_API_VERSION=1.41
BEFORE_OOM_KUBELET_PORT=$(allocate_available_port) \
	|| fatal "failed to allocate kubelet stub port"
BEFORE_OOM_KUBELET_CERT="${KUBELET_CERT}"
BEFORE_OOM_KUBELET_KEY="${KUBELET_KEY}"
export DOCKER_HOST BEFORE_OOM_DOCKER_API_VERSION BEFORE_OOM_KUBELET_PORT
export BEFORE_OOM_KUBELET_CERT BEFORE_OOM_KUBELET_KEY

started_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > "${PODS_FILE}" << EOF
{
  "apiVersion": "v1",
  "kind": "PodList",
  "items": [{
    "metadata": {
      "name": "before-oom-e2e",
      "namespace": "before-oom-e2e",
      "uid": "00000000-0000-0000-0000-000000000001"
    },
    "spec": {
      "hostname": "before-oom-e2e",
      "containers": [{
        "name": "go-heap",
        "image": "before-oom-e2e",
        "resources": {
          "requests": {"memory": "48Mi"},
          "limits": {"memory": "48Mi"}
        }
      }]
    },
    "status": {
      "phase": "Running",
      "podIP": "127.0.0.2",
      "qosClass": "Guaranteed",
      "containerStatuses": [{
        "name": "go-heap",
        "image": "before-oom-e2e",
        "imageID": "",
        "containerID": "docker://${CONTAINER_ID}",
        "ready": true,
        "restartCount": 0,
        "state": {"running": {"startedAt": "${started_at}"}}
      }]
    }
  }]
}
EOF

"${FIXTURE_BIN}" kubelet \
	--listen "127.0.0.1:${BEFORE_OOM_KUBELET_PORT}" \
	--cert "${KUBELET_CERT}" \
	--key "${KUBELET_KEY}" \
	--pods "${PODS_FILE}" \
	> "${KUBELET_LOG}" 2>&1 &
KUBELET_PID=$!

kubelet_ready() {
	curl -skf "https://127.0.0.1:${BEFORE_OOM_KUBELET_PORT}/pods" > /dev/null
}
wait_until 10 1 kubelet_ready || fatal "kubelet stub did not become ready"

integration_huatuo_bamai_start write_before_oom_memory_snapshot_config \
	--region dev \
	--bpf-dir "${ROOT_DIR}/_output/bpf" \
	--tools-bin-dir "${ROOT_DIR}/_output/bin" \
	--log-debug

container_synced() {
	curl -sf "${CURL_TIMEOUT[@]}" "${HUATUO_BAMAI_PODS_API}" \
		| grep -q "${CONTAINER_ID}"
}
wait_until 15 1 container_synced \
	|| fatal "container metadata was not synchronized"

memory_usage=$(< "${CGROUP_DIR}/${MEMORY_USAGE_FILE}")
((threshold_bytes - memory_usage >= 16 * MIB)) \
	|| skip "insufficient cgroup headroom for a low-memory threshold test"

memory_usage_below() {
	local boundary=$1 current
	current=$(< "${CGROUP_DIR}/${MEMORY_USAGE_FILE}")
	[[ "${current}" =~ ^[0-9]+$ ]] && ((current < boundary))
}
snapshot_count() {
	awk 'NF { count++ } END { print count + 0 }' "${EVENT_FILE}" \
		2> /dev/null || echo 0
}
snapshot_saved() {
	[[ -s "${EVENT_FILE}" ]] && [[ "$(snapshot_count)" -ge 1 ]]
}
v2_high_count() {
	awk '$1 == "high" { print $2; found = 1 } END { exit !found }' \
		"${MEMORY_EVENTS_FILE}"
}
v2_high_increased() {
	local baseline=$1 current
	current=$(v2_high_count) || return 1
	((current > baseline))
}
if [[ ${CGROUP_MODE} == v2 ]]; then
	v2_high_before=$(v2_high_count) \
		|| fatal "failed to read the initial cgroup v2 high counter"
fi

printf '%s\n' "${INITIAL_ALLOCATION_MIB}" >&9
wait_until 5 0.2 workload_reached "${INITIAL_ALLOCATION_MIB}" \
	|| fatal "Go workload did not complete its below-threshold allocation"
memory_usage=$(< "${CGROUP_DIR}/${MEMORY_USAGE_FILE}")
((memory_usage < threshold_bytes)) \
	|| fatal "below-threshold stage unexpectedly crossed ${THRESHOLD_PERCENT}%"
sleep 1
[[ "$(snapshot_count)" -eq 0 ]] \
	|| fatal "below-threshold allocation produced a snapshot"

allocated_mib=${INITIAL_ALLOCATION_MIB}
# cgroup v1 memory.usage_in_bytes is approximate and threshold wakeups can lag
# batched page accounting. Keep a small margin above the configured threshold
# so the test does not stop at a value visible only to the userspace read. Once
# the threshold is visibly crossed, however, give the bounded capture time to
# persist before adding more pressure. This avoids forcing a memory.high-
# throttled v2 workload toward the fixed margin after the event already fired.
while ((memory_usage < pressure_target_bytes)); do
	if ((memory_usage >= threshold_bytes)) \
		&& wait_until 5 0.2 snapshot_saved > /dev/null 2>&1; then
		memory_usage=$(< "${CGROUP_DIR}/${MEMORY_USAGE_FILE}")
		break
	fi
	allocated_mib=$((allocated_mib + ALLOCATION_STEP_MIB))
	((allocated_mib <= 40)) \
		|| fatal "workload could not cross the threshold within the memory budget"
	printf '%s\n' "${ALLOCATION_STEP_MIB}" >&9
	wait_until 5 0.2 workload_reached "${allocated_mib}" \
		|| fatal "Go workload did not reach ${allocated_mib} MiB"
	memory_usage=$(< "${CGROUP_DIR}/${MEMORY_USAGE_FILE}")
done

wait_until 20 1 snapshot_saved || fatal "before-OOM snapshot was not persisted"
if [[ ${CGROUP_MODE} == v2 ]]; then
	v2_high_after=$(v2_high_count) \
		|| fatal "failed to read the final cgroup v2 high counter"
	((v2_high_after > v2_high_before)) \
		|| fatal "cgroup v2 memory.high counter did not increase"
fi

"${FIXTURE_BIN}" validate \
	--events "${EVENT_FILE}" \
	--container-id "${CONTAINER_ID}" \
	--cgroup "${cgroup_path}" \
	--memory-max "${memory_max}" \
	--pid "${WORKLOAD_PID}" \
	--threshold "${THRESHOLD_PERCENT}" \
	|| fatal "persisted before-OOM snapshot failed content validation"

saved_count=$(snapshot_count)
printf 'reset\n' >&9
wait_until 10 0.2 workload_reached 0 \
	|| fatal "Go workload did not release its heap"
wait_until 10 0.2 memory_usage_below "${threshold_bytes}" \
	|| fatal "cgroup usage did not fall below the ${CGROUP_MODE} threshold"

# Cross the same kernel threshold again while the first snapshot is still in
# cooldown. A second pressure notification must not create another document.
allocated_mib=0
memory_usage=$(< "${CGROUP_DIR}/${MEMORY_USAGE_FILE}")
while ((memory_usage < pressure_target_bytes)); do
	# During cooldown no second snapshot is expected. On v2, the high counter is
	# the positive evidence that the same pressure source fired, so stop adding
	# memory as soon as it advances instead of forcing the workload to the v1
	# accounting margin.
	if [[ ${CGROUP_MODE} == v2 ]] && ((memory_usage >= threshold_bytes)) \
		&& wait_until 5 0.2 v2_high_increased "${v2_high_after}" \
			> /dev/null 2>&1; then
		memory_usage=$(< "${CGROUP_DIR}/${MEMORY_USAGE_FILE}")
		break
	fi
	allocated_mib=$((allocated_mib + ALLOCATION_STEP_MIB))
	((allocated_mib <= 40)) \
		|| fatal "cooldown workload could not cross the memory threshold"
	printf '%s\n' "${ALLOCATION_STEP_MIB}" >&9
	wait_until 5 0.2 workload_reached "${allocated_mib}" \
		|| fatal "Go workload did not reach ${allocated_mib} MiB during cooldown"
	memory_usage=$(< "${CGROUP_DIR}/${MEMORY_USAGE_FILE}")
done
sleep 1
if [[ ${CGROUP_MODE} == v2 ]]; then
	v2_high_cooldown=$(v2_high_count) \
		|| fatal "failed to read the cooldown cgroup v2 high counter"
	((v2_high_cooldown > v2_high_after)) \
		|| fatal "cooldown workload did not produce cgroup v2 memory.high pressure"
fi
[[ "$(snapshot_count)" -eq "${saved_count}" ]] \
	|| fatal "cooldown allowed a duplicate before-OOM snapshot"

assert_log_has_no_failure \
	"${HUATUO_BAMAI_TEST_TMPDIR}/huatuo.log" "huatuo-bamai"

memory_usage=$(< "${CGROUP_DIR}/${MEMORY_USAGE_FILE}")
peak_mib=$(((memory_usage + MIB - 1) / MIB))
log_info "before-OOM cgroup ${CGROUP_MODE} E2E passed (peak~${peak_mib} MiB, entries<=3)"
