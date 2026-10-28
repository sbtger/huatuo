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

set -euo pipefail
source "${ROOT_DIR}/integration/lib_observability.sh"

assert_memory_load_failure() {
	local expected=$1
	wait_until 15 .1 grep -Fq "required map" "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo.log" \
		|| fatal "missing map error was not reported"
	grep -Fq "${expected}" "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo.log" \
		|| fatal "error omitted the required map name"
	! grep -Fq 'panic:' "${HUATUO_BAMAI_TEST_TMPDIR}/huatuo.log" \
		|| fatal "wrong BPF object crashed the daemon"
	huatuo_bamai_collect_metrics
	assert_huatuo_bamai_shutdown_with_signal TERM
}

mkdir "${HUATUO_BAMAI_TEST_TMPDIR}/bpf"
for observability_component in memory_free memory_reclaim; do
	case "${observability_component}" in
	memory_free)
		memory_object=memory_free_compact.o
		memory_map=mm_free_compact_map
		;;
	memory_reclaim)
		memory_object=memory_reclaim.o
		memory_map=memory_cgroup_allocpages_stall
		;;
	esac
	# A valid ELF with unrelated maps must fail through the loader error path.
	cp "${ROOT_DIR}/_output/bpf/cgroup_css_sync.o" "${HUATUO_BAMAI_TEST_TMPDIR}/bpf/${memory_object}"
	integration_huatuo_bamai_start write_config_bamai_observability \
		--region integration --disable-kubelet --log-debug \
		--bpf-dir "${HUATUO_BAMAI_TEST_TMPDIR}/bpf"
	assert_memory_load_failure "${memory_map}"
done
