// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __BPF_ABI_OOM_H__
#define __BPF_ABI_OOM_H__

#include "bpf_abi.h"

enum oom_snapshot_gate_state {
	OOM_SNAPSHOT_GATE_DISABLED = 0,
	OOM_SNAPSHOT_GATE_ADMITTED = 1,
	OOM_SNAPSHOT_GATE_BUSY = 2,
	OOM_SNAPSHOT_GATE_COOLDOWN = 3,
};

enum oom_snapshot_ack_status {
	OOM_SNAPSHOT_ACK_CAPTURED = 0,
	OOM_SNAPSHOT_ACK_PARTIAL = 1,
	OOM_SNAPSHOT_ACK_UNAVAILABLE = 2,
	OOM_SNAPSHOT_ACK_FAILED = 3,
	OOM_SNAPSHOT_ACK_FILTERED = 4,
};

enum oom_snapshot_release_reason {
	OOM_SNAPSHOT_RELEASE_NONE = 0,
	OOM_SNAPSHOT_RELEASE_ACK = 1,
	OOM_SNAPSHOT_RELEASE_DEADLINE = 2,
	OOM_SNAPSHOT_RELEASE_WORK_LIMIT = 3,
	OOM_SNAPSHOT_RELEASE_PERF_OUTPUT_FAILED = 4,
};

struct oom_snapshot_config {
	u64 timeout_ns;
	u64 cooldown_ns;
	u64 failure_cooldown_ns;
	u64 max_failure_cooldown_ns;
};

struct oom_snapshot_state {
	u64 cooldown_until_ns;
	u32 failure_streak;
	u32 pad;
};

struct oom_snapshot_gate {
	u64 cookie;
	u64 deadline_ns;
	u32 victim_tgid;
	u32 pad;
};

struct oom_snapshot_ack {
	u64 cookie;
	u32 status;
	u32 pad;
};

struct oom_snapshot_release {
	u64 cookie;
	u64 release_ns;
	u32 reason;
	u32 ack_status;
};
struct oom_event {
	u8 trigger_comm[COMPAT_TASK_COMM_LEN];
	u8 victim_comm[COMPAT_TASK_COMM_LEN];
	u32 trigger_pid;
	u32 victim_pid;
	u64 trigger_memcg_css;
	u64 victim_memcg_css;
	u64 mem_limit_pages;
	u64 mem_usage_pages;
	u64 timestamp;
	u64 snapshot_cookie;
	u64 snapshot_admission_deadline_ns;
	u8 snapshot_gate_state;
	u8 snapshot_pad[7];
};

BPF_ABI_EXPORT(oom_event);

#endif /* __BPF_ABI_OOM_H__ */
