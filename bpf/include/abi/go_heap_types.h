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

#ifndef __BPF_ABI_OOM_GO_HEAP_H__
#define __BPF_ABI_OOM_GO_HEAP_H__

#include "bpf_abi.h"

#define GO_HEAP_MAX_STACK_DEPTH 64
#define GO_HEAP_MAX_BUCKETS 4096

#define GO_HEAP_CAPTURE_COMPLETE (1U << 0)
#define GO_HEAP_CAPTURE_DEADLINE (1U << 1)
#define GO_HEAP_CAPTURE_LIMIT (1U << 2)
#define GO_HEAP_CAPTURE_READ_ERROR (1U << 3)
#define GO_HEAP_CAPTURE_TAIL_CALL_ERROR (1U << 4)

struct go_heap_target {
	u64 mbuckets_address;
	u64 start_time_ticks;
};

BPF_ABI_EXPORT(go_heap_target);

struct go_heap_mem_cycle {
	u64 allocs;
	u64 frees;
	u64 alloc_bytes;
	u64 free_bytes;
};

BPF_ABI_EXPORT(go_heap_mem_cycle);

struct go_heap_mem_record {
	struct go_heap_mem_cycle active;
	struct go_heap_mem_cycle future[3];
};

BPF_ABI_EXPORT(go_heap_mem_record);

struct go_heap_bucket {
	u64 stack_depth;
	u64 stack[GO_HEAP_MAX_STACK_DEPTH];
	struct go_heap_mem_record record;
};

BPF_ABI_EXPORT(go_heap_bucket);

/*
 * A non-zero owner keeps the global bucket array stable until userspace has
 * copied it and acknowledges the capture by deleting the control-map entry.
 */
struct go_heap_control {
	u64 owner_tgid;
	u32 capture_id;
	u32 reserved;
	u64 completed_ns;
};

BPF_ABI_EXPORT(go_heap_control);

struct go_heap_event {
	u64 oom_timestamp;
	u64 capture_started_ns;
	u64 capture_duration_ns;
	u64 start_time_ticks;
	u32 victim_tgid;
	u32 capture_id;
	u32 bucket_count;
	u32 skipped_buckets;
	u32 flags;
	u32 reserved;
};

BPF_ABI_EXPORT(go_heap_event);

#endif /* __BPF_ABI_OOM_GO_HEAP_H__ */
