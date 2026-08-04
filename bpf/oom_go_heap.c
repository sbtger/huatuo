/*
 * Copyright 2026 The HuaTuo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>

#include "bpf_common.h"
#include "abi/go_heap_types.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define GO_HEAP_BUCKETS_PER_CALL 256
#define GO_HEAP_TAIL_CALL_INDEX 0

/* Rewritten by userspace. The standalone object is inert by default. */
const volatile u32 go_heap_capture_enabled = 0;
const volatile u64 go_heap_capture_budget_ns = 2 * NSEC_PER_MSEC;

/* Must match bpf/oom.c so the loader can replace this map with that object. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 256);
} oom_victims SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct go_heap_target));
	__uint(max_entries, 4096);
} go_heap_targets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct go_heap_bucket));
	__uint(max_entries, GO_HEAP_MAX_BUCKETS);
} go_heap_buckets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct go_heap_control));
	__uint(max_entries, 1);
} go_heap_control SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct go_heap_event));
	__uint(max_entries, 1);
} go_heap_event_buf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
} go_heap_events SEC(".maps");

struct runtime_bucket_header {
	u64 next;
	u64 allnext;
	u64 bucket_type;
	u64 hash;
	u64 size;
	u64 stack_depth;
};

struct go_heap_capture_state {
	u64 bucket_address;
	u64 oom_timestamp;
	u64 start_time_ticks;
	u64 started_ns;
	u64 deadline_ns;
	u32 victim_tgid;
	u32 capture_id;
	u32 bucket_count;
	u32 visited_buckets;
	u32 skipped_buckets;
	u32 flags;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct go_heap_capture_state));
	__uint(max_entries, 1);
} go_heap_state SEC(".maps");

int go_heap_capture_tail(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
	__array(values, int(void *));
} go_heap_tailcalls SEC(".maps") = {
	.values = {
		[GO_HEAP_TAIL_CALL_INDEX] = (void *)&go_heap_capture_tail,
	},
};

static __always_inline int
finish_capture(void *ctx, struct go_heap_capture_state *state,
	       struct go_heap_control *control)
{
	struct go_heap_event *event;
	u32 zero = 0;

	control->completed_ns = bpf_ktime_get_ns();
	event = bpf_map_lookup_elem(&go_heap_event_buf, &zero);
	if (!event) {
		bpf_map_delete_elem(&go_heap_control, &zero);
		return 0;
	}
	event->oom_timestamp = state->oom_timestamp;
	event->capture_started_ns = state->started_ns;
	event->capture_duration_ns = control->completed_ns - state->started_ns;
	event->start_time_ticks = state->start_time_ticks;
	event->victim_tgid = state->victim_tgid;
	event->capture_id = state->capture_id;
	event->bucket_count = state->bucket_count;
	event->skipped_buckets = state->skipped_buckets;
	event->flags = state->flags;
	event->reserved = 0;
	if (bpf_perf_event_output(ctx, &go_heap_events,
				  COMPAT_BPF_F_CURRENT_CPU, event,
				  sizeof(*event)) != 0)
		bpf_map_delete_elem(&go_heap_control, &zero);
	return 0;
}

static __always_inline int
capture_segment(void *ctx, struct go_heap_capture_state *state,
		struct go_heap_control *control)
{
	struct runtime_bucket_header header = {};
	struct go_heap_bucket *output;
	u32 tail_call_index = GO_HEAP_TAIL_CALL_INDEX;
	int i;

#pragma clang loop unroll(disable)
	for (i = 0; i < GO_HEAP_BUCKETS_PER_CALL; i++) {
		u32 stack_size;

		if (!state->bucket_address) {
			state->flags |= GO_HEAP_CAPTURE_COMPLETE;
			return finish_capture(ctx, state, control);
		}
		if (state->visited_buckets >= GO_HEAP_MAX_BUCKETS) {
			state->flags |= GO_HEAP_CAPTURE_LIMIT;
			return finish_capture(ctx, state, control);
		}
		if ((state->visited_buckets & 15) == 0 &&
		    bpf_ktime_get_ns() >= state->deadline_ns) {
			state->flags |= GO_HEAP_CAPTURE_DEADLINE;
			return finish_capture(ctx, state, control);
		}
		if (bpf_probe_read_user(&header, sizeof(header),
					(void *)state->bucket_address) != 0) {
			state->flags |= GO_HEAP_CAPTURE_READ_ERROR;
			return finish_capture(ctx, state, control);
		}
		state->visited_buckets++;

		if (header.stack_depth == 0 ||
		    header.stack_depth > GO_HEAP_MAX_STACK_DEPTH) {
			state->skipped_buckets++;
			state->bucket_address = header.allnext;
			continue;
		}

		output = bpf_map_lookup_elem(&go_heap_buckets,
					     &state->bucket_count);
		if (!output) {
			state->flags |= GO_HEAP_CAPTURE_LIMIT;
			return finish_capture(ctx, state, control);
		}
		/* The mask gives older verifiers an explicit non-negative bound. */
		stack_size = (u32)(header.stack_depth & 0x7f) * sizeof(u64);
		if (stack_size > sizeof(output->stack)) {
			state->flags |= GO_HEAP_CAPTURE_READ_ERROR;
			return finish_capture(ctx, state, control);
		}
		output->stack_depth = header.stack_depth;
		if (bpf_probe_read_user(output->stack, stack_size,
					(void *)(state->bucket_address +
						 sizeof(header))) != 0 ||
		    bpf_probe_read_user(&output->record, sizeof(output->record),
					(void *)(state->bucket_address +
						 sizeof(header) + stack_size)) != 0) {
			state->flags |= GO_HEAP_CAPTURE_READ_ERROR;
			return finish_capture(ctx, state, control);
		}
		state->bucket_count++;
		state->bucket_address = header.allnext;
	}

	bpf_tail_call(ctx, &go_heap_tailcalls, tail_call_index);
	state->flags |= GO_HEAP_CAPTURE_TAIL_CALL_ERROR;
	return finish_capture(ctx, state, control);
}

SEC("tracepoint/go_heap/capture")
int go_heap_capture_tail(void *ctx)
{
	struct go_heap_capture_state *state;
	struct go_heap_control *control;
	u32 zero = 0;

	state = bpf_map_lookup_elem(&go_heap_state, &zero);
	control = bpf_map_lookup_elem(&go_heap_control, &zero);
	if (!state || !control)
		return 0;
	return capture_segment(ctx, state, control);
}

SEC("tracepoint/signal/signal_deliver")
int go_heap_signal_deliver(struct trace_event_raw_signal_deliver *ctx)
{
	struct go_heap_control initial_control = {};
	struct go_heap_capture_state *state;
	struct go_heap_control *control;
	struct go_heap_target *target;
	u64 bucket_address = 0;
	u64 *oom_timestamp;
	u32 tgid, zero = 0;

	if (!go_heap_capture_enabled || ctx->sig != 9)
		return 0;

	tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
	oom_timestamp = bpf_map_lookup_elem(&oom_victims, &tgid);
	if (!oom_timestamp)
		return 0;
	target = bpf_map_lookup_elem(&go_heap_targets, &tgid);
	if (!target)
		return 0;

	initial_control.owner_tgid = tgid;
	initial_control.capture_id = (u32)*oom_timestamp;
	if (bpf_map_update_elem(&go_heap_control, &zero, &initial_control,
				COMPAT_BPF_NOEXIST) != 0)
		return 0;
	control = bpf_map_lookup_elem(&go_heap_control, &zero);
	state = bpf_map_lookup_elem(&go_heap_state, &zero);
	if (!control || !state) {
		bpf_map_delete_elem(&go_heap_control, &zero);
		return 0;
	}

	state->oom_timestamp = *oom_timestamp;
	state->start_time_ticks = target->start_time_ticks;
	state->victim_tgid = tgid;
	state->capture_id = initial_control.capture_id;
	state->bucket_count = 0;
	state->visited_buckets = 0;
	state->skipped_buckets = 0;
	state->flags = 0;
	state->started_ns = bpf_ktime_get_ns();
	state->deadline_ns = state->started_ns + go_heap_capture_budget_ns;
	if (bpf_probe_read_user(&bucket_address, sizeof(bucket_address),
				(void *)target->mbuckets_address) != 0) {
		state->flags |= GO_HEAP_CAPTURE_READ_ERROR;
		return finish_capture(ctx, state, control);
	}
	state->bucket_address = bucket_address;
	return capture_segment(ctx, state, control);
}
