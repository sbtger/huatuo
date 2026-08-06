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

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#include "bpf_common.h"
#include "abi/java_stack_types.h"

char __license[] SEC("license") = "Dual MIT/GPL";

/* Rewritten by userspace. The standalone object is inert by default. */
const volatile u32 java_stack_capture_enabled = 0;
const volatile u32 java_stack_discovery_pid = 0;
const volatile u32 java_stack_ptregs_offset = 0;

#define JAVA_OOM_MIN_PTREGS_OFFSET 4096
#define JAVA_OOM_MAX_PTREGS_OFFSET (64 * 1024)
#define JAVA_OOM_MAX_FRAME_DISTANCE (1024 * 1024)
#define JAVA_OOM_MAX_THREAD_SCAN 20
#define JAVA_OOM_MAX_CUSTOM_FRAMES 12
#define JAVA_OOM_TAIL_CALL_INDEX 0

struct java_stack_unwind_state {
	u64 pc;
	u64 sp;
	u64 fp;
};

struct java_stack_walk_state {
	struct java_stack_unwind_state unwind;
	u64 current_task;
	u64 thread_head;
	u64 next_thread;
	u64 thread_list_offset;
	u32 victim_tgid;
	u32 signal_tid;
	u32 frame_count;
	u32 resolved_count;
	u32 thread_scan_count;
};

/* Must match bpf/oom.c so the loader can replace this map. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 256);
} oom_victims SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct java_stack_target));
	__uint(max_entries, 4096);
	__uint(map_flags, COMPAT_BPF_F_NO_PREALLOC);
} java_stack_targets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct java_stack_event));
	__uint(max_entries, 1);
} java_stack_event_buf SEC(".maps");

/* Userspace removes the owner after copying the matching perf event. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(struct java_stack_capture_key));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 4096);
} java_stack_captures SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
} java_stack_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct java_stack_walk_state));
	__uint(max_entries, 1);
} java_stack_walk_state SEC(".maps");

int java_stack_unwind_tail(void *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
	__array(values, int(void *));
} java_stack_tailcalls SEC(".maps") = {
	.values = {
		[JAVA_OOM_TAIL_CALL_INDEX] = (void *)&java_stack_unwind_tail,
	},
};

/* Used only by a short-lived startup probe, before the capture object loads. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 1);
} java_stack_system_config SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int java_stack_discover_pt_regs(struct bpf_raw_tracepoint_args *ctx)
{
	struct task_struct *task;
	void *stack_base;
	u64 regs, base, offset;
	u64 pid_tgid;
	u32 zero = 0;

	if (!java_stack_discovery_pid)
		return 0;
	pid_tgid = bpf_get_current_pid_tgid();
	if ((u32)(pid_tgid >> 32) != java_stack_discovery_pid)
		return 0;
	task = (struct task_struct *)bpf_get_current_task();
	stack_base = BPF_CORE_READ(task, stack);
	regs = ctx->args[0];
	base = (u64)stack_base;
	if (!base || regs <= base)
		return 0;
	offset = regs - base;
	if (offset < JAVA_OOM_MIN_PTREGS_OFFSET ||
	    offset >= JAVA_OOM_MAX_PTREGS_OFFSET)
		return 0;
	bpf_map_update_elem(&java_stack_system_config, &zero, &offset,
			    COMPAT_BPF_ANY);
	return 0;
}

static __always_inline void
clear_java_stack_event(struct java_stack_event *event)
{
	volatile u64 *words = (volatile u64 *)event;
	int index;

#pragma clang loop unroll(disable)
	for (index = 0; index < sizeof(*event) / sizeof(u64); index++)
		words[index] = 0;
}

static __always_inline int
hotspot_find_codeblob(const struct java_stack_target *target, u64 pc,
		      u64 *codeblob)
{
	const struct java_stack_hotspot_code_heap *heap = NULL;
	u64 segment_count, segment;
	u8 tag = 0xff;
	int index;

#pragma clang loop unroll(disable)
	for (index = 0; index < JAVA_OOM_MAX_CODE_HEAPS; index++) {
		if ((u32)index >= target->heap_count)
			break;
		if (pc >= target->heaps[index].code_start &&
		    pc < target->heaps[index].code_end) {
			heap = &target->heaps[index];
			break;
		}
	}
	if (!heap || target->segment_shift > 31)
		return -1;

	segment = (pc - heap->code_start) >> target->segment_shift;
	segment_count = heap->segmap_end - heap->segmap_start;
	if (heap->segmap_end <= heap->segmap_start || segment >= segment_count)
		return -1;

#pragma clang loop unroll(disable)
	for (index = 0; index < 12; index++) {
		if (bpf_probe_read_user(&tag, sizeof(tag),
					(void *)(heap->segmap_start + segment)) != 0)
			return -2;
		if (tag == 0 || tag == 0xff)
			break;
		if ((u64)tag > segment)
			return -2;
		segment -= tag;
	}
	if (tag != 0)
		return -2;

	*codeblob = heap->code_start +
		(segment << target->segment_shift) + target->heap_block_size;
	if (*codeblob < heap->code_start || *codeblob >= heap->code_end)
		return -2;
	return 0;
}

static __always_inline int
hotspot_copy_symbol(const struct java_stack_target *target, u64 symbol,
		    u8 output[JAVA_OOM_SYMBOL_NAME_SIZE], u16 *output_len,
		    u32 *flags)
{
	u32 copy_length, terminator;
	u16 symbol_length;

	if (!symbol || bpf_probe_read_user(&symbol_length, sizeof(symbol_length),
					  (void *)(symbol + target->symbol_length)) != 0 ||
	    symbol_length == 0) {
		*flags |= JAVA_OOM_FRAME_READ_ERROR;
		return -1;
	}
	copy_length = symbol_length;
	if (copy_length >= JAVA_OOM_SYMBOL_NAME_SIZE) {
		copy_length = JAVA_OOM_SYMBOL_NAME_SIZE - 1;
		*flags |= JAVA_OOM_FRAME_TRUNCATED;
	}
	/* Give older verifiers an explicit helper-size upper bound. */
	copy_length &= JAVA_OOM_SYMBOL_NAME_SIZE - 1;
	if (bpf_probe_read_user(output, copy_length,
				(void *)(symbol + target->symbol_body)) != 0) {
		*flags |= JAVA_OOM_FRAME_READ_ERROR;
		return -1;
	}
	terminator = copy_length & (JAVA_OOM_SYMBOL_NAME_SIZE - 1);
	output[terminator] = 0;
	*output_len = (u16)copy_length;
	return 0;
}

static __always_inline int
hotspot_resolve_method(const struct java_stack_target *target, u64 method,
		       struct java_stack_hotspot_frame *frame)
{
	u64 const_method, constants;
	u64 pool_holder, class_symbol, method_symbol;
	u16 name_index;

	if (!method ||
	    bpf_probe_read_user(&const_method, sizeof(const_method),
				(void *)(method + target->method_const_method)) != 0 ||
	    !const_method ||
	    bpf_probe_read_user(&constants, sizeof(constants),
				(void *)(const_method +
				 target->const_method_constants)) != 0 ||
	    !constants ||
	    bpf_probe_read_user(&pool_holder, sizeof(pool_holder),
				(void *)(constants +
				 target->constant_pool_holder)) != 0 ||
	    !pool_holder ||
	    bpf_probe_read_user(&class_symbol, sizeof(class_symbol),
				(void *)(pool_holder + target->klass_name)) != 0 ||
	    !class_symbol ||
	    bpf_probe_read_user(&name_index, sizeof(name_index),
				(void *)(const_method +
				 target->const_method_name_index)) != 0 ||
	    !name_index ||
	    bpf_probe_read_user(&method_symbol, sizeof(method_symbol),
				(void *)(constants + target->constant_pool_size +
				 (u64)name_index * sizeof(u64))) != 0 ||
	    !(method_symbol &= ~1ULL)) {
		frame->flags |= JAVA_OOM_FRAME_READ_ERROR;
		return -1;
	}
	if (hotspot_copy_symbol(target, class_symbol, frame->class_name,
				&frame->class_name_len, &frame->flags) != 0 ||
	    hotspot_copy_symbol(target, method_symbol, frame->method_name,
				&frame->method_name_len, &frame->flags) != 0)
		return -1;
	frame->flags |= JAVA_OOM_FRAME_RESOLVED;
	return 0;
}

/* Returns 1 for an Interpreter frame, 0 for an nmethod, and -1 otherwise. */
static __always_inline int
hotspot_classify_frame(const struct java_stack_target *target,
		       struct java_stack_hotspot_frame *frame)
{
	u64 codeblob, blob_name, method;
	u8 name[12] = {};
	int error;

	error = hotspot_find_codeblob(target, frame->pc, &codeblob);
	if (error != 0) {
		frame->flags |= error == -1 ? JAVA_OOM_FRAME_HEAP_MISS :
			JAVA_OOM_FRAME_READ_ERROR;
		return -1;
	}
	if (bpf_probe_read_user(&blob_name, sizeof(blob_name),
				(void *)(codeblob + target->codeblob_name)) != 0 ||
	    !blob_name ||
	    bpf_probe_read_user(name, sizeof(name), (void *)blob_name) != 0) {
		frame->flags |= JAVA_OOM_FRAME_READ_ERROR;
		return -1;
	}
	if (name[0] == 'n' && name[1] == 'm' && name[2] == 'e' &&
	    name[3] == 't' && name[4] == 'h' && name[5] == 'o' &&
	    name[6] == 'd') {
		if (bpf_probe_read_user(&frame->compile_id,
					sizeof(frame->compile_id),
					(void *)(codeblob +
					 target->nmethod_compile_id)) != 0 ||
		    bpf_probe_read_user(&method, sizeof(method),
					(void *)(codeblob +
					 target->nmethod_method)) != 0 ||
		    hotspot_resolve_method(target, method, frame) != 0) {
			frame->flags |= JAVA_OOM_FRAME_READ_ERROR;
			return -1;
		}
		return 0;
	}
	if (name[0] == 'I' && name[1] == 'n' && name[2] == 't' &&
	    name[3] == 'e' && name[4] == 'r' && name[5] == 'p' &&
	    name[6] == 'r' && name[7] == 'e' && name[8] == 't' &&
	    name[9] == 'e' && name[10] == 'r') {
		frame->flags |= JAVA_OOM_FRAME_INTERPRETER;
		return 1;
	}
	frame->flags |= JAVA_OOM_FRAME_NOT_NMETHOD;
	return -1;
}

static __always_inline int
hotspot_get_task_user_state(struct task_struct *task,
			    struct java_stack_unwind_state *state)
{
#ifdef __TARGET_ARCH_x86
	struct pt_regs regs;
	void *stack_base;
	u32 offset = java_stack_ptregs_offset;

	if (offset < JAVA_OOM_MIN_PTREGS_OFFSET ||
	    offset >= JAVA_OOM_MAX_PTREGS_OFFSET)
		return -1;
	stack_base = BPF_CORE_READ(task, stack);
	if (!stack_base ||
	    bpf_probe_read_kernel(&regs, sizeof(regs),
				  stack_base + offset) != 0 ||
	    (regs.cs & 3) != 3 || (regs.ss & 3) != 3 ||
	    !regs.ip || !regs.sp || !regs.bp)
		return -1;
	state->pc = regs.ip;
	state->sp = regs.sp;
	state->fp = regs.bp;
	return 0;
#else
	return -1;
#endif
}

static __always_inline int
hotspot_unwind_frame_pointer(struct java_stack_unwind_state *state)
{
	u64 words[2];
	u64 distance;

	if (state->fp < state->sp)
		return -1;
	distance = state->fp - state->sp;
	if (distance >= JAVA_OOM_MAX_FRAME_DISTANCE || (state->fp & 7))
		return -1;
	if (bpf_probe_read_user(words, sizeof(words), (void *)state->fp) != 0 ||
	    words[0] <= state->fp || !words[1])
		return -1;
	if (words[0] - state->fp >= JAVA_OOM_MAX_FRAME_DISTANCE)
		return -1;
	state->sp = state->fp + sizeof(words);
	state->fp = words[0];
	state->pc = words[1];
	return 0;
}

static __always_inline int
hotspot_unwind_interpreter(const struct java_stack_target *target,
			   struct java_stack_unwind_state *state,
			   struct java_stack_hotspot_frame *frame)
{
	/* x86 frame_x86.hpp: method=-3, sender_sp=-1, fp=0, pc=+1. */
	u64 slots[12];
	u64 method, next_sp, next_fp, next_pc;

	if (state->fp < state->sp ||
	    state->fp - state->sp >= JAVA_OOM_MAX_FRAME_DISTANCE ||
	    state->fp < 10 * sizeof(u64))
		return -1;
	if (bpf_probe_read_user(slots, sizeof(slots),
				(void *)(state->fp - 10 * sizeof(u64))) != 0)
		return -1;
	method = slots[7];
	next_sp = slots[9];
	next_fp = slots[10];
	next_pc = slots[11];
	if (!method || !next_pc || next_fp <= state->fp ||
	    next_fp - state->fp >= JAVA_OOM_MAX_FRAME_DISTANCE)
		return -1;
	if (hotspot_resolve_method(target, method, frame) != 0)
		return -1;
	state->sp = next_sp;
	state->fp = next_fp;
	state->pc = next_pc;
	return 0;
}

static __always_inline void
clear_java_direct_frames(struct java_stack_event *event)
{
	volatile u64 *words = (volatile u64 *)event->ips;
	int index;

#pragma clang loop unroll(disable)
	for (index = 0;
	     index < (sizeof(event->ips) + sizeof(event->direct_frame_count) +
		      sizeof(event->direct_error_count) +
		      sizeof(event->direct_frames)) / sizeof(u64); index++)
		words[index] = 0;
}

static __always_inline void
capture_helper_stack(struct trace_event_raw_signal_deliver *ctx,
		     const struct java_stack_target *target,
		     struct java_stack_event *event)
{
	u32 frame_count;
	int index;

	clear_java_direct_frames(event);
	event->stack_size = bpf_get_stack(ctx, event->ips,
					  sizeof(event->ips),
					  COMPAT_BPF_F_USER_STACK);
	if (event->stack_size < 0) {
		event->flags |= JAVA_OOM_STACK_CAPTURE_ERROR;
		return;
	}
	event->flags |= JAVA_OOM_STACK_CAPTURED;
	frame_count = (u32)event->stack_size / sizeof(u64);
	if (frame_count > JAVA_OOM_MAX_DIRECT_FRAMES)
		frame_count = JAVA_OOM_MAX_DIRECT_FRAMES;
	event->direct_frame_count = frame_count;
#pragma clang loop unroll(disable)
	for (index = 0; index < JAVA_OOM_MAX_DIRECT_FRAMES; index++) {
		struct java_stack_hotspot_frame *frame;

		if ((u32)index >= frame_count)
			break;
		frame = &event->direct_frames[index];
		frame->pc = event->ips[index];
		if (hotspot_classify_frame(target, frame) != 0)
			event->direct_error_count++;
	}
}

static __always_inline int
publish_java_stack_event(void *ctx, struct java_stack_event *event)
{
	struct java_stack_capture_key capture_key = {};
	int error;

	event->capture_duration_ns = bpf_ktime_get_ns() -
		event->capture_timestamp;
	error = bpf_perf_event_output(ctx, &java_stack_events,
				      COMPAT_BPF_F_CURRENT_CPU,
				      event, sizeof(*event));
	if (error != 0) {
		capture_key.victim_tgid = event->victim_tgid;
		capture_key.oom_timestamp = event->oom_timestamp;
		bpf_map_delete_elem(&java_stack_captures, &capture_key);
	}
	return 0;
}

static __always_inline int
finish_custom_stack(void *ctx, struct java_stack_event *event,
		    struct java_stack_walk_state *state)
{
	event->stack_size = state->frame_count * sizeof(u64);
	event->direct_frame_count = state->frame_count;
	event->flags &= ~JAVA_OOM_STACK_PTREGS_ERROR;
	event->flags |= JAVA_OOM_STACK_CAPTURED |
		JAVA_OOM_STACK_HOTSPOT_UNWOUND;
	if (state->thread_scan_count)
		event->flags |= JAVA_OOM_STACK_THREAD_SCANNED;
	return publish_java_stack_event(ctx, event);
}

static __always_inline int
finish_helper_stack(void *ctx, const struct java_stack_target *target,
		    struct java_stack_event *event,
		    struct java_stack_walk_state *state)
{
	event->victim_tid = state->signal_tid;
	capture_helper_stack((struct trace_event_raw_signal_deliver *)ctx,
			     target, event);
	return publish_java_stack_event(ctx, event);
}

/* Returns 0 for a usable task, 1 for a skipped task, and -1 when done. */
static __always_inline int
hotspot_begin_next_thread(struct java_stack_walk_state *state,
			  struct java_stack_event *event)
{
#ifdef __TARGET_ARCH_x86
	struct task_struct *task;
	u64 node, next;
	char comm[16] = {};
	u32 tid;

	if (state->thread_scan_count >= JAVA_OOM_MAX_THREAD_SCAN)
		return -1;
	node = state->next_thread;
	if (!node || node == state->thread_head ||
	    node < state->thread_list_offset)
		return -1;
	if (bpf_probe_read_kernel(&next, sizeof(next), (void *)node) != 0)
		return -1;
	state->next_thread = next;
	state->thread_scan_count++;
	task = (struct task_struct *)(node - state->thread_list_offset);
	if ((u64)task == state->current_task)
		return 1;
	BPF_CORE_READ_INTO(&comm, task, comm);
	if (!((comm[0] == 'j' && comm[1] == 'a' && comm[2] == 'v' &&
	       comm[3] == 'a' && comm[4] == 0) ||
	      (comm[0] == 'm' && comm[1] == 'a' && comm[2] == 'i' &&
	       comm[3] == 'n' && comm[4] == 0)))
		return 1;
	__builtin_memset(&state->unwind, 0, sizeof(state->unwind));
	if (hotspot_get_task_user_state(task, &state->unwind) != 0)
		return 1;
	clear_java_direct_frames(event);
	state->frame_count = 0;
	state->resolved_count = 0;
	tid = BPF_CORE_READ(task, pid);
	event->victim_tid = tid;
	return 0;
#else
	return -1;
#endif
}

SEC("tracepoint/java_stack/unwind")
int java_stack_unwind_tail(void *ctx)
{
	struct java_stack_walk_state *state;
	struct java_stack_hotspot_frame *frame;
	struct java_stack_event *event;
	struct java_stack_target *target;
	u32 index, zero = 0;
	int kind, unwind_error, next_error;

	state = bpf_map_lookup_elem(&java_stack_walk_state, &zero);
	event = bpf_map_lookup_elem(&java_stack_event_buf, &zero);
	if (!state || !event)
		return 0;
	target = bpf_map_lookup_elem(&java_stack_targets,
				     &state->victim_tgid);
	if (!target) {
		event->stack_size = -1;
		event->flags |= JAVA_OOM_STACK_CAPTURE_ERROR;
		return publish_java_stack_event(ctx, event);
	}

	if (state->frame_count < JAVA_OOM_MAX_CUSTOM_FRAMES) {
		index = state->frame_count & (JAVA_OOM_MAX_DIRECT_FRAMES - 1);
		frame = &event->direct_frames[index];
		frame->pc = state->unwind.pc;
		event->ips[index] = state->unwind.pc;
		kind = hotspot_classify_frame(target, frame);
		if (kind == 1)
			unwind_error = hotspot_unwind_interpreter(
				target, &state->unwind, frame);
		else
			unwind_error = hotspot_unwind_frame_pointer(&state->unwind);
		if (frame->flags & JAVA_OOM_FRAME_RESOLVED)
			state->resolved_count++;
		else
			event->direct_error_count++;
		state->frame_count++;
		if (unwind_error == 0 &&
		    state->frame_count < JAVA_OOM_MAX_CUSTOM_FRAMES) {
			bpf_tail_call(ctx, &java_stack_tailcalls,
				      JAVA_OOM_TAIL_CALL_INDEX);
			return finish_helper_stack(ctx, target, event, state);
		}
	}
	if (state->resolved_count)
		return finish_custom_stack(ctx, event, state);

	next_error = hotspot_begin_next_thread(state, event);
	if (next_error >= 0) {
		bpf_tail_call(ctx, &java_stack_tailcalls,
			      JAVA_OOM_TAIL_CALL_INDEX);
	}
	return finish_helper_stack(ctx, target, event, state);
}

SEC("tracepoint/signal/signal_deliver")
int java_stack_signal_deliver(struct trace_event_raw_signal_deliver *ctx)
{
	struct java_stack_event *event;
	struct java_stack_walk_state *state;
	struct java_stack_target *target;
	struct task_struct *current, *leader;
	struct java_stack_capture_key capture_key = {};
	u64 pid_tgid, *oom_timestamp, list_offset;
	u32 tgid, tid, zero = 0;

	if (!java_stack_capture_enabled || ctx->sig != 9)
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tgid = (u32)(pid_tgid >> 32);
	tid = (u32)pid_tgid;
	oom_timestamp = bpf_map_lookup_elem(&oom_victims, &tgid);
	if (!oom_timestamp)
		return 0;
	target = bpf_map_lookup_elem(&java_stack_targets, &tgid);
	if (!target)
		return 0;
	capture_key.victim_tgid = tgid;
	capture_key.oom_timestamp = *oom_timestamp;

	/* Only one signal-delivery thread may publish this OOM snapshot. */
	if (bpf_map_update_elem(&java_stack_captures, &capture_key, oom_timestamp,
				COMPAT_BPF_NOEXIST) != 0)
		return 0;

	event = bpf_map_lookup_elem(&java_stack_event_buf, &zero);
	state = bpf_map_lookup_elem(&java_stack_walk_state, &zero);
	if (!event || !state) {
		bpf_map_delete_elem(&java_stack_captures, &capture_key);
		return 0;
	}

	/* The perf record copies the full slot, including bytes past short stacks. */
	clear_java_stack_event(event);
	event->oom_timestamp = *oom_timestamp;
	event->capture_timestamp = bpf_ktime_get_ns();
	event->start_time_ticks = target->start_time_ticks;
	event->cgroup_id = bpf_get_current_cgroup_id();
	event->victim_tgid = tgid;
	event->victim_tid = tid;
	__builtin_memset(state, 0, sizeof(*state));
	state->victim_tgid = tgid;
	state->signal_tid = tid;
	current = (struct task_struct *)bpf_get_current_task();
	state->current_task = (u64)current;
	leader = BPF_CORE_READ(current, group_leader);
	list_offset = __builtin_preserve_field_info(
		((struct task_struct *)0)->thread_group,
		BPF_FIELD_BYTE_OFFSET);
	state->thread_list_offset = list_offset;
	if (leader && list_offset) {
		state->thread_head = (u64)leader + list_offset;
		bpf_probe_read_kernel(&state->next_thread,
				      sizeof(state->next_thread),
				      (void *)state->thread_head);
	}
	if (tid == tgid && state->next_thread &&
	    state->next_thread != state->thread_head) {
		state->frame_count = JAVA_OOM_MAX_CUSTOM_FRAMES;
	} else if (hotspot_get_task_user_state(current, &state->unwind) != 0) {
		event->flags |= JAVA_OOM_STACK_PTREGS_ERROR;
		state->frame_count = JAVA_OOM_MAX_CUSTOM_FRAMES;
	}
	bpf_tail_call(ctx, &java_stack_tailcalls, JAVA_OOM_TAIL_CALL_INDEX);
	return finish_helper_stack(ctx, target, event, state);
}
