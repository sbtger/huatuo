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

#ifndef __BPF_ABI_OOM_JAVA_STACK_H__
#define __BPF_ABI_OOM_JAVA_STACK_H__

#include "bpf_abi.h"

#define JAVA_OOM_MAX_STACK_DEPTH 64
#define JAVA_OOM_MAX_DIRECT_FRAMES 16
#define JAVA_OOM_MAX_CODE_HEAPS 8
#define JAVA_OOM_SYMBOL_NAME_SIZE 64

#define JAVA_OOM_STACK_CAPTURED (1U << 0)
#define JAVA_OOM_STACK_CAPTURE_ERROR (1U << 1)
#define JAVA_OOM_STACK_HOTSPOT_UNWOUND (1U << 2)
#define JAVA_OOM_STACK_PTREGS_ERROR (1U << 3)
#define JAVA_OOM_STACK_THREAD_SCANNED (1U << 4)

#define JAVA_OOM_FRAME_RESOLVED (1U << 0)
#define JAVA_OOM_FRAME_NOT_NMETHOD (1U << 1)
#define JAVA_OOM_FRAME_HEAP_MISS (1U << 2)
#define JAVA_OOM_FRAME_READ_ERROR (1U << 3)
#define JAVA_OOM_FRAME_TRUNCATED (1U << 4)
#define JAVA_OOM_FRAME_INTERPRETER (1U << 5)

struct java_stack_hotspot_code_heap {
	u64 code_start;
	u64 code_end;
	u64 segmap_start;
	u64 segmap_end;
};

BPF_ABI_EXPORT(java_stack_hotspot_code_heap);

struct java_stack_target {
	u64 start_time_ticks;
	struct java_stack_hotspot_code_heap heaps[JAVA_OOM_MAX_CODE_HEAPS];
	u32 heap_count;
	u16 nmethod_method;
	u16 nmethod_compile_id;
	u16 constant_pool_size;
	u16 klass_name;
	u8 segment_shift;
	u8 heap_block_size;
	u8 codeblob_name;
	u8 method_const_method;
	u8 const_method_constants;
	u8 const_method_name_index;
	u8 constant_pool_holder;
	u8 symbol_length;
	u8 symbol_body;
};

BPF_ABI_EXPORT(java_stack_target);

struct java_stack_capture_key {
	u32 victim_tgid;
	u32 reserved;
	u64 oom_timestamp;
};

BPF_ABI_EXPORT(java_stack_capture_key);

struct java_stack_hotspot_frame {
	u64 pc;
	u32 compile_id;
	u32 flags;
	u16 class_name_len;
	u16 method_name_len;
	u8 class_name[JAVA_OOM_SYMBOL_NAME_SIZE];
	u8 method_name[JAVA_OOM_SYMBOL_NAME_SIZE];
};

BPF_ABI_EXPORT(java_stack_hotspot_frame);

struct java_stack_event {
	u64 oom_timestamp;
	u64 capture_timestamp;
	u64 capture_duration_ns;
	u64 start_time_ticks;
	u64 cgroup_id;
	u32 victim_tgid;
	u32 victim_tid;
	s32 stack_size;
	u32 flags;
	u64 ips[JAVA_OOM_MAX_STACK_DEPTH];
	u32 direct_frame_count;
	u32 direct_error_count;
	struct java_stack_hotspot_frame direct_frames[JAVA_OOM_MAX_DIRECT_FRAMES];
};

BPF_ABI_EXPORT(java_stack_event);

#endif /* __BPF_ABI_OOM_JAVA_STACK_H__ */
