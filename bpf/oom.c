#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_common.h"
#include "bpf_ratelimit.h"
#include "abi/oom_types.h"

char __license[] SEC("license") = "Dual MIT/GPL";

BPF_RATELIMIT_IN_MAP(rate, 1, COMPAT_CPU_NUM * 10000, 0);

static long (*compat_bpf_probe_read_user)(void *dst, __u32 size,
					  const void *unsafe_ptr) = (void *)112;

/*
 * Linux changed mm_struct.rss_stat from mm_rss_stat.count[] to an array
 * of percpu_counter. The ___ suffix makes this a CO-RE flavor of mm_struct.
 */
struct mm_struct___percpu_rss {
	struct percpu_counter rss_stat[NR_MM_COUNTERS];
} __attribute__((preserve_access_index));

/*
 * member must be a compile-time MM_* constant so both CO-RE array accessors
 * can be relocated and the unavailable layout can be pruned by the verifier.
 */
#define READ_MM_RSS_PAGES(mm, member) ({                                \
	u64 __pages = 0;                                                 \
	struct mm_struct *__mm = (mm);                                  \
	if (bpf_core_field_exists(__mm->rss_stat.count[member])) {       \
		long __legacy = 0;                                       \
		bpf_core_read(&__legacy, sizeof(__legacy),                \
			      &__mm->rss_stat.count[member]);             \
		if (__legacy > 0)                                        \
			__pages = (u64)__legacy;                          \
	} else {                                                         \
		struct mm_struct___percpu_rss *__new = (void *)__mm;       \
		if (bpf_core_field_exists(__new->rss_stat[member].count)) {\
			s64 __percpu = 0;                                 \
			bpf_core_read(&__percpu, sizeof(__percpu),         \
				      &__new->rss_stat[member].count);    \
			if (__percpu > 0)                                  \
				__pages = (u64)__percpu;                  \
		}                                                        \
	}                                                                \
	__pages;                                                         \
})

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
} oom_perf_events SEC(".maps");

/*
 * Only OOM victims are present in this map.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 256);
} oom_exit_pending SEC(".maps");

/*
 * Avoid a hash lookup on ordinary process exits.
 */
volatile u32 oom_exit_pending_count;

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
} oom_exit_events SEC(".maps");

/*
 * A per-CPU scratch value keeps the exit event off the 512-byte BPF stack.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct oom_exit_event));
	__uint(max_entries, 1);
} oom_exit_scratch SEC(".maps");

#define OOM_CAPTURE_CMDLINE_OK    (1U << 0)
#define OOM_CAPTURE_CMDLINE_TRUNC (1U << 1)
#define OOM_CAPTURE_ENVIRON_OK    (1U << 2)
#define OOM_CAPTURE_ENVIRON_TRUNC (1U << 3)

/*
 * Copy a bounded argv or environment region while preserving whether the
 * source was readable and whether the fixed event buffer truncated it.
 */
static __always_inline u16
capture_user_region(u8 *dst, u32 capacity, unsigned long start,
		    unsigned long end, u8 *flags, u8 ok_flag, u8 trunc_flag)
{
	u64 length;

	if (!start || end <= start)
		return 0;

	length = end - start;
	if (length > capacity) {
		length = capacity;
		*flags |= trunc_flag;
	}
	if (compat_bpf_probe_read_user(dst, (u32)length, (void *)start) != 0)
		return 0;

	*flags |= ok_flag;
	return (u16)length;
}

SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message)
{
	struct oom_event info = {};
	struct task_struct *trigger_task, *victim_task;
	struct mm_struct *victim_mm;
	u64 *pending_timestamp;

	if (bpf_ratelimited_in_map(ctx, rate))
		return 0;

	if (!oc)
		return 0;

	trigger_task	 = (struct task_struct *)bpf_get_current_task();
	victim_task	 = BPF_CORE_READ(oc, chosen);

	info.trigger_pid = BPF_CORE_READ(trigger_task, pid);
	info.victim_pid	 = BPF_CORE_READ(victim_task, tgid);
	BPF_CORE_READ_STR_INTO(&info.trigger_comm, trigger_task, comm);
	BPF_CORE_READ_STR_INTO(&info.victim_comm, victim_task, comm);

	victim_mm = BPF_CORE_READ(victim_task, mm);
	if (victim_mm) {
		info.victim_rss_anon_pages =
		    READ_MM_RSS_PAGES(victim_mm, MM_ANONPAGES);
		info.victim_rss_file_pages =
		    READ_MM_RSS_PAGES(victim_mm, MM_FILEPAGES);
		info.victim_rss_shmem_pages =
		    READ_MM_RSS_PAGES(victim_mm, MM_SHMEMPAGES);
		info.victim_total_vm_pages =
		    BPF_CORE_READ(victim_mm, total_vm);
	}

	info.victim_memcg_css =
	    (u64)BPF_CORE_READ(victim_task, cgroups, subsys[memory_cgrp_id]);
	info.trigger_memcg_css =
	    (u64)BPF_CORE_READ(trigger_task, cgroups, subsys[memory_cgrp_id]);

	info.mem_limit_pages = BPF_CORE_READ(oc, totalpages);
	struct mem_cgroup *memcg = BPF_CORE_READ(oc, memcg);
	if (memcg) {
		info.mem_usage_pages =
		    (u64)BPF_CORE_READ(memcg, memory.usage.counter);
	}

	/*
	 * The timestamp is a per-selection correlation ID. Repeated reports for
	 * one victim reuse the pending value so every base event can match the
	 * single exit event emitted by that process.
	 */
	info.timestamp = bpf_ktime_get_ns();
	if (bpf_map_update_elem(&oom_exit_pending, &info.victim_pid,
				&info.timestamp, COMPAT_BPF_NOEXIST) == 0) {
		__sync_fetch_and_add(&oom_exit_pending_count, 1);
	} else {
		pending_timestamp =
		    bpf_map_lookup_elem(&oom_exit_pending, &info.victim_pid);
		if (pending_timestamp)
			info.timestamp = *pending_timestamp;
	}

	bpf_perf_event_output(ctx, &oom_perf_events, COMPAT_BPF_F_CURRENT_CPU,
			      &info, sizeof(info));
	return 0;
}

/*
 * Ordinary exits stop at the pending-count gate. An OOM victim removes its
 * pending key once, captures argv and environ before mm teardown, then emits
 * a separately correlated event without delaying the kernel exit path.
 */
SEC("kprobe/do_exit")
int BPF_KPROBE(do_exit_trace, long code)
{
	u32 zero;
	u32 pid;
	u64 event_timestamp;
	u64 *timestamp;
	struct oom_exit_event *evt;
	struct task_struct *task;
	struct mm_struct *mm;
	unsigned long arg_start, arg_end, env_start, env_end;

	if (oom_exit_pending_count == 0)
		return 0;

	pid = (u32)(bpf_get_current_pid_tgid() >> 32);
	timestamp = bpf_map_lookup_elem(&oom_exit_pending, &pid);
	if (!timestamp)
		return 0;

	event_timestamp = *timestamp;
	if (bpf_map_delete_elem(&oom_exit_pending, &pid) != 0)
		return 0;
	__sync_fetch_and_add(&oom_exit_pending_count, -1);

	zero = 0;
	evt = bpf_map_lookup_elem(&oom_exit_scratch, &zero);
	if (!evt)
		return 0;

	evt->timestamp = event_timestamp;
	evt->pid = pid;
	evt->cmdline_len = 0;
	evt->environ_len = 0;
	evt->capture_flags = 0;

	task = (struct task_struct *)bpf_get_current_task();
	mm = BPF_CORE_READ(task, mm);
	if (!mm)
		return 0;

	arg_start = BPF_CORE_READ(mm, arg_start);
	arg_end = BPF_CORE_READ(mm, arg_end);
	env_start = BPF_CORE_READ(mm, env_start);
	env_end = BPF_CORE_READ(mm, env_end);

	evt->cmdline_len = capture_user_region(
	    evt->victim_cmdline, sizeof(evt->victim_cmdline),
	    arg_start, arg_end, &evt->capture_flags,
	    OOM_CAPTURE_CMDLINE_OK, OOM_CAPTURE_CMDLINE_TRUNC);
	evt->environ_len = capture_user_region(
	    evt->victim_environ, sizeof(evt->victim_environ),
	    env_start, env_end, &evt->capture_flags,
	    OOM_CAPTURE_ENVIRON_OK, OOM_CAPTURE_ENVIRON_TRUNC);

	bpf_perf_event_output(ctx, &oom_exit_events,
			      COMPAT_BPF_F_CURRENT_CPU, evt, sizeof(*evt));
	return 0;
}
