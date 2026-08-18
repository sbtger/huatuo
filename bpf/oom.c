#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "bpf_common.h"
#include "bpf_ratelimit.h"
#include "abi/oom_types.h"

char __license[] SEC("license") = "Dual MIT/GPL";

BPF_RATELIMIT_IN_MAP(rate, 1, COMPAT_CPU_NUM * 10000, 0);

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(u32));
} oom_perf_events SEC(".maps");

/*
 * One host-wide owner prevents an OOM storm from queuing capture work. A
 * later OOM emits its base event and returns immediately when this slot is
 * occupied or the cooldown has not expired.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct oom_snapshot_gate));
	__uint(max_entries, 1);
} oom_snapshot_active SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct oom_snapshot_ack));
	__uint(max_entries, 1);
} oom_snapshot_acks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct oom_snapshot_config));
	__uint(max_entries, 1);
} oom_snapshot_config SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(struct oom_snapshot_state));
	__uint(max_entries, 1);
} oom_snapshot_state SEC(".maps");

/*
 * The kernel side is the source of truth for why a gate was released. This
 * avoids treating an ACK map write as proof that the polling program observed
 * it before the deadline.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(key_size, sizeof(u64));
	__uint(value_size, sizeof(struct oom_snapshot_release));
	__uint(max_entries, 64);
} oom_snapshot_release SEC(".maps");

/*
 * Test-only fault injection. A non-zero value forces a specific kernel-side
 * fail-open path so the synchronous gate can be exercised without a real perf
 * buffer failure or tail-call exhaustion. Zero disables injection and leaves
 * the production gate behavior unchanged.
 */
#define OOM_SNAPSHOT_FAULT_NONE 0
#define OOM_SNAPSHOT_FAULT_PERF_OUTPUT 1
#define OOM_SNAPSHOT_FAULT_WORK_LIMIT 2

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} oom_snapshot_fault_injection SEC(".maps");

static __always_inline u32 snapshot_fault_code(void)
{
	u32 zero = 0;
	u32 *fault = bpf_map_lookup_elem(&oom_snapshot_fault_injection, &zero);
	if (!fault)
		return OOM_SNAPSHOT_FAULT_NONE;
	return *fault;
}

/*
 * TID of the thread currently frozen at exit_mm_release. The userspace reader
 * must address this thread (not the thread-group leader) because the leader can
 * tear down its own mm/fs first, which breaks process_vm_readv(tgid) and
 * /proc/<tgid>/root even though the frozen thread's mm/fs are still intact.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
	__uint(max_entries, 1);
} oom_snapshot_gate_tid SEC(".maps");

/*
 * Old supported kernels have bounded loops but no bpf_loop helper. Tail calls
 * split polling into verifier-friendly chunks and impose an independent hard
 * work limit if monotonic time ever stops advancing.
 */
#define OOM_SNAPSHOT_POLL_ITERATIONS 1024
/*
 * The fixed work budget must outlive the configured gate (at most 50 ms) on
 * every supported target. The monotonic deadline is authoritative; work-limit
 * release remains a fail-open safety net and is recorded separately so target
 * kernels can reject an insufficient polling budget during qualification.
 */
/*
 * Do not raise this as a substitute for target qualification. Verifier cost
 * grows with POLL_ITERATIONS * CLOCK_READS: Linux 5.10 simulates every outer
 * iteration and rejects the object once it processes one million
 * instructions, which the 2048-iteration layout exceeds at 1000001. The
 * 1024-iteration layout halves that to roughly 500k, while the tail-call
 * chain still covers the 50 ms gate several times over.
 */
#define OOM_SNAPSHOT_CLOCK_READS 192

/*
 * Upper bound on how long the victim may take to reach exit_mm_release after
 * the gate is admitted. The configured timeout_ns is the capture budget and
 * starts only once a thread actually freezes; this admission bound keeps a
 * late or stuck victim from holding the single gate slot indefinitely.
 */
#define OOM_SNAPSHOT_ADMISSION_TIMEOUT_NS (1000ULL * 1000 * 1000)

int oom_snapshot_poll(struct pt_regs *ctx);

struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(max_entries, 1);
	__array(values, int(void *));
} oom_snapshot_pollers SEC(".maps") = {
	.values = {
		[0] = (void *)&oom_snapshot_poll,
	},
};

static __always_inline int finish_snapshot_gate(u32 *key,
						 struct oom_snapshot_gate *gate,
						 u32 reason, u32 ack_status)
{
	struct oom_snapshot_config *config;
	struct oom_snapshot_release release = {};
	struct oom_snapshot_state *state;
	u32 zero = 0;
	u64 backoff, now;

	now = bpf_ktime_get_ns();
	config = bpf_map_lookup_elem(&oom_snapshot_config, &zero);
	state = bpf_map_lookup_elem(&oom_snapshot_state, &zero);
	if (config && state) {
		if (reason == OOM_SNAPSHOT_RELEASE_ACK &&
		    (ack_status == OOM_SNAPSHOT_ACK_CAPTURED ||
		     ack_status == OOM_SNAPSHOT_ACK_PARTIAL ||
		     ack_status == OOM_SNAPSHOT_ACK_FILTERED)) {
			state->failure_streak = 0;
			state->cooldown_until_ns = now + config->cooldown_ns;
		} else {
			backoff = config->failure_cooldown_ns;
			if (state->failure_streak < 3)
				state->failure_streak++;
			/*
			 * The shift below is undefined for a u64 when the count reaches
			 * 64. The state map is written raw by userspace at attach time,
			 * so clamp defensively to keep a corrupt value from disabling
			 * the failure cooldown.
			 */
			if (state->failure_streak > 6)
				state->failure_streak = 6;
			backoff <<= state->failure_streak - 1;
			if (backoff > config->max_failure_cooldown_ns)
				backoff = config->max_failure_cooldown_ns;
			state->cooldown_until_ns = now + backoff;
		}
	}
	release.cookie = gate->cookie;
	release.release_ns = now;
	release.reason = reason;
	release.ack_status = ack_status;
	bpf_map_update_elem(&oom_snapshot_release, &gate->cookie, &release,
				COMPAT_BPF_ANY);
	bpf_map_delete_elem(&oom_snapshot_active, key);
	bpf_map_delete_elem(&oom_snapshot_gate_tid, key);
	return 0;
}

static __always_inline int poll_snapshot_gate(struct pt_regs *ctx)
{
	struct oom_snapshot_gate *gate;
	struct oom_snapshot_ack *ack;
	u32 zero = 0;
	u64 now = 0;
	int i, j;

	gate = bpf_map_lookup_elem(&oom_snapshot_active, &zero);
	if (!gate)
		return 0;

	if (snapshot_fault_code() == OOM_SNAPSHOT_FAULT_WORK_LIMIT)
		return finish_snapshot_gate(&zero, gate,
			OOM_SNAPSHOT_RELEASE_WORK_LIMIT, OOM_SNAPSHOT_ACK_FAILED);

	for (i = 0; i < OOM_SNAPSHOT_POLL_ITERATIONS; i++) {
		ack = bpf_map_lookup_elem(&oom_snapshot_acks, &zero);
		if (ack && ack->cookie == gate->cookie)
			return finish_snapshot_gate(&zero, gate,
				OOM_SNAPSHOT_RELEASE_ACK, ack->status);
		/*
		 * Fixed straight-line clock reads consume time without adding verifier
		 * branches. ACK is still checked every few microseconds, while tail
		 * calls provide enough total work for the configured hard deadline.
		 */
#pragma unroll
		for (j = 0; j < OOM_SNAPSHOT_CLOCK_READS; j++)
			now = bpf_ktime_get_ns();
		if (now >= gate->deadline_ns)
			return finish_snapshot_gate(&zero, gate,
				OOM_SNAPSHOT_RELEASE_DEADLINE, OOM_SNAPSHOT_ACK_FAILED);
	}

	bpf_tail_call(ctx, &oom_snapshot_pollers, 0);
	/* Tail-call exhaustion is fail-open, observable, and never permanent. */
	return finish_snapshot_gate(&zero, gate,
		OOM_SNAPSHOT_RELEASE_WORK_LIMIT, OOM_SNAPSHOT_ACK_FAILED);
}

SEC("kprobe/huatuo_tailcall_oom_snapshot_poll")
int oom_snapshot_poll(struct pt_regs *ctx)
{
	return poll_snapshot_gate(ctx);
}
SEC("kprobe/oom_kill_process")
int BPF_KPROBE(oom_kill_process, struct oom_control *oc, const char *message)
{
	struct oom_event info = {};
	struct oom_snapshot_config *snapshot_config;
	struct oom_snapshot_state *snapshot_state;
	struct oom_snapshot_gate snapshot_gate = {};
	struct oom_snapshot_gate *stale;
	struct task_struct *trigger_task, *victim_task;
	u32 zero = 0;
	u64 now;
	long output_ret;

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

	now = bpf_ktime_get_ns();
	info.timestamp = now;
	snapshot_config = bpf_map_lookup_elem(&oom_snapshot_config, &zero);
	snapshot_state = bpf_map_lookup_elem(&oom_snapshot_state, &zero);
	if (!snapshot_config || !snapshot_state || snapshot_config->timeout_ns == 0)
		goto emit;
	if (now < snapshot_state->cooldown_until_ns) {
		info.snapshot_gate_state = OOM_SNAPSHOT_GATE_COOLDOWN;
		goto emit;
	}
	snapshot_gate.cookie = now;
	snapshot_gate.deadline_ns = now + OOM_SNAPSHOT_ADMISSION_TIMEOUT_NS;
	snapshot_gate.victim_tgid = info.victim_pid;
	if (bpf_map_update_elem(&oom_snapshot_active, &zero, &snapshot_gate,
				COMPAT_BPF_NOEXIST) != 0) {
		/*
		 * The single gate slot can be left occupied by a victim that never
		 * reached exit_mm_release (for example a process stuck in
		 * uninterruptible sleep). The admission deadline is otherwise only
		 * enforced on the victim's exit path, so without this reaping a
		 * single stuck victim would report GATE_BUSY forever. Reap the stale
		 * gate and retry once so a later OOM can still be admitted.
		 */
		stale = bpf_map_lookup_elem(&oom_snapshot_active, &zero);
		if (!stale || now < stale->deadline_ns) {
			info.snapshot_gate_state = OOM_SNAPSHOT_GATE_BUSY;
			goto emit;
		}
		finish_snapshot_gate(&zero, stale,
			OOM_SNAPSHOT_RELEASE_DEADLINE, OOM_SNAPSHOT_ACK_FAILED);
		if (bpf_map_update_elem(&oom_snapshot_active, &zero, &snapshot_gate,
					COMPAT_BPF_NOEXIST) != 0) {
			info.snapshot_gate_state = OOM_SNAPSHOT_GATE_BUSY;
			goto emit;
		}
	}
	bpf_map_delete_elem(&oom_snapshot_gate_tid, &zero);
	info.snapshot_gate_state = OOM_SNAPSHOT_GATE_ADMITTED;
	info.snapshot_cookie = snapshot_gate.cookie;
	info.snapshot_admission_deadline_ns = snapshot_gate.deadline_ns;

emit:
	if (info.snapshot_gate_state == OOM_SNAPSHOT_GATE_ADMITTED &&
	    snapshot_fault_code() == OOM_SNAPSHOT_FAULT_PERF_OUTPUT) {
		/*
		 * Fault injection: the perf event never reaches userspace, so the
		 * victim must not wait for an ACK that will never arrive.
		 */
		return finish_snapshot_gate(&zero, &snapshot_gate,
			OOM_SNAPSHOT_RELEASE_PERF_OUTPUT_FAILED,
			OOM_SNAPSHOT_ACK_FAILED);
	}
	output_ret = bpf_perf_event_output(ctx, &oom_perf_events,
					   COMPAT_BPF_F_CURRENT_CPU,
					   &info, sizeof(info));
	if (info.snapshot_gate_state != OOM_SNAPSHOT_GATE_ADMITTED)
		return 0;
	if (output_ret < 0)
		return finish_snapshot_gate(&zero, &snapshot_gate,
			OOM_SNAPSHOT_RELEASE_PERF_OUTPUT_FAILED,
			OOM_SNAPSHOT_ACK_FAILED);
	/*
	 * The gate is no longer polled here. oom_kill_process runs while the
	 * kernel holds oom_lock, so busy-waiting for the userspace ACK would
	 * serialize every concurrent OOM behind one 50 ms head-of-line stall.
	 * The victim now blocks on its own exit path (see exit_mm_release),
	 * where its mm is still intact but oom_lock is no longer held.
	 */
	return 0;
}

/*
 * The victim reaches here from do_exit() -> exit_mm() before current->mm is
 * cleared, so the runtime-managed heap is still readable while we wait for
 * the userspace ACK. This runs on every process exit, so keep the early
 * returns as cheap as possible and only the matching victim blocks.
 */
SEC("kprobe/exit_mm_release")
int BPF_KPROBE(exit_mm_release, struct task_struct *tsk, struct mm_struct *mm)
{
	struct oom_snapshot_config *config;
	struct oom_snapshot_gate *gate;
	u32 zero = 0;
	u32 tid;
	u64 now;

	if (!mm)
		return 0;
	gate = bpf_map_lookup_elem(&oom_snapshot_active, &zero);
	if (!gate)
		return 0;
	if (BPF_CORE_READ(tsk, tgid) != gate->victim_tgid)
		return 0;

	/*
	 * Fast path: the first matching thread already published the frozen TID,
	 * so this thread just tears down. Checking here, before the deadline
	 * reset, keeps a late-arriving thread from reaping an active gate after
	 * the capture budget has already been installed.
	 */
	if (bpf_map_lookup_elem(&oom_snapshot_gate_tid, &zero))
		return 0;

	/*
	 * The first matching thread to freeze publishes the frozen TID and starts
	 * the capture budget. Publishing with BPF_NOEXIST makes exactly one thread
	 * win; every other thread sees EEXIST and tears down immediately. The
	 * deadline reset is written before the TID so userspace never observes a
	 * frozen thread with a stale deadline.
	 */
	now = bpf_ktime_get_ns();
	if (now >= gate->deadline_ns)
		return finish_snapshot_gate(&zero, gate,
			OOM_SNAPSHOT_RELEASE_DEADLINE,
			OOM_SNAPSHOT_ACK_FAILED);
	config = bpf_map_lookup_elem(&oom_snapshot_config, &zero);
	if (!config || config->timeout_ns == 0) {
		/*
		 * The feature was disabled after admission but before this victim
		 * froze. Do not hold the victim for the stale admission deadline;
		 * release the gate immediately so it exits without busy-waiting.
		 */
		return finish_snapshot_gate(&zero, gate,
			OOM_SNAPSHOT_RELEASE_DEADLINE,
			OOM_SNAPSHOT_ACK_FAILED);
	}
	gate->deadline_ns = now + config->timeout_ns;
	bpf_map_update_elem(&oom_snapshot_active, &zero, gate,
			    COMPAT_BPF_ANY);
	tid = BPF_CORE_READ(tsk, pid);
	if (bpf_map_update_elem(&oom_snapshot_gate_tid, &zero, &tid,
				COMPAT_BPF_NOEXIST) != 0)
		return 0;
	/*
	 * Only the winning thread busy-waits. The shared mm stays valid as long
	 * as this one thread holds its mm reference here; the remaining threads
	 * tear down their own mm/fs immediately, so a multi-threaded victim does
	 * not spin every CPU while frozen.
	 */
	return poll_snapshot_gate(ctx);
}
