<!--
Copyright 2026 The HuaTuo Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Container memburst

Set `AutoTracing.MemoryBurst.EnableContainer=true` to enable independent
container anonymous-memory burst tracing (default false). Existing host
behavior is unchanged. Reuse `DeltaMemoryBurst`, `DeltaAnonThreshold`,
`SlidingWindowLength`, `Interval`, `IntervalTracing`, `DumpProcessMaxNum`,
the window comparison and RSS process ranking. Events remain `memburst` with
the same data layout and set the corresponding container ID.

Read v1 `total_active_anon + total_inactive_anon`, or v2
`active_anon + inactive_anon`. The denominator is the smaller of host MemTotal
and the effective memory limit (v1 `hierarchical_memory_limit`; v2 minimum
ancestor `memory.max`). Unlimited containers use MemTotal. Anonymous LRU usage,
like the host baseline, is not total cgroup usage and can include shmem.

Each container has its own history and cooldown. Discovery or memory-read
failure, path or limit change resets history but preserves the last successful
trace time, so a new window cannot bypass `IntervalTracing`. State is removed
when the container disappears from a successful discovery result.
Snapshots read `cgroup.procs` recursively
only after a trigger and outside cooldown; RSS ranking need not sum to charged
cgroup memory. The existing ring compares newest vs oldest retained sample:
60 samples at 10-second intervals span 590 seconds.

No new BPF probes or maps. Per-interval cost is reading memory counters and
ancestor limits, with one bounded history ring per live container. Process
enumeration occurs on triggers. The shared window helper benchmark on the
development host takes approximately 23 ns/sample with zero allocations;
this excludes file reads and snapshots and is not an end-to-end overhead claim.

Validation on the 5.10 hybrid test VM: a bounded worker in an isolated 128 MiB
v1 memory cgroup grew from 8176 to 110596 KiB anonymous LRU. The real counters
crossed the two-sample test window's doubling/70%-of-limit thresholds, and the
RSS snapshot included the worker. `TestContainerBurstLiveGrowth` accepts its
PID via `HUATUO_MEMBURST_WORKER_PID`; it does not create pressure itself.
This checks counters, threshold logic and snapshots, not kubelet discovery or
container-event persistence. The VM has no kubelet, so that end-to-end path
and pure-v2 live memory coverage remain unverified. v2 ancestor-limit behavior
is covered by fixtures. The live worker and its cgroup were removed afterward.
