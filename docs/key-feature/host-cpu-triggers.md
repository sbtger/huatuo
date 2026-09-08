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

# Host CPU burst autotracing

`cpusys` can additionally trigger on host user CPU or total executing CPU.
It reuses the existing `/proc/stat` sampling loop, system-wide `perf` capture
and `cpusys` storage record. No new tracer, probe or periodic reader is added.

```toml
[AutoTracing.CPUSys]
EnableUser = false
EnableTotal = false
UserThreshold = 75
DeltaUserThreshold = 45
UsageThreshold = 90
DeltaUsageThreshold = 55
```

Existing system thresholds, sampling interval, capture duration and cooldown
remain unchanged. New switches default off; `cpusys` itself must also be enabled.
Each enabled trigger requires both the percentage and its increase from the
previous interval to **exceed** their thresholds. This detects bursts, not every
case of sustained high usage. The first percentage sample establishes a baseline.

All percentages use the delta of aggregate CPU time as their denominator:

| Trigger | Numerator |
| --- | --- |
| Existing system | `system` |
| User | `user + nice` |
| Total executing | `user + nice + system + irq + softirq` |

The denominator sums the first eight `/proc/stat` CPU counters. Guest time is
already included in user/nice and is not counted twice. Idle, iowait and steal
are excluded from total executing time: local on-CPU profiling cannot explain
waiting or time stolen by a hypervisor. This is whole-machine utilization,
including container work, not a container's quota-normalized utilization.

All three triggers share one capture and cooldown. Simultaneous crossings do
not run perf repeatedly. `container_id` stays empty. Existing system JSON fields
are preserved. Enabling the new triggers adds their `user_percent*` and/or
`total_percent*` fields and `trigger_reasons` (`user`, `total`, `system`);
zero-valued additional fields are omitted. With both switches off the stored
JSON schema remains unchanged.

Verification: unit tests cover counter calculations, rollback, defaults,
independent switches, threshold boundaries and cooldown. SQLite integration
tests check payload persistence. `TestCPUHostLiveTrigger`, enabled only by
`HUATUO_CPU_LIVE_DIR`, runs a bounded one-process workload and checks the real
sampling → perf → SQLite path. That directory must contain this build's `perf`
executable and `perf.o`; run only in a test VM with BPF/perf privileges.
