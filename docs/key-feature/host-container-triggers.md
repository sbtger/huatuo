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

# Host dload independent trigger

| Feature | Opt-in configuration | Implementation |
| --- | --- | --- |
| Host `dload` | `AutoTracing.Dload.EnableHost=true`, `HostThresholdLoad=5` | Shared BPF task iterator counts whole-host D-state threads; reuse the existing interval-based EMA and stack capture. Threshold and cooldown state are independent of container triggers. |

The addition defaults to disabled. Existing container dload configuration and
output remain available. Events retain their existing name and data layout.

Host dload includes container threads; it is not a non-container-only count.
It requires the same BPF task iterator/BTF/privileges and host PID visibility as
the existing host D-state metric (upstream iterator foundation: Linux 5.8).
It works with either cgroup version. On v2, `EnableHost` can be used without
`EnableCgroupV2`; when both are enabled a single iterator snapshot supplies
both scopes. On unsupported v1 kernels, only the new host trigger stops;
the existing netlink container path remains. D-load is a sampled estimate,
not `/proc/loadavg`. Host stacks include threads, not only process leaders.
Simultaneous host/container threshold crossings produce separate events.

Costs: no new BPF probes/maps. Host dload enables the existing full task walk
once per sample unless a compatible fresh snapshot is already available.

Validation on the 5.10 test VM: with debug off, a bounded `vfork` worker stays
in D state until its child exits. A one-second sample and host threshold zero
produce D=1 and D-load=0.02, trigger independently without container discovery,
and persist a SQLite record containing the worker's kernel stack. The existing
debug capture test now also queries SQLite rather than accepting an unconfigured
`Save` as proof. Live tests require `HUATUO_TRIGGER_BPF_DIR`; the normal trigger
test additionally requires `HUATUO_DLOAD_WORKER_PID`. Use only a disposable VM;
the fixture must exit on its own and the test never creates an unbounded D task.
