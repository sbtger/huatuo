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

# Host reclaim events

Set `EventTracing.MemoryReclaim.EnableHost=true` to retain slow direct-reclaim
events without a resolved container in the host event stream. The default is
false. Existing `try_to_free_pages` entry/return probes, duration threshold,
event name (`memory_reclaim`) and container output are unchanged.

An empty container ID does **not** prove that the reclaiming process is a host
service: bare-metal tasks and unresolved container tasks are both retained with
`container_attribution="unresolved"`. Known containers still produce a single
container event, not a duplicate host event. This is not kswapd tracing or an
aggregate reclaim counter. Container discovery failures cannot suppress the
host stream when enabled. Attribution uses the same refresh policy with either
output setting: cache hits have a five-second TTL, while misses retry at most
once per second. New containers may initially be unresolved until discovery
and a cache refresh succeed; repeated host events cannot force a refresh storm.

No new BPF probes or maps. Additional cost is event serialization/storage for
previously discarded events; keep the existing duration threshold.

Validation on the 5.10 test VM: the current-source BPF object loads and both
existing probes attach. A labeled fixture verifies host-stream serialization
and SQLite persistence. These are separate checks, not a real reclaim event
delivery test. Global direct-reclaim pressure has not been generated: imposing
a limit on one cgroup does not equivalently exercise `try_to_free_pages`.
Run the opt-in attach test with `HUATUO_TRIGGER_BPF_DIR`; the persistence test
requires only the `integration` build tag.
