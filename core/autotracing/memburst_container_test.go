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

package autotracing

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"huatuo-bamai/internal/cgroups"
	"huatuo-bamai/internal/cgroups/paths"
)

func TestContainerBurstMemory(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "pod")
	dir := filepath.Join(parent, "container")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir, parent} {
		if err := os.WriteFile(filepath.Join(path, "memory.max"), []byte("max\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw := map[string]uint64{"active_anon": 4096, "inactive_anon": 2048}
	current, limit, err := containerBurstMemory(raw, root, dir, 1024, true)
	if err != nil || current != 6 || limit != 1024 {
		t.Fatal(current, limit, err)
	}
	if err := os.WriteFile(filepath.Join(parent, "memory.max"), []byte("524288\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, limit, err = containerBurstMemory(raw, root, dir, 1024, true)
	if err != nil || limit != 512 {
		t.Fatal(limit, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "memory.max"), []byte("262144\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, limit, err = containerBurstMemory(raw, root, dir, 1024, true)
	if err != nil || limit != 256 {
		t.Fatal(limit, err)
	}
	v1 := map[string]uint64{"total_active_anon": 4096, "total_inactive_anon": 2048, "hierarchical_memory_limit": 131072}
	current, limit, err = containerBurstMemory(v1, root, dir, 1024, false)
	if err != nil || current != 6 || limit != 128 {
		t.Fatal(current, limit, err)
	}
	delete(v1, "total_active_anon")
	if _, _, err := containerBurstMemory(v1, root, dir, 1024, false); err == nil {
		t.Fatal("missing counter accepted")
	}
	raw["inactive_anon"] = ^uint64(0)
	if _, _, err := containerBurstMemory(raw, root, dir, 1024, true); err == nil {
		t.Fatal("overflow accepted")
	}
}

func TestRecordMemoryBurst(t *testing.T) {
	history := make([]int, 3)
	index, full := 0, false
	for i, current := range []int{10, 20, 70, 70, 70} {
		got := recordMemoryBurst(current, 100, history, &index, &full, 2, 70)
		if got != (i == 2 || i == 3) {
			t.Fatalf("sample %d: trigger=%v", i, got)
		}
	}
}

func TestContainerMemBurstCooldownSurvivesHistoryReset(t *testing.T) {
	cfg := &MemBurstConfig{
		SlidingWindowLength: 3, DeltaMemoryBurst: 100,
		DeltaAnonThreshold: 70, IntervalTracing: 1800,
	}
	lastTrace := time.Date(2026, time.September, 9, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name  string
		reset bool
		path  string
		limit int
	}{
		{name: "missing samples", reset: true, path: "/container", limit: 100},
		{name: "path change", path: "/new-container-path", limit: 100},
		{name: "limit change", path: "/container", limit: 120},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := &containerMemBurst{
				path: "/container", limit: 100,
				history: []int{10, 10, 90}, index: 1, full: true,
				lastTrace: lastTrace,
			}
			if tc.reset {
				// Repeated failures must neither retain stale samples nor lose cooldown.
				state.resetHistory()
				state.resetHistory()
			}
			for i, current := range []int{10, 10, 90} {
				now := lastTrace.Add(time.Duration(600+i*10) * time.Second)
				if state.recordSample(tc.path, current, tc.limit, cfg, now) {
					t.Fatal("triggered before the original cooldown expired")
				}
				if state.full != (i == 2) || state.index != (i+1)%3 {
					t.Fatalf("sample %d: stale window retained: %+v", i, state)
				}
				if !state.lastTrace.Equal(lastTrace) {
					t.Fatal("history reset or sampling changed lastTrace")
				}
			}
			for i, current := range []int{10, 10, 90} {
				now := lastTrace.Add(time.Duration(1780+i*10) * time.Second)
				if got := state.recordSample(tc.path, current, tc.limit, cfg, now); got != (i == 2) {
					t.Fatalf("sample %d at cooldown boundary: trigger=%v", i, got)
				}
			}
		})
	}
}

func TestContainerMemBurstWithoutPreviousTrace(t *testing.T) {
	// A failed first read has no state to reset.
	var state *containerMemBurst
	state.resetHistory()
	state = &containerMemBurst{}
	cfg := &MemBurstConfig{
		SlidingWindowLength: 3, DeltaMemoryBurst: 100,
		DeltaAnonThreshold: 70, IntervalTracing: 1800,
	}
	now := time.Date(2026, time.September, 9, 0, 0, 0, 0, time.UTC)
	for i, current := range []int{10, 10, 90} {
		if got := state.recordSample("/container", current, 100, cfg, now); got != (i == 2) {
			t.Fatalf("sample %d without a previous trace: trigger=%v", i, got)
		}
	}
}

func BenchmarkContainerMemBurstRecordSample(b *testing.B) {
	cfg := &MemBurstConfig{
		SlidingWindowLength: 60, DeltaMemoryBurst: 100,
		DeltaAnonThreshold: 70, IntervalTracing: 1800,
	}
	now := time.Now()
	state := &containerMemBurst{}
	state.recordSample("/container", 75, 100, cfg, now)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		state.recordSample("/container", 75, 100, cfg, now)
	}
}

func TestContainerMemoryProcesses(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "nested")
	if err := os.Mkdir(child, 0o750); err != nil {
		t.Fatal(err)
	}
	// A fixture with the current process verifies recursive scope and deduplication.
	pid := []byte(fmt.Sprint(os.Getpid(), "\n"))
	for _, dir := range []string{root, child} {
		if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), pid, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	procs, err := containerMemoryProcesses(root, 10)
	if err != nil || len(procs) != 1 || procs[0].PID != int32(os.Getpid()) {
		t.Fatal(procs, err)
	}
}

func BenchmarkRecordMemoryBurst(b *testing.B) {
	history := make([]int, 60)
	index, full := 0, false
	for b.Loop() {
		recordMemoryBurst(75, 100, history, &index, &full, 2, 70)
	}
}

func TestContainerBurstLiveMemory(t *testing.T) {
	if os.Getenv("HUATUO_TRIGGER_LIVE_MEMORY") != "1" {
		t.Skip("set HUATUO_TRIGGER_LIVE_MEMORY=1 on a test VM")
	}
	manager, err := cgroups.NewManager()
	if err != nil {
		t.Fatal(err)
	}
	membership, err := cgroups.PathsForPID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	unified := cgroups.CgroupMode() == cgroups.Unified
	root := paths.RootfsDefaultPath
	group := membership.Unified
	if !unified {
		root = filepath.Join(root, "memory")
		group = membership.Controllers["memory"]
	}
	if group == "" {
		t.Fatal("missing memory cgroup")
	}
	raw, err := manager.MemoryStatRaw(group)
	if err != nil {
		t.Fatal(err)
	}
	mem, err := readMemInfo(map[string]bool{"MemTotal": true})
	if err != nil {
		t.Fatal(err)
	}
	current, limit, err := containerBurstMemory(raw, root, filepath.Join(root, group), mem["MemTotal"], unified)
	if err != nil || current <= 0 || limit <= 0 {
		t.Fatal(current, limit, err)
	}
	t.Logf("live memory cgroup %s: anonymous LRU=%d KiB, effective denominator=%d KiB", group, current, limit)
}
