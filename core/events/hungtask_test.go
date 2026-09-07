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

package events

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/bpf/abi"
	"huatuo-bamai/internal/cgroups/paths"
	"huatuo-bamai/internal/pod"
	"huatuo-bamai/pkg/metric"

	"github.com/cilium/ebpf"
)

func hungTaskTestContainers() map[string]*pod.Container {
	return map[string]*pod.Container{
		"test": {ID: "test", Name: "workload", CgroupPath: "/kubepods/test", Labels: map[string]any{"HostNamespace": "test"}},
	}
}

func TestHungTaskContainer(t *testing.T) {
	containers := hungTaskTestContainers()
	containers["nested"] = &pod.Container{ID: "nested", CgroupPath: "/kubepods/test/nested"}
	containers["root"] = &pod.Container{ID: "root", CgroupPath: "/"}
	containers["empty"] = &pod.Container{ID: "empty"}
	containers["relative"] = &pod.Container{ID: "relative", CgroupPath: "relative"}
	containers["nil"] = nil
	resolve := func(root string) (uint64, error) {
		switch root {
		case "/kubepods/test":
			return 1<<32 | 42, nil
		case "/kubepods/test/nested":
			return 43, nil
		default:
			t.Fatalf("invalid container root %q", root)
			return 0, nil
		}
	}
	for _, tt := range []struct {
		name string
		ids  []uint64
		want string
	}{
		{"exact", []uint64{1<<32 | 42}, "test"},
		{"child", []uint64{100, 1<<32 | 42}, "test"},
		{"nearest", []uint64{100, 43, 1<<32 | 42}, "nested"},
		{"reused inode", []uint64{2<<32 | 42}, ""},
		{"unmatched", []uint64{100}, ""},
		{"host fallback", nil, ""},
		{"zero ID", []uint64{0}, ""},
	} {
		event := hungTaskEvent(tt.ids...)
		got := hungTaskContainer(&event, containers, resolve)
		if tt.want == "" {
			if got != nil {
				t.Fatalf("%s matched %s", tt.name, got.ID)
			}
		} else if got == nil || got.ID != tt.want {
			t.Fatalf("%s: got %v, want %s", tt.name, got, tt.want)
		}
	}
	event := hungTaskEvent(42)
	if got := hungTaskContainer(&event, containers, func(string) (uint64, error) { return 0, os.ErrNotExist }); got != nil {
		t.Fatal("removed cgroup was attributed")
	}
	event.CgroupCount = 17
	if got := hungTaskContainer(&event, containers, resolve); got != nil {
		t.Fatal("invalid event was attributed")
	}
}

func hungTaskEvent(ids ...uint64) abi.HungtaskEvent {
	event := abi.HungtaskEvent{TID: 321, CgroupCount: uint32(len(ids))}
	copy(event.CgroupIds[:], ids)
	return event
}

func TestHungTaskRecordIdentity(t *testing.T) {
	originalCount := atomic.LoadInt64(&hungtaskCounter)
	t.Cleanup(func() { atomic.StoreInt64(&hungtaskCounter, originalCount) })
	containers := hungTaskTestContainers()
	discover := func() (map[string]*pod.Container, error) { return containers, nil }
	c := hungTaskTracing{nextAllowedTime: time.Now().Add(time.Hour)}
	resolve := func(string) (uint64, error) { return 42, nil }
	// TID is not consulted: exited/reused/migrated tasks retain event identity.
	for _, tid := range []uint32{321, 999} {
		event := hungTaskEvent(42)
		event.TID = tid
		container, err := c.record(&event, discover, resolve)
		if err != nil || container == nil || container.ID != "test" {
			t.Fatalf("record: %v, %v", container, err)
		}
	}
	data, err := c.update(discover)
	if err != nil {
		t.Fatal(err)
	}
	assertHungTaskMetrics(t, data, map[string]float64{"total": float64(originalCount + 2), "container_total": 2})
	for _, count := range []uint32{0, 17} {
		event := abi.HungtaskEvent{CgroupCount: count}
		container, err := c.record(&event, func() (map[string]*pod.Container, error) {
			t.Fatal("host-only event must not discover containers")
			return nil, nil
		}, resolve)
		if err != nil || container != nil {
			t.Fatalf("host event: %v, %v", container, err)
		}
	}
	if atomic.LoadInt64(&hungtaskCounter) != originalCount+4 {
		t.Fatal("lost host count")
	}
}

func TestHungTaskDiscoveryFailureAndCleanup(t *testing.T) {
	original := atomic.LoadInt64(&hungtaskCounter)
	t.Cleanup(func() { atomic.StoreInt64(&hungtaskCounter, original) })
	c := hungTaskTracing{containerCounts: map[string]uint64{"test": 2, "exited": 3}}
	failure := errors.New("discovery unavailable")
	fail := func() (map[string]*pod.Container, error) { return nil, failure }
	event := hungTaskEvent(42)
	_, err := c.record(&event, fail, func(string) (uint64, error) { t.Fatal("unexpected ID lookup"); return 0, nil })
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	data, err := c.update(fail)
	if !errors.Is(err, failure) {
		t.Fatal(err)
	}
	assertHungTaskMetrics(t, data, map[string]float64{"total": float64(original + 1)})
	if len(c.containerCounts) != 2 {
		t.Fatal("discovery outage discarded counters")
	}
	data, err = c.update(func() (map[string]*pod.Container, error) { return hungTaskTestContainers(), nil })
	if err != nil {
		t.Fatal(err)
	}
	assertHungTaskMetrics(t, data, map[string]float64{"total": float64(original + 1), "container_total": 2})
	if len(c.containerCounts) != 1 {
		t.Fatal("exited container was not removed")
	}
}

func assertHungTaskMetrics(t *testing.T, data []*metric.Data, want map[string]float64) {
	t.Helper()
	if len(data) != len(want) {
		t.Fatalf("got %d metrics, want %d", len(data), len(want))
	}
	for _, m := range data {
		value, ok := want[m.Name()]
		if !ok || m.Value != value || m.Type() != metric.MetricTypeCounter {
			t.Fatalf("unexpected metric %s=%v", m.Name(), m.Value)
		}
		if m.Name() == "container_total" && m.Labels()["container_name"] != "workload" {
			t.Fatalf("labels: %v", m.Labels())
		}
		delete(want, m.Name())
	}
}

func TestHungTaskConcurrentRecordAndUpdate(t *testing.T) {
	original := atomic.LoadInt64(&hungtaskCounter)
	t.Cleanup(func() { atomic.StoreInt64(&hungtaskCounter, original) })
	c := hungTaskTracing{}
	containers := hungTaskTestContainers()
	discover := func() (map[string]*pod.Container, error) { return containers, nil }
	resolve := func(string) (uint64, error) { return 42, nil }
	event := hungTaskEvent(42)
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				if _, err := c.record(&event, discover, resolve); err != nil {
					t.Error(err)
				}
				if _, err := c.update(discover); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	data, err := c.update(discover)
	if err != nil {
		t.Fatal(err)
	}
	assertHungTaskMetrics(t, data, map[string]float64{"total": float64(original + 400), "container_total": 400})
}

func BenchmarkHungTaskContainer(b *testing.B) {
	containers := hungTaskTestContainers()
	event := hungTaskEvent(100, 42)
	resolve := func(string) (uint64, error) { return 42, nil }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if hungTaskContainer(&event, containers, resolve) == nil {
			b.Fatal("missing container")
		}
	}
}

type hungTaskBPF struct {
	bpf.BPF
	attachErr, closeErr error
	closed, attached    bool
}

func (b *hungTaskBPF) AttachAndEventPipe(context.Context, string, uint32) (bpf.PerfEventReader, error) {
	b.attached = true
	return nil, b.attachErr
}

func (b *hungTaskBPF) Close() error { b.closed = true; return b.closeErr }

func TestHungTaskFallback(t *testing.T) {
	failure := errors.New("unsupported target-task cgroup access")
	for _, stage := range []string{"none", "load", "attach", "close", "both", "host attach"} {
		t.Run(stage, func(t *testing.T) {
			full, host := &hungTaskBPF{}, &hungTaskBPF{}
			if stage == "attach" || stage == "close" || stage == "host attach" {
				full.attachErr = failure
			}
			if stage == "close" {
				full.closeErr = failure
			}
			if stage == "host attach" {
				host.attachErr = failure
			}
			calls := 0
			obj, _, err := startHungTaskBPF(context.Background(), "hungtask.o", func(_ string, containers bool) (bpf.BPF, error) {
				calls++
				if containers != (calls == 1) || calls > 2 {
					t.Fatal("unexpected retry")
				}
				if stage == "both" || (stage == "load" && containers) {
					return nil, failure
				}
				if containers {
					return full, nil
				}
				if full.attached && !full.closed {
					t.Fatal("retry before cleanup")
				}
				return host, nil
			})
			wantCalls := 2
			if stage == "none" || stage == "close" {
				wantCalls = 1
			}
			if calls != wantCalls {
				t.Fatalf("%d attempts, want %d", calls, wantCalls)
			}
			if stage == "both" || stage == "close" || stage == "host attach" {
				if !errors.Is(err, failure) || obj != nil {
					t.Fatalf("%v, %v", obj, err)
				}
				if stage == "host attach" && !host.closed {
					t.Fatal("failed fallback leaked")
				}
			} else {
				want := host
				if stage == "none" {
					want = full
				}
				if err != nil || obj != want {
					t.Fatalf("%v, %v", obj, err)
				}
			}
		})
	}
}

func TestHungTaskBPFLayout(t *testing.T) {
	object := os.Getenv("HUATUO_HUNGTASK_BPF_OBJECT")
	if object == "" {
		t.Skip("set HUATUO_HUNGTASK_BPF_OBJECT to the compiled object")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Programs) != 2 || spec.Programs["raw_sched_process_hang"].Type != ebpf.RawTracepoint ||
		spec.Programs["tracepoint_sched_process_hang"].Type != ebpf.TracePoint || abi.HungtaskEventSize != 152 {
		t.Fatal("unexpected hungtask programs or event ABI")
	}
	for _, unified := range []uint32{0, 1} {
		if err := spec.Copy().RewriteConstants(map[string]any{"unified_cgroups": unified}); err != nil {
			t.Fatal(err)
		}
	}
	if os.Getenv("HUATUO_BPF_INTEGRATION") != "1" {
		return
	}
	previous := bpf.DefaultObjDir
	bpf.DefaultObjDir = filepath.Dir(object)
	t.Cleanup(func() { bpf.DefaultObjDir = previous })
	// Only attach: do not induce hung tasks or alter the system timeout.
	for _, containers := range []bool{false, true} {
		obj, err := loadHungTaskObject(filepath.Base(object), containers)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer obj.Close()
			reader, err := obj.AttachAndEventPipe(context.Background(), "hungtask_perf_events", 8192)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			if (obj.ProgramIDByName("raw_sched_process_hang") != 0) != containers {
				t.Fatal("wrong capture mode")
			}
		}()
	}
}

func BenchmarkHungTaskContainerKernfs(b *testing.B) {
	root := os.Getenv("HUATUO_HUNGTASK_CGROUP_PATH")
	if root == "" {
		b.Skip("set HUATUO_HUNGTASK_CGROUP_PATH to a cgroup directory")
	}
	id, err := paths.KernfsID(root)
	if err != nil {
		b.Fatal(err)
	}
	containers := hungTaskTestContainers()
	event := hungTaskEvent(id)
	resolve := func(string) (uint64, error) { return paths.KernfsID(root) }
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if hungTaskContainer(&event, containers, resolve) == nil {
			b.Fatal("missing container")
		}
	}
}
