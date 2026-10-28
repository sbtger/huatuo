// Copyright 2026 The HuaTuo Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package collector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/ccfos/huatuo/internal/bpf"
	"github.com/ccfos/huatuo/internal/pod"
	"github.com/ccfos/huatuo/pkg/metric"

	"github.com/ccfos/huatuo/internal/cgroups/paths"
	"github.com/ccfos/huatuo/internal/cgroups/subsystem"
	"github.com/ccfos/huatuo/internal/tracing"
	"github.com/ccfos/huatuo/pkg/types"
)

// setCgroupRootfs points the cgroup rootfs at a temp dir containing an empty
// memory subsystem directory, and restores the original on cleanup.
func setCgroupRootfs(t *testing.T) string {
	t.Helper()

	orig := paths.RootfsDefaultPath
	t.Cleanup(func() { paths.RootfsDefaultPath = orig })

	paths.RootfsDefaultPath = t.TempDir()

	memDir := filepath.Join(paths.RootfsDefaultPath, subsystem.SubsystemMemory)
	if err := os.MkdirAll(memDir, 0o755); err != nil {
		t.Fatalf("create memory cgroup dir: %v", err)
	}

	return memDir
}

func TestNewMemOthersCollectorNotSupported(t *testing.T) {
	setCgroupRootfs(t)

	// No Didi memcg extension files: the collector must opt out with
	// ErrNotSupported so the framework marks it inactive.
	if _, err := newMemOthersCollector(); !errors.Is(err, types.ErrNotSupported) {
		t.Fatalf("newMemOthersCollector() error = %v, want ErrNotSupported", err)
	}
}

func TestNewMemOthersCollectorSupported(t *testing.T) {
	memDir := setCgroupRootfs(t)

	stat := filepath.Join(memDir, "memory.directstall_stat")
	if err := os.WriteFile(stat, []byte("directstall_time 0\n"), 0o600); err != nil {
		t.Fatalf("create %s: %v", stat, err)
	}

	attr, err := newMemOthersCollector()
	if err != nil {
		t.Fatalf("newMemOthersCollector() error = %v, want nil", err)
	}
	if attr == nil || attr.Flag&tracing.FlagMetric == 0 {
		t.Fatalf("newMemOthersCollector() attr = %+v, want metric collector", attr)
	}
}

func stallMapItem(css uint64, counters ...uint64) bpf.MapItem {
	key, value := make([]byte, 8), make([]byte, 8*len(counters))
	binary.LittleEndian.PutUint64(key, css)
	for i, count := range counters {
		binary.LittleEndian.PutUint64(value[8*i:], count)
	}
	return bpf.MapItem{
		Key:   key,
		Value: value,
	}
}

func stallCountersItem(css uint64, counters ...uint64) bpf.MapItem {
	item := stallMapItem(css)
	item.Value = make([]byte, 16*(len(counters)/2))
	for cpu := 0; cpu < len(counters)/2; cpu++ {
		binary.LittleEndian.PutUint64(item.Value[cpu*16:], counters[cpu*2])
		binary.LittleEndian.PutUint64(item.Value[cpu*16+8:], counters[cpu*2+1])
	}
	return item
}

func stallContainer(name string, css uint64) *pod.Container {
	return &pod.Container{
		Name:      name,
		CgroupCss: map[string]uint64{subsystem.SubsystemMemory: css},
		Labels:    map[string]any{"HostNamespace": "default"},
	}
}

func TestContainerMemoryStallsConversion(t *testing.T) {
	items := []bpf.MapItem{
		stallCountersItem(0, 10000000, 20000000, 1000000, 2000000),
		stallCountersItem(42, 2000000, 3000000, 4000000, 5000000),
		stallCountersItem(43, 9000000, 9000000),
		{Key: []byte{1}},
	}
	data, err := containerMemoryStalls(items, map[uint64]*pod.Container{42: stallContainer("stall-fixture", 42)})
	if err == nil || len(data) != 4 {
		t.Fatalf("data=%v error=%v", data, err)
	}
	for i, name := range []string{"compaction_stall", "allocpages_stall", "container_compaction_stall", "container_allocpages_stall"} {
		if data[i].Name() != name || data[i].Value != []float64{11, 22, 6, 8}[i] || data[i].Type() != metric.MetricTypeGauge {
			t.Fatalf("invalid stall: name=%s value=%v", data[i].Name(), data[i].Value)
		}
		if i >= 2 && data[i].Labels()[metric.LabelContainerName] != "stall-fixture" {
			t.Fatalf("invalid labels: %v", data[i].Labels())
		}
	}
	data, err = containerMemoryStalls(items[:3], nil)
	if err != nil || len(data) != 2 {
		t.Fatalf("unknown targets exported: data=%v err=%v", data, err)
	}
}

type memoryStallBPFStub struct {
	bpf.BPF
	items []bpf.MapItem
	err   error
}

func (s *memoryStallBPFStub) DumpMapByName(string) ([]bpf.MapItem, error) {
	return s.items, s.err
}

func TestMemoryStallsPartialOutput(t *testing.T) {
	failure := errors.New("container unavailable")
	for _, stage := range []string{"discovery", "missing CSS", "invalid host", "invalid container", "map"} {
		t.Run(stage, func(t *testing.T) {
			stub := &memoryStallBPFStub{items: []bpf.MapItem{
				stallCountersItem(0, 10000000, 20000000),
				stallCountersItem(42, 2000000, 3000000),
				stallCountersItem(43, 4000000, 5000000),
			}}
			want, wantError := 6, false
			switch stage {
			case "discovery":
				want, wantError = 2, true
			case "missing CSS":
				want = 4
			case "invalid host":
				stub.items[0].Value = []byte{1}
				want, wantError = 4, true
			case "invalid container":
				stub.items[2].Value = []byte{1}
				want, wantError = 4, true
			case "map":
				stub.err = failure
				want, wantError = 0, true
			}
			data, err := (&reclaimCompact{}).update(&memoryStallObject{
				BPF:        stub,
				containers: true,
			}, func() (map[string]*pod.Container, error) {
				if stage == "discovery" {
					return map[string]*pod.Container{"partial": stallContainer("partial", 42)}, failure
				}
				invalidCSS := uint64(43)
				if stage == "missing CSS" {
					invalidCSS = 0
				}
				return map[string]*pod.Container{
					"valid": stallContainer("valid", 42),
					"other": stallContainer("other", invalidCSS),
				}, nil
			})
			if len(data) != want || (err != nil) != wantError {
				t.Fatalf("stage=%s metrics=%v err=%v", stage, data, err)
			}
			if stage == "discovery" || stage == "map" {
				if !errors.Is(err, failure) {
					t.Fatalf("lost error: %v", err)
				}
			}
		})
	}
}

func TestMemcgReclaimPerCPUTotals(t *testing.T) {
	containers := map[uint64]*pod.Container{
		42: {
			Name:   "valid",
			Labels: map[string]any{"HostNamespace": "default"},
		},
		43: {
			Name:   "idle",
			Labels: map[string]any{"HostNamespace": "default"},
		},
	}
	data, err := memcgReclaimMetrics([]bpf.MapItem{stallMapItem(0, 10, 20), stallMapItem(42, 2, 3)}, containers)
	if err != nil || len(data) != 2 {
		t.Fatalf("metrics=%v err=%v", data, err)
	}
	for i, want := range []float64{30, 5} {
		if data[i].Value != want {
			t.Fatalf("metric %d=%v want=%v", i, data[i].Value, want)
		}
	}
	if data[0].Name() != "directstall" || data[1].Name() != "container_directstall" {
		t.Fatal("metric names changed")
	}
	data, err = memcgReclaimMetrics([]bpf.MapItem{stallMapItem(42, 2, 3)}, containers)
	if err == nil || len(data) != 1 {
		t.Fatalf("missing host swallowed: data=%v err=%v", data, err)
	}
	stub := &memoryStallBPFStub{items: []bpf.MapItem{stallMapItem(0, 10, 20), stallMapItem(42, 2, 3)}}
	failure := errors.New("discovery failed")
	data, err = (&memoryCgroupReclaim{}).update(stub, func() (map[string]*pod.Container, error) { return nil, failure })
	if !errors.Is(err, failure) || len(data) != 1 || data[0].Value != 30 {
		t.Fatalf("host output lost: data=%v err=%v", data, err)
	}
}

type memoryStallAttachStub struct {
	bpf.BPF
	attachErr, closeErr error
	closed              int
}

func (s *memoryStallAttachStub) AttachWithOptions([]bpf.AttachOption) error { return s.attachErr }
func (s *memoryStallAttachStub) Close() error                               { s.closed++; return s.closeErr }
func TestMemoryStallsHostFallback(t *testing.T) {
	for _, stage := range []string{"load", "attach", "host", "close"} {
		t.Run(stage, func(t *testing.T) {
			failure := errors.New("container unavailable")
			hostFailure := errors.New("host unavailable")
			closeFailure := errors.New("close failed")
			first, last := &memoryStallAttachStub{}, &memoryStallAttachStub{}
			calls := []bool{}
			obj, err := loadMemoryStalls("fixture", func(_ string, containers bool) (bpf.BPF, error) {
				calls = append(calls, containers)
				if !containers {
					if stage == "host" {
						return nil, hostFailure
					}
					return last, nil
				}
				if stage == "load" || stage == "host" {
					return nil, failure
				}
				first.attachErr = failure
				if stage == "close" {
					first.closeErr = closeFailure
				}
				return first, nil
			})
			if stage == "host" || stage == "close" {
				if obj != nil || !errors.Is(err, failure) {
					t.Fatalf("obj=%v err=%v", obj, err)
				}
				expected := hostFailure
				if stage == "close" {
					expected = closeFailure
				}
				if !errors.Is(err, expected) {
					t.Fatalf("missing error %v: %v", expected, err)
				}
			} else if err != nil || obj == nil || obj.containers || obj.BPF != last {
				t.Fatalf("fallback obj=%v err=%v", obj, err)
			}
			want := 2
			if stage == "close" {
				want = 1
			}
			if len(calls) != want || !calls[0] || (want == 2 && calls[1]) {
				t.Fatalf("load modes=%v", calls)
			}
			if stage == "attach" || stage == "close" {
				if first.closed != 1 {
					t.Fatal("failed object not closed")
				}
			}
		})
	}
}

func BenchmarkMemoryStallPerCPUSum(b *testing.B) {
	for _, cpus := range []int{1, 4, 64, 256} {
		b.Run(fmt.Sprintf("cpus-%d", cpus), func(b *testing.B) {
			value := make([]byte, 16*cpus)
			for cpu := range cpus {
				binary.LittleEndian.PutUint64(value[cpu*16:], 1)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				total, err := decodeMemoryLatency(value)
				if err != nil || total.CompactionStat != uint64(cpus) {
					b.Fatal(total, err)
				}
			}
		})
	}
}

func TestMemoryLoadersRejectMissingMap(t *testing.T) {
	for _, name := range []string{"mm_free_compact_map", "memory_cgroup_allocpages_stall"} {
		if err := requireMemoryMap("fixture.o", &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{}}, name); err == nil {
			t.Fatal("missing map accepted", name)
		}
	}
}

func TestMemcgReclaimMissingRowsRemainMissing(t *testing.T) {
	containers := map[uint64]*pod.Container{42: {Name: "unrecorded"}}
	for _, items := range [][]bpf.MapItem{
		{stallMapItem(0, 0)},
		{stallMapItem(0, 10), stallMapItem(43, 10)},
		{stallMapItem(0, 10), {
			Key:   stallMapItem(42).Key,
			Value: []byte{1},
		}},
	} {
		data, _ := memcgReclaimMetrics(items, containers)
		if len(data) != 1 || data[0].Name() != "directstall" {
			t.Fatalf("unknown count exported as zero: %v", data)
		}
	}
}

func TestMemoryHostOnlySkipsDiscovery(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		t.Run(fmt.Sprintf("malformed-%t", malformed), func(t *testing.T) {
			discover := func() (map[string]*pod.Container, error) {
				t.Fatal("host-only snapshot queried container metadata")
				return nil, nil
			}
			stall := stallCountersItem(0, 1000000, 2000000)
			reclaim := stallMapItem(0, 10, 20)
			if malformed {
				stall.Value, reclaim.Value = []byte{1}, []byte{1}
			}
			data, err := (&reclaimCompact{}).update(&memoryStallObject{
				BPF: &memoryStallBPFStub{items: []bpf.MapItem{stall}}, containers: true,
			}, discover)
			if malformed {
				if err == nil || len(data) != 0 {
					t.Fatalf("invalid host stall accepted: %v %v", data, err)
				}
			} else if err != nil || len(data) != 2 || data[0].Value != 1 || data[1].Value != 2 {
				t.Fatalf("host stall changed: %v %v", data, err)
			}
			data, err = (&memoryCgroupReclaim{}).update(&memoryStallBPFStub{items: []bpf.MapItem{reclaim}}, discover)
			if malformed {
				if err == nil || len(data) != 0 {
					t.Fatalf("invalid host reclaim accepted: %v %v", data, err)
				}
			} else if err != nil || len(data) != 1 || data[0].Value != 30 {
				t.Fatalf("host reclaim changed: %v %v", data, err)
			}
		})
	}
}

func BenchmarkMemcgReclaimUnknownCSS(b *testing.B) {
	items := make([]bpf.MapItem, 1025)
	items[0] = stallMapItem(0, 1)
	for i := 1; i < len(items); i++ {
		items[i] = stallMapItem(uint64(i), make([]uint64, 64)...)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		data, err := memcgReclaimMetrics(items, nil)
		if err != nil || len(data) != 1 {
			b.Fatalf("host output lost: %v %v", data, err)
		}
	}
}
