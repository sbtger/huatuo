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

package collector

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/pod"

	"github.com/cilium/ebpf"
)

func memoryStallItem(css, compact, reclaim uint64) bpf.MapItem {
	key, value := make([]byte, 8), make([]byte, 16)
	binary.LittleEndian.PutUint64(key, css)
	binary.LittleEndian.PutUint64(value, compact)
	binary.LittleEndian.PutUint64(value[8:], reclaim)
	return bpf.MapItem{Key: key, Value: value}
}

type memoryStallBPF struct {
	bpf.BPF
	containerErr        error
	hostOnly            bool
	attachErr, closeErr error
	closed              bool
	opts                []bpf.AttachOption
}

func (b *memoryStallBPF) ProgramIDByName(string) uint32 {
	if b.hostOnly {
		return 0
	}
	return 1
}

func (b *memoryStallBPF) AttachWithOptions(opts []bpf.AttachOption) error {
	b.opts = opts
	return b.attachErr
}

func (b *memoryStallBPF) Close() error { b.closed = true; return b.closeErr }

func TestMemoryStallHostOnly(t *testing.T) {
	c := reclaimCompact{}
	data, err := c.update(&memoryStallBPF{hostOnly: true}, func() (map[string]*pod.Container, error) {
		t.Fatal("host-only collector must not discover containers")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertVMStatMetrics(t, data, map[string]float64{"compaction_stall": 2, "allocpages_stall": 3})
}

func TestMemoryStallFallback(t *testing.T) {
	failure := errors.New("unsupported container feature")
	for _, stage := range []string{"none", "load", "attach", "close", "both", "host attach"} {
		t.Run(stage, func(t *testing.T) {
			full, host := &memoryStallBPF{}, &memoryStallBPF{hostOnly: true}
			if stage == "attach" || stage == "close" {
				full.attachErr = failure
			}
			if stage == "close" {
				full.closeErr = failure
			}
			if stage == "host attach" {
				full.attachErr, host.attachErr = failure, failure
			}
			calls := 0
			obj, err := loadMemoryStalls("test", func(_ string, containers bool) (bpf.BPF, error) {
				calls++
				if containers {
					if stage == "load" || stage == "both" {
						return nil, failure
					}
					return full, nil
				}
				if full.attachErr != nil && !full.closed {
					t.Fatal("fallback before close")
				}
				if stage == "both" {
					return nil, failure
				}
				return host, nil
			})
			if stage == "close" || stage == "both" || stage == "host attach" {
				if obj != nil || !errors.Is(err, failure) {
					t.Fatalf("got %v, %v", obj, err)
				}
				if stage == "close" && calls != 1 {
					t.Fatal("must not retry after close failure")
				}
				if stage == "host attach" && (!host.closed || calls != 2) {
					t.Fatal("failed host fallback must close without further retries")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if stage == "none" {
				if obj != full || calls != 1 || len(full.opts) != 5 || full.opts[0].ProgramName != "memory_stall_cgroup_mkdir" {
					t.Fatal("unexpected full attachment")
				}
			} else if obj != host || calls != 2 || len(host.opts) != 4 {
				t.Fatal("unexpected host fallback")
			}
		})
	}
}

func (b *memoryStallBPF) DumpMapByName(name string) ([]bpf.MapItem, error) {
	if name == "mm_free_compact_map" {
		return []bpf.MapItem{memoryStallItem(0, 2_000_000, 3_000_000)}, nil
	}
	return []bpf.MapItem{memoryStallItem(42, 1_000_000, 500_000)}, b.containerErr
}

func TestMemoryStallFailureIsolation(t *testing.T) {
	failure := errors.New("container unavailable")
	for _, tt := range []struct {
		name                 string
		discoveryErr, mapErr error
	}{
		{"success", nil, nil},
		{"discovery", failure, nil},
		{"map", nil, failure},
	} {
		t.Run(tt.name, func(t *testing.T) {
			container := vmstatTestContainer("")
			container.CgroupCss = map[string]uint64{"memory": 42}
			c := reclaimCompact{}
			data, err := c.update(&memoryStallBPF{containerErr: tt.mapErr}, func() (map[string]*pod.Container, error) {
				return map[string]*pod.Container{"test": container}, tt.discoveryErr
			})
			want := map[string]float64{"compaction_stall": 2, "allocpages_stall": 3}
			if tt.discoveryErr != nil || tt.mapErr != nil {
				if !errors.Is(err, failure) {
					t.Fatalf("error = %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				want["container_compaction_stall"] = 1
				want["container_allocpages_stall"] = 0.5
			}
			assertVMStatMetrics(t, data, want)
		})
	}
}

func TestContainerMemoryStalls(t *testing.T) {
	containers := map[uint64]*pod.Container{42: vmstatTestContainer("")}
	for _, tt := range []struct {
		name    string
		items   []bpf.MapItem
		want    map[string]float64
		wantErr bool
	}{
		{"missing", nil, map[string]float64{}, false},
		{"unknown", []bpf.MapItem{memoryStallItem(0, 1, 2), memoryStallItem(99, 3, 4)}, map[string]float64{}, false},
		{"valid zero", []bpf.MapItem{memoryStallItem(42, 0, 1_500_000)}, map[string]float64{"container_compaction_stall": 0, "container_allocpages_stall": 1.5}, false},
		{"malformed with valid", []bpf.MapItem{{Key: []byte{1}}, memoryStallItem(42, 1_000_000, 0)}, map[string]float64{"container_compaction_stall": 1, "container_allocpages_stall": 0}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data, err := containerMemoryStalls(tt.items, containers)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v", err)
			}
			assertVMStatMetrics(t, data, tt.want)
		})
	}
}

func BenchmarkContainerMemoryStalls(b *testing.B) {
	items := []bpf.MapItem{memoryStallItem(42, 1_000_000, 500_000)}
	containers := map[uint64]*pod.Container{42: vmstatTestContainer("")}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := containerMemoryStalls(items, containers); err != nil {
			b.Fatal(err)
		}
	}
}

// HUATUO_MEMORY_STALL_BPF_OBJECT selects a freshly compiled object, avoiding
// accidental verification of stale generated artifacts.
func TestMemoryStallBPFLayout(t *testing.T) {
	object := os.Getenv("HUATUO_MEMORY_STALL_BPF_OBJECT")
	if object == "" {
		t.Skip("set HUATUO_MEMORY_STALL_BPF_OBJECT to a freshly built object")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name            string
		kind            ebpf.MapType
		key, value, max uint32
	}{
		{"mm_free_compact_map", ebpf.Array, 4, 16, 1},
		{"mm_container_free_compact_map", ebpf.LRUHash, 8, 16, 10240},
		{"mm_stall_start", ebpf.LRUHash, 16, 24, 10240},
	} {
		m := spec.Maps[tt.name]
		if m == nil || m.Type != tt.kind || m.KeySize != tt.key || m.ValueSize != tt.value || m.MaxEntries != tt.max {
			t.Fatalf("unexpected map %s: %+v", tt.name, m)
		}
	}
	if len(spec.Programs) != 5 {
		t.Fatalf("got %d programs, want 5", len(spec.Programs))
	}
	for _, enabled := range []uint32{0, 1} {
		if err := spec.Copy().RewriteConstants(map[string]any{"enable_container_stalls": enabled}); err != nil {
			t.Fatalf("rewrite container mode %d: %v", enabled, err)
		}
	}
	if os.Getenv("HUATUO_BPF_INTEGRATION") != "1" {
		return
	}
	// Exercise both production load modes, not just the default BPF object.
	previousDir := bpf.DefaultObjDir
	bpf.DefaultObjDir = filepath.Dir(object)
	t.Cleanup(func() { bpf.DefaultObjDir = previousDir })
	for _, mode := range []struct {
		name       string
		containers bool
	}{{"host", false}, {"containers", true}} {
		t.Run(mode.name, func(t *testing.T) {
			obj, err := loadMemoryStallObject(filepath.Base(object), mode.containers)
			if err != nil {
				t.Fatal(err)
			}
			defer obj.Close()
			if err := obj.AttachWithOptions(memoryStallAttachOptions(mode.containers)); err != nil {
				t.Fatal(err)
			}
			c := reclaimCompact{}
			data, err := c.update(obj, func() (map[string]*pod.Container, error) {
				if !mode.containers {
					t.Fatal("host fallback must not discover containers")
				}
				return nil, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(data) != 2 {
				t.Fatalf("got %d host metrics, want 2", len(data))
			}
		})
	}
}
