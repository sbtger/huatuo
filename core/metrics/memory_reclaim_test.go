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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/pod"
)

func hostReclaimItems(counts ...uint64) []bpf.MapItem {
	value := make([]byte, 8*len(counts))
	for i, count := range counts {
		binary.LittleEndian.PutUint64(value[i*8:], count)
	}
	return []bpf.MapItem{{Key: make([]byte, 4), Value: value}}
}

func TestHostMemcgReclaimCount(t *testing.T) {
	for _, tt := range []struct {
		name    string
		items   []bpf.MapItem
		want    uint64
		wantErr bool
	}{
		{"zero", hostReclaimItems(0, 0), 0, false},
		{"one CPU", hostReclaimItems(9), 9, false},
		{"multiple CPUs", hostReclaimItems(3, 0, 7, 11), 21, false},
		{"wide count", hostReclaimItems(1<<40, 2), 1<<40 + 2, false},
		{"missing", nil, 0, true},
		{"duplicate", append(hostReclaimItems(1), hostReclaimItems(2)...), 0, true},
		{"empty value", hostReclaimItems(), 0, true},
		{"short value", []bpf.MapItem{{Key: make([]byte, 4), Value: []byte{1}}}, 0, true},
		{"short key", []bpf.MapItem{{Key: []byte{0}, Value: make([]byte, 8)}}, 0, true},
		{"nonzero key", []bpf.MapItem{{Key: []byte{1, 0, 0, 0}, Value: make([]byte, 8)}}, 0, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hostMemcgReclaimCount(tt.items)
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Fatalf("count = %d, error = %v; want %d, error %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

type memcgReclaimBPF struct {
	bpf.BPF
	hostItems, containerItems []bpf.MapItem
	hostErr, containerErr     error
}

func (b *memcgReclaimBPF) DumpMapByName(name string) ([]bpf.MapItem, error) {
	switch name {
	case "memory_host_directstall":
		return b.hostItems, b.hostErr
	case "memory_cgroup_allocpages_stall":
		return b.containerItems, b.containerErr
	default:
		return nil, fmt.Errorf("unexpected map %q", name)
	}
}

func TestMemcgReclaimFailureIsolation(t *testing.T) {
	failure := errors.New("unavailable")
	container := vmstatTestContainer("")
	container.CgroupCss = map[string]uint64{"memory": 42}
	item := bpf.MapItem{Key: make([]byte, 8), Value: make([]byte, 8)}
	binary.LittleEndian.PutUint64(item.Key, 42)
	binary.LittleEndian.PutUint64(item.Value, 7)
	for _, tt := range []struct {
		name                                string
		hostItems, containerItems           []bpf.MapItem
		hostErr, containerErr, discoveryErr error
		noContainers                        bool
		want                                map[string]float64
		wantErr                             bool
	}{
		{name: "independent totals", hostItems: hostReclaimItems(11, 12), containerItems: []bpf.MapItem{item}, want: map[string]float64{"directstall": 23, "container_directstall": 7}},
		{name: "no discovered containers", hostItems: hostReclaimItems(23), containerItems: []bpf.MapItem{item}, noContainers: true, want: map[string]float64{"directstall": 23}},
		{name: "empty container map", hostItems: hostReclaimItems(23), want: map[string]float64{"directstall": 23, "container_directstall": 0}},
		{name: "zero before events", hostItems: hostReclaimItems(0, 0), want: map[string]float64{"directstall": 0, "container_directstall": 0}},
		{name: "discovery failure", hostItems: hostReclaimItems(23), discoveryErr: failure, want: map[string]float64{"directstall": 23}, wantErr: true},
		{name: "container map failure", hostItems: hostReclaimItems(23), containerErr: failure, want: map[string]float64{"directstall": 23}, wantErr: true},
		{name: "bad container key", hostItems: hostReclaimItems(23), containerItems: []bpf.MapItem{{Key: []byte{1}}}, want: map[string]float64{"directstall": 23}, wantErr: true},
		{name: "bad container value", hostItems: hostReclaimItems(23), containerItems: []bpf.MapItem{{Key: item.Key, Value: []byte{1}}}, want: map[string]float64{"directstall": 23}, wantErr: true},
		{name: "host map failure", hostErr: failure, containerItems: []bpf.MapItem{item}, want: map[string]float64{"container_directstall": 7}, wantErr: true},
		{name: "missing host row", containerItems: []bpf.MapItem{item}, want: map[string]float64{"container_directstall": 7}, wantErr: true},
		{name: "both fail", hostErr: failure, discoveryErr: failure, want: map[string]float64{}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			obj := &memcgReclaimBPF{hostItems: tt.hostItems, containerItems: tt.containerItems, hostErr: tt.hostErr, containerErr: tt.containerErr}
			c := memoryCgroupReclaim{}
			data, err := c.update(obj, func() (map[string]*pod.Container, error) {
				if tt.noContainers {
					return nil, nil
				}
				return map[string]*pod.Container{"test": container}, tt.discoveryErr
			})
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, want error %v", err, tt.wantErr)
			}
			if (tt.hostErr != nil || tt.containerErr != nil || tt.discoveryErr != nil) && !errors.Is(err, failure) {
				t.Fatalf("lost failure: %v", err)
			}
			assertVMStatMetrics(t, data, tt.want)
			for _, metric := range data {
				if metric.Name() == "directstall" {
					if _, ok := metric.Labels()["container_name"]; ok {
						t.Fatal("host metric has container labels")
					}
				}
			}
		})
	}
}

func BenchmarkHostMemcgReclaimCount(b *testing.B) {
	for _, cpus := range []int{8, 128, 1024} {
		b.Run(fmt.Sprintf("cpus=%d", cpus), func(b *testing.B) {
			counts := make([]uint64, cpus)
			for i := range counts {
				counts[i] = 1
			}
			items := hostReclaimItems(counts...)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				count, err := hostMemcgReclaimCount(items)
				if err != nil || count != uint64(cpus) {
					b.Fatalf("count = %d, error = %v", count, err)
				}
			}
		})
	}
}

func TestMemoryReclaimCountLayout(t *testing.T) {
	var count memoryBpfStruct
	if size := binary.Size(count); size != 8 {
		t.Fatalf("count layout = %d bytes, want 8", size)
	}
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint64(raw, 42)
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &count); err != nil {
		t.Fatal(err)
	}
	if count.DirectstallCount != 42 {
		t.Fatalf("count = %d, want 42", count.DirectstallCount)
	}
}

func TestMemcgReclaimBPFLayout(t *testing.T) {
	object := os.Getenv("HUATUO_MEMCG_RECLAIM_BPF_OBJECT")
	if object == "" {
		t.Skip("set HUATUO_MEMCG_RECLAIM_BPF_OBJECT to a freshly built object")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	m := spec.Maps["memory_cgroup_allocpages_stall"]
	if m == nil || m.Type != ebpf.Hash || m.KeySize != 8 ||
		m.ValueSize != uint32(binary.Size(memoryBpfStruct{})) || m.MaxEntries != 10240 {
		t.Fatalf("unexpected count map: %+v", m)
	}
	if spec.Maps["memory_cgroup_reclaim_start"] != nil {
		t.Fatal("count-only collection must not retain a timing map")
	}
	host := spec.Maps["memory_host_directstall"]
	if host == nil || host.Type != ebpf.PerCPUArray || host.KeySize != 4 || host.ValueSize != 8 || host.MaxEntries != 1 {
		t.Fatalf("unexpected host count map: %+v", host)
	}
	for _, name := range []string{
		"tracepoint_vmscan_mm_vmscan_memcg_reclaim_begin",
		"kprobe_mem_cgroup_css_released",
	} {
		if spec.Programs[name] == nil {
			t.Fatalf("missing BPF program %s", name)
		}
	}
	if len(spec.Programs) != 2 {
		t.Fatalf("got %d BPF programs, want 2", len(spec.Programs))
	}
	if os.Getenv("HUATUO_BPF_INTEGRATION") != "1" {
		return
	}
	raw, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := bpf.LoadBPFFromBytes("memory_reclaim", raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer obj.Close()
	if err := obj.Attach(); err != nil {
		t.Fatal(err)
	}
	c := memoryCgroupReclaim{}
	data, err := c.update(obj, func() (map[string]*pod.Container, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 1 || data[0].Name() != "directstall" {
		t.Fatalf("expected one host directstall metric, got %v", data)
	}
}
