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

package java

import (
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"huatuo-bamai/internal/memsnap"
)

func TestWeightedWindows(t *testing.T) {
	const mib = uint64(1 << 20)
	regions := []region{
		{bottom: 0x10000000, top: 0x10000000 + mib},
		{bottom: 0x20000000, top: 0x20000000 + 3*mib},
		{bottom: 0x30000000, top: 0x30000000 + 6*mib},
	}
	windows := planWindows(regions, 0x1234, 4*mib, windowBytes)
	if len(windows) != int(4*mib/windowBytes) {
		t.Fatalf("windows=%d", len(windows))
	}
	counts := make(map[uint64]int)
	seen := make(map[uint64]struct{}, len(windows))
	for _, sample := range windows {
		if _, exists := seen[sample.start]; exists {
			t.Fatalf("duplicate window at %#x", sample.start)
		}
		seen[sample.start] = struct{}{}
		regionBottom := uint64(0)
		for _, region := range regions[:3] {
			if sample.start >= region.bottom &&
				sample.start+sample.size <= region.top {
				regionBottom = region.bottom
				break
			}
		}
		if regionBottom == 0 || sample.start&(defaultObjectAlignment-1) != 0 {
			t.Fatalf("invalid window=%+v", sample)
		}
		counts[regionBottom]++
	}
	want := []int{
		len(windows) / 10, len(windows) * 3 / 10,
		len(windows) * 6 / 10,
	}
	for index, region := range regions[:3] {
		delta := counts[region.bottom] - want[index]
		if delta < 0 {
			delta = -delta
		}
		if delta > 2 {
			t.Fatalf("Region %d windows=%d, want near %d", index,
				counts[region.bottom], want[index])
		}
	}
	repeat := planWindows(regions, 0x1234, 4*mib, windowBytes)
	rotated := planWindows(regions, 0x5678, 4*mib, windowBytes)
	different := false
	for index := range windows {
		if repeat[index].start != windows[index].start ||
			repeat[index].size != windows[index].size {
			t.Fatalf("same seed changed window %d", index)
		}
		if rotated[index].start != windows[index].start {
			different = true
		}
	}
	if !different {
		t.Fatal("different seed produced the same weighted windows")
	}
}

func TestFullBudgetWindows(t *testing.T) {
	regions := []region{
		{bottom: 0x10000000, top: 0x10000000 + 2*windowBytes + 17},
		{bottom: 0x20000000, top: 0x20000000 + windowBytes},
		{bottom: 0x28000000, top: 0x28000000 + 19},
	}
	ordinaryUsed := regions[0].top - regions[0].bottom +
		regions[1].top - regions[1].bottom +
		regions[2].top - regions[2].bottom
	windows := planWindows(regions, 0x1234, ordinaryUsed, windowBytes)
	want := map[uint64]uint64{
		regions[0].bottom:                 windowBytes,
		regions[0].bottom + windowBytes:   windowBytes,
		regions[0].bottom + 2*windowBytes: 17,
		regions[1].bottom:                 windowBytes,
		regions[2].bottom:                 19,
	}
	if len(windows) != len(want) {
		t.Fatalf("windows=%d, want %d", len(windows), len(want))
	}
	for _, sample := range windows {
		size, exists := want[sample.start]
		if !exists {
			t.Fatalf("unexpected or duplicate window=%+v", sample)
		}
		if sample.size != size {
			t.Fatalf("window %#x size=%d, want %d", sample.start, sample.size, size)
		}
		delete(want, sample.start)
	}
	if len(want) != 0 {
		t.Fatalf("missing windows=%v", want)
	}
}

func TestTailWindowWeight(t *testing.T) {
	regions := []region{
		{bottom: 0x10000000, top: 0x10000000 + windowBytes},
		{bottom: 0x20000000, top: 0x20000000 + 8},
	}
	tailSelections := 0
	for seed := uint64(1); seed <= 4096; seed++ {
		windows := planWindows(regions, seed, windowBytes, windowBytes)
		if len(windows) != 1 {
			t.Fatalf("seed=%d windows=%d, want 1", seed, len(windows))
		}
		if windows[0].start == regions[1].bottom {
			tailSelections++
		}
	}
	if tailSelections == 0 || tailSelections > 64 {
		t.Fatalf("8-byte tail selected %d/4096 times", tailSelections)
	}
}

func TestHumongousRegions(t *testing.T) {
	const capacity = uint64(1 << 20)
	regions := []region{
		{bottom: 0x10000000, top: 0x10000000 + capacity, capacity: capacity, tag: 2, hasTag: true},
		{bottom: 0x20000000, top: 0x20000000 + capacity/2, capacity: capacity, tag: 8, hasTag: true},
		{bottom: 0x30000000, top: 0x30000000 + capacity, capacity: capacity, tag: 4, hasTag: true},
		{bottom: 0x30100000, top: 0x30100000 + capacity, capacity: capacity, tag: 5, hasTag: true},
	}
	heap, err := groupRegions(regions, g1SamplingTestMetadata())
	if err != nil {
		t.Fatal(err)
	}
	if heap.ordinaryUsed != capacity+capacity/2 {
		t.Fatalf("ordinary bytes=%d", heap.ordinaryUsed)
	}
	if len(heap.ordinary) != 2 || len(heap.humongous) != 1 ||
		len(heap.humongous[0].regions) != 2 {
		t.Fatalf("grouped regions=%+v", heap)
	}
	if got := humongousGroupBytes(heap.humongous[0]); got != 2*capacity {
		t.Fatalf("humongous bytes=%d, want %d", got, 2*capacity)
	}
	if got := humongousGroupBytes(regionGroup{}); got != 0 {
		t.Fatalf("invalid group bytes=%d, want 0", got)
	}
}

func TestJDK8SpanningRegions(t *testing.T) {
	java25 := &vmMeta{image: &vmImage{
		javaVersion: "25.0.1", vmRelease: "25.0.1+8-LTS",
	}}
	if jdk8SpanningRegions(java25) {
		t.Fatal("Java 25 release was mistaken for HotSpot 8 VM release 25")
	}
	java25WithoutReleaseFile := &vmMeta{image: &vmImage{
		vmRelease: "25.0.1+8-LTS",
	}}
	if jdk8SpanningRegions(java25WithoutReleaseFile) {
		t.Fatal("Java 25 VM release was mistaken for the legacy JDK 8 format")
	}
	hotSpot8 := &vmMeta{image: &vmImage{
		javaVersion: "1.8.0_462", vmRelease: "25.462-b08",
	}}
	if !jdk8SpanningRegions(hotSpot8) {
		t.Fatal("HotSpot 8 VM release was not recognized")
	}
}

func TestObjectAlignment(t *testing.T) {
	metadata := &vmMeta{
		objectAlignment: 16,
		constants: map[string]int64{
			"Klass::_lh_instance_slow_path_bit": 1,
		},
	}
	size, err := objectSize(make([]byte, 16),
		&klass{name: "service/Payload", layoutHelper: 24}, metadata, 0, 12)
	if err != nil || size != 32 {
		t.Fatalf("size=%d error=%v, want 32", size, err)
	}
}

func TestCrossWindowObject(t *testing.T) {
	const (
		klassAddress = uint64(0x2000)
		klassBase    = uint64(0x1000)
	)
	raw := make([]byte, 512)
	binary.LittleEndian.PutUint64(raw[0:8], 1)
	binary.LittleEndian.PutUint32(raw[8:12], uint32(klassAddress-klassBase))
	classes := map[uint64]*klass{
		klassAddress: {name: "service/LargePayload", layoutHelper: 128 << 10},
	}
	observations := make(map[uint64]classSample)
	scanKnownWindow(sampleWindow{
		start: 0x100000, regionTop: 0x100000 + 128<<10, raw: raw,
	}, classes,
		ptrEncoding{compressedKlass: true, klassBase: klassBase},
		&vmMeta{objectAlignment: defaultObjectAlignment}, 0, observations)
	if observations[klassAddress].count != 1 ||
		observations[klassAddress].bytes != 128<<10 {
		t.Fatalf("observation=%+v", observations[klassAddress])
	}
}

func TestObjectPastRegion(t *testing.T) {
	const (
		klassAddress = uint64(0x2000)
		klassBase    = uint64(0x1000)
		windowStart  = uint64(0x100000)
	)
	raw := make([]byte, 16)
	binary.LittleEndian.PutUint64(raw[0:8], 1)
	binary.LittleEndian.PutUint32(raw[8:12], uint32(klassAddress-klassBase))
	observations := make(map[uint64]classSample)
	scanKnownWindow(sampleWindow{
		start: windowStart, regionTop: windowStart + 64<<10, raw: raw,
	}, map[uint64]*klass{
		klassAddress: {name: "service/TooLarge", layoutHelper: 128 << 10},
	}, ptrEncoding{compressedKlass: true, klassBase: klassBase},
		&vmMeta{objectAlignment: defaultObjectAlignment}, 0, observations)
	if len(observations) != 0 {
		t.Fatalf("out-of-Region object was counted: %+v", observations)
	}
}

func TestLockedObjects(t *testing.T) {
	const (
		klassAddress = uint64(0x2000)
		klassBase    = uint64(0x1000)
	)
	classes := map[uint64]*klass{
		klassAddress: {name: "service/Locked", layoutHelper: 16},
	}
	encoding := ptrEncoding{compressedKlass: true, klassBase: klassBase}
	metadata := &vmMeta{objectAlignment: defaultObjectAlignment}
	for _, mark := range []uint64{0, 1, 2, 3} {
		raw := make([]byte, 16)
		binary.LittleEndian.PutUint64(raw[0:8], mark)
		binary.LittleEndian.PutUint32(raw[8:12],
			uint32(klassAddress-klassBase))
		observations := make(map[uint64]classSample)
		scanKnownWindow(sampleWindow{
			start: 0x100000, regionTop: 0x100010, raw: raw,
		}, classes, encoding, metadata, 0,
			observations)
		want := uint64(1)
		if mark == 3 {
			want = 0
		}
		if observations[klassAddress].count != want {
			t.Fatalf("mark=%d observation=%+v, want %d",
				mark, observations[klassAddress], want)
		}
	}
}

func TestScanCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reason := scanWindows(processMemory{pid: -1, ctx: ctx},
		[]region{{bottom: 0x1000, top: 0x2000}}, 1, windowBytes,
		windowBytes, func([]sampleWindow) bool { return true })
	if reason == "" || !strings.Contains(reason, context.Canceled.Error()) {
		t.Fatalf("stop reason=%q", reason)
	}
}

func TestMirrorSizeOffsetIsOptional(t *testing.T) {
	offset, err := mirrorSizeOffset(processMemory{}, &vmMeta{
		structs: make(map[string]vmStruct),
	})
	if err != nil || offset != 0 {
		t.Fatalf("offset=%d error=%v", offset, err)
	}
}

func TestEstimateAggregates(t *testing.T) {
	const classAddress = uint64(0xabc)
	statistics := sampleStats{
		ordinarySampledBytes: 200,
		ordinary: map[uint64]classSample{
			classAddress: {count: 10, bytes: 100},
		},
		humongous: map[uint64]classSample{
			classAddress: {count: 1, bytes: 50},
		},
	}
	aggregates := estimateAggregates(map[uint64]*klass{
		classAddress: {name: "service/Payload"},
	}, statistics, 400)
	got := aggregates["service.Payload"]
	if got.ShallowBytes != 250 || got.Count != 21 {
		t.Fatalf("aggregate=%+v", got)
	}
	unknown := estimateAggregates(nil, sampleStats{
		ordinarySampledBytes: 1,
		ordinary: map[uint64]classSample{
			0xabc: {count: 1, bytes: 16},
		},
	}, 1)
	if len(unknown) != 0 {
		t.Fatalf("unknown Klass produced aggregates=%+v", unknown)
	}
}

func TestObjectSort(t *testing.T) {
	objects := []memsnap.ObjectAggregate{
		{TypeName: "z.Type", Count: 4, ShallowBytes: 100},
		{TypeName: "a.Type", Count: 4, ShallowBytes: 100},
		{TypeName: "more.Objects", Count: 8, ShallowBytes: 100},
		{TypeName: "largest", Count: 1, ShallowBytes: 200},
	}
	sortObjects(objects)
	want := []string{"largest", "more.Objects", "a.Type", "z.Type"}
	for index := range want {
		if objects[index].TypeName != want[index] {
			t.Fatalf("objects=%+v", objects)
		}
	}
}

func TestVMStructLookup(t *testing.T) {
	metadata := &vmMeta{
		structs: map[string]vmStruct{
			"old":          {typeString: "address", offset: 8},
			"Base::_field": {typeString: "address", offset: 16},
		},
		types: map[string]vmType{"Derived": {superclass: "Base"}},
	}
	if got := firstStruct(metadata, "new", "old"); got.offset != 8 {
		t.Fatalf("alias offset=%d, want 8", got.offset)
	}
	if got := inheritedStruct(metadata, "Derived", "_field"); got.offset != 16 {
		t.Fatalf("inherited offset=%d, want 16", got.offset)
	}
}

func g1SamplingTestMetadata() *vmMeta {
	return &vmMeta{constants: map[string]int64{
		"G1HeapRegionType::FreeTag":               0,
		"G1HeapRegionType::EdenTag":               2,
		"G1HeapRegionType::SurvTag":               3,
		"G1HeapRegionType::StartsHumongousTag":    4,
		"G1HeapRegionType::ContinuesHumongousTag": 5,
		"G1HeapRegionType::YoungMask":             2,
		"G1HeapRegionType::HumongousMask":         4,
		"G1HeapRegionType::OldMask":               8,
	}}
}

func TestNormalizeClassName(t *testing.T) {
	tests := map[string]string{
		"[B": "byte[]", "[[Ljava/lang/String;": "java.lang.String[][]",
		"service/CacheEntry": "service.CacheEntry",
	}
	for input, want := range tests {
		if got := normalizeClassName(input); got != want {
			t.Errorf("normalizeClassName(%q)=%q, want %q", input, got, want)
		}
	}
}

func TestReadBatchBound(t *testing.T) {
	end := readBatchEnd(0, 1000)
	if end != maxReadIOVs {
		t.Fatalf("batch end=%d, want %d", end, maxReadIOVs)
	}
}
