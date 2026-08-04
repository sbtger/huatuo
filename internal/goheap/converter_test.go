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

package goheap

import (
	"math"
	"testing"
	"time"

	"huatuo-bamai/internal/profiler"
)

type mapSymbolizer map[uint64]string

func (s mapSymbolizer) Resolve(pc uint64) string { return s[pc] }

func TestConvertBuildsInuseProfiles(t *testing.T) {
	t.Parallel()
	bucket := Bucket{
		StackDepth: 3,
		Stack:      [MaxStackDepth]uint64{0x10, 0x20, 0x30},
		Record: MemRecord{
			Active: MemRecordCycle{Allocs: 10, Frees: 4, AllocBytes: 1000, FreeBytes: 400},
			Future: [3]MemRecordCycle{{Allocs: 2, Frees: 1, AllocBytes: 200, FreeBytes: 100}},
		},
	}
	profiles, err := Convert(Target{GoVersion: "go1.24.0"}, []Bucket{bucket}, time.Unix(123, 0), mapSymbolizer{
		0x10: "leaf", 0x20: "middle", 0x30: "root",
	})
	if err != nil {
		t.Fatal(err)
	}
	if profiles.InuseSpace.ProfileType != profiler.ProfileTypeMemInuseSpace {
		t.Fatalf("space profile type = %q", profiles.InuseSpace.ProfileType)
	}
	if profiles.InuseObjects.ProfileType != profiler.ProfileTypeMemInuseObjects {
		t.Fatalf("object profile type = %q", profiles.InuseObjects.ProfileType)
	}
	if got := profiles.InuseSpace.Profile.Sample[0].Value[0]; got != 700 {
		t.Fatalf("inuse bytes = %d, want 700", got)
	}
	if got := profiles.InuseObjects.Profile.Sample[0].Value[0]; got != 7 {
		t.Fatalf("inuse objects = %d, want 7", got)
	}
	if profiles.Stats.EmittedBuckets != 1 {
		t.Fatalf("stats = %+v", profiles.Stats)
	}
	assertProfileStack(t, profiles.InuseSpace, []string{"leaf", "middle", "root"})
}

func TestConvertHandlesPartialAndInconsistentBuckets(t *testing.T) {
	t.Parallel()
	buckets := []Bucket{
		{StackDepth: MaxStackDepth + 1},
		{StackDepth: 0},
		{
			StackDepth: 1,
			Stack:      [MaxStackDepth]uint64{0x42},
			Record: MemRecord{Active: MemRecordCycle{
				Allocs: 1, Frees: 2, AllocBytes: 1, FreeBytes: 2,
			}},
		},
		{
			StackDepth: 1,
			Stack:      [MaxStackDepth]uint64{0x43},
			Record: MemRecord{
				Active: MemRecordCycle{Allocs: math.MaxUint64, AllocBytes: math.MaxUint64},
				Future: [3]MemRecordCycle{{Allocs: 1, AllocBytes: 1}},
			},
		},
	}
	profiles, err := Convert(Target{GoVersion: "go1.22.2"}, buckets, time.Time{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if profiles.Stats.InvalidStackDepths != 1 || profiles.Stats.CounterUnderflows != 2 ||
		profiles.Stats.CounterOverflows != 2 || profiles.Stats.ProfileValueClamps != 2 ||
		profiles.Stats.EmittedBuckets != 1 {
		t.Fatalf("stats = %+v", profiles.Stats)
	}
	if got := profiles.InuseSpace.Profile.Sample[0].Value[0]; got != math.MaxInt64 {
		t.Fatalf("saturated bytes = %d", got)
	}
}

func TestConvertRejectsUnsupportedRuntime(t *testing.T) {
	t.Parallel()
	if _, err := Convert(Target{GoVersion: "go1.25"}, nil, time.Time{}, nil); err == nil {
		t.Fatal("Convert unexpectedly accepted an unknown runtime layout")
	}
}

func assertProfileStack(t *testing.T, data *profiler.ProfileData, want []string) {
	t.Helper()
	sample := data.Profile.Sample[0]
	if len(sample.LocationId) != len(want) {
		t.Fatalf("location count = %d, want %d", len(sample.LocationId), len(want))
	}
	functions := make(map[uint64]int64, len(data.Profile.Function))
	for _, function := range data.Profile.Function {
		functions[function.Id] = function.Name
	}
	locations := make(map[uint64]int64, len(data.Profile.Location))
	for _, location := range data.Profile.Location {
		locations[location.Id] = functions[location.Line[0].FunctionId]
	}
	for i, id := range sample.LocationId {
		name := data.Profile.StringTable[locations[id]]
		if name != want[i] {
			t.Fatalf("frame %d = %q, want %q", i, name, want[i])
		}
	}
}
