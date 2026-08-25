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

package memsnap

import (
	"encoding/json"
	"runtime"
	"strings"
	"testing"
	"unsafe"
)

func TestSnapshotJSON(t *testing.T) {
	snapshot := &Snapshot{
		RuntimeVersion: "go1.24", Status: StatusComplete, DurationMS: 2,
		Entries: []Entry{{
			Kind: "allocation_site", Name: "main.allocate", Bytes: 8192,
			Objects: 8, Stack: []string{"main.allocate", "main.main"},
		}},
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(raw)
	for _, required := range []string{
		`"status":"complete"`, `"duration_ms":2`, `"entries":`,
		`"bytes":8192`, `"objects":8`,
	} {
		if !strings.Contains(encoded, required) {
			t.Fatalf("snapshot does not contain %s: %s", required, encoded)
		}
	}
}

func TestLimitOutputEntries(t *testing.T) {
	entries := []Entry{
		{Name: "first", Bytes: 300},
		{Name: "second", Bytes: 200},
		{Name: "third", Bytes: 100},
	}
	snapshot := &Snapshot{Status: StatusComplete, Entries: entries}
	if err := LimitOutput(snapshot, 2); err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != StatusComplete || snapshot.Reason != "" ||
		!snapshot.OutputTruncated || len(snapshot.Entries) != 2 ||
		snapshot.Entries[1].Name != "second" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
	entries[0].Name = "mutated"
	if snapshot.Entries[0].Name != "first" {
		t.Fatal("top-K truncation retained the dropped entries backing array")
	}
}

func TestLimitOutputBoundsStringsAndEncodedBytes(t *testing.T) {
	large := strings.Repeat("x", MaxSnapshotBytes)
	snapshot := &Snapshot{
		RuntimeVersion: large,
		Status:         StatusPartial,
		Reason:         large,
		Entries: []Entry{
			{Kind: large, Name: large, Stack: []string{large}},
			{Kind: large, Name: large, Stack: []string{large}},
		},
	}
	if err := LimitOutput(snapshot, 2); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > MaxSnapshotBytes {
		t.Fatalf("encoded snapshot bytes = %d, want <= %d", len(raw), MaxSnapshotBytes)
	}
	if !snapshot.OutputTruncated || len(snapshot.RuntimeVersion) > maxRuntimeVersionBytes ||
		len(snapshot.Reason) > maxReasonBytes || len(snapshot.Entries[0].Name) > maxEntryNameBytes ||
		len(snapshot.Entries[0].Stack[0]) > maxStackFrameBytes {
		t.Fatalf("snapshot was not bounded: %+v", snapshot)
	}
}

func TestLimitOutputRejectsUnboundedTopK(t *testing.T) {
	if err := LimitOutput(&Snapshot{}, MaxTopK+1); err == nil {
		t.Fatal("LimitOutput() error = nil, want top-K bound error")
	}
}

func TestLimitOutputDropsEntriesToEncodedLimit(t *testing.T) {
	frame := strings.Repeat("x", maxStackFrameBytes)
	stack := make([]string, maxStackFrames)
	for index := range stack {
		stack[index] = frame
	}
	entries := make([]Entry, MaxTopK)
	for index := range entries {
		entries[index] = Entry{Name: "entry", Stack: append([]string(nil), stack...)}
	}
	snapshot := &Snapshot{Status: StatusComplete, Entries: entries}
	if err := LimitOutput(snapshot, MaxTopK); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > MaxSnapshotBytes || len(snapshot.Entries) >= MaxTopK ||
		!snapshot.OutputTruncated {
		t.Fatalf("bounded snapshot bytes=%d entries=%d truncated=%v",
			len(raw), len(snapshot.Entries), snapshot.OutputTruncated)
	}
	probe := *snapshot
	probe.Entries = entries[:len(snapshot.Entries)+1]
	probeRaw, err := json.Marshal(&probe)
	if err != nil {
		t.Fatal(err)
	}
	if len(probeRaw) <= MaxSnapshotBytes {
		t.Fatalf("one more entry still fits: bytes=%d entries=%d",
			len(probeRaw), len(probe.Entries))
	}
	entries[0].Name = "mutated"
	if snapshot.Entries[0].Name != "entry" {
		t.Fatal("encoded-size truncation retained the dropped entries backing array")
	}
}

func TestLimitOutputReleasesTruncatedStackBackingArray(t *testing.T) {
	stack := make([]string, maxStackFrames+1)
	for index := range stack {
		stack[index] = "frame"
	}
	snapshot := &Snapshot{Status: StatusComplete, Entries: []Entry{{
		Name: "entry", Stack: stack,
	}}}
	if err := LimitOutput(snapshot, 1); err != nil {
		t.Fatal(err)
	}
	stack[0] = "mutated"
	if snapshot.Entries[0].Stack[0] != "frame" {
		t.Fatal("stack truncation retained the dropped frames backing array")
	}
}

func TestLimitOutputDetachesRetainedProviderStorage(t *testing.T) {
	runtimeVersion := strings.Repeat("r", maxRuntimeVersionBytes+1)
	reason := strings.Repeat("q", maxReasonBytes+1)
	kind := strings.Repeat("k", maxEntryKindBytes+1)
	name := strings.Repeat("n", maxEntryNameBytes+1)
	frame := strings.Repeat("f", maxStackFrameBytes+1)
	stackBacking := make([]string, maxStackFrames)
	stackBacking[0] = frame
	entryBacking := make([]Entry, MaxTopK)
	entryBacking[0] = Entry{
		Kind: kind, Name: name, Stack: stackBacking[:1],
	}
	snapshot := &Snapshot{
		RuntimeVersion: runtimeVersion,
		Status:         StatusPartial,
		Reason:         reason,
		Entries:        entryBacking[:1],
	}

	if err := LimitOutput(snapshot, 1); err != nil {
		t.Fatal(err)
	}
	stringsToCheck := []struct {
		name   string
		source string
		got    string
	}{
		{name: "runtime version", source: runtimeVersion, got: snapshot.RuntimeVersion},
		{name: "reason", source: reason, got: snapshot.Reason},
		{name: "entry kind", source: kind, got: snapshot.Entries[0].Kind},
		{name: "entry name", source: name, got: snapshot.Entries[0].Name},
		{name: "stack frame", source: frame, got: snapshot.Entries[0].Stack[0]},
	}
	for _, check := range stringsToCheck {
		if unsafe.StringData(check.got) == unsafe.StringData(check.source) {
			t.Errorf("%s retained provider string storage", check.name)
		}
	}

	entryBacking[0].Bytes = 1
	stackBacking[0] = "mutated"
	if snapshot.Entries[0].Bytes != 0 || snapshot.Entries[0].Stack[0] == "mutated" {
		t.Fatal("snapshot retained provider entry or stack backing storage")
	}
}

func TestLimitOutputWorstCaseAllocationBound(t *testing.T) {
	frame := strings.Repeat("x", maxStackFrameBytes)
	stack := make([]string, maxStackFrames)
	for index := range stack {
		stack[index] = frame
	}
	entries := make([]Entry, MaxTopK)
	for index := range entries {
		entries[index] = Entry{Name: "entry", Stack: append([]string(nil), stack...)}
	}
	snapshot := &Snapshot{Status: StatusComplete, Entries: entries}

	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if err := LimitOutput(snapshot, MaxTopK); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(snapshot)

	// Leave headroom for encoding/json implementation changes while preventing
	// a regression to repeatedly marshaling the full remaining snapshot.
	const maxAllocatedBytes = 64 << 20
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > maxAllocatedBytes {
		t.Fatalf("LimitOutput allocated %d bytes, want <= %d", allocated,
			maxAllocatedBytes)
	}
}

func TestEntriesFromObjects(t *testing.T) {
	entries := EntriesFromObjects([]ObjectAggregate{{
		TypeName: "service.Payload", Count: 12, ShallowBytes: 384,
	}})
	if len(entries) != 1 || entries[0].Kind != "object_type" ||
		entries[0].Bytes != 384 || entries[0].Objects != 12 {
		t.Fatalf("entries=%+v", entries)
	}
}
