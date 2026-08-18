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
	"strings"
	"testing"
	"time"
)

func validManifest() Manifest {
	started := time.Unix(100, 0).UTC()
	return Manifest{
		SchemaVersion:    SchemaVersion,
		SnapshotID:       "snap-1",
		OOMRequestCookie: 7,
		Identity:         ProcessIdentity{TGID: 42, StartTimeTicks: 99, BootID: "boot"},
		Language:         LanguageGo,
		Scope:            ScopeRuntimeManagedHeap,
		Mode:             ModeFast,
		Trigger:          TriggerOOMVictim,
		Status:           StatusComplete,
		Coverage: Coverage{
			Consistency:   "runtime_snapshot",
			SizeSemantics: "sampled_estimate",
			KnownGaps:     []string{"native memory"},
		},
		CaptureStartedWallTime:      started,
		CaptureCompletedWallTime:    started.Add(time.Millisecond),
		CaptureStartedMonotonicNS:   100,
		CaptureCompletedMonotonicNS: 200,
	}
}

func TestManifestValidate(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Manifest)
		want   string
	}{
		{name: "valid"},
		{name: "complete truncated", mutate: func(m *Manifest) {
			m.Truncated = true
			m.TruncationReasons = []string{"limit"}
		}, want: "complete snapshot cannot be truncated"},
		{name: "partial without truncation", mutate: func(m *Manifest) {
			m.Status = StatusPartialDeadline
		}, want: "partial snapshot must be marked truncated"},
		{name: "missing coverage", mutate: func(m *Manifest) {
			m.Coverage.KnownGaps = nil
		}, want: "known gaps"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			manifest := validManifest()
			if test.mutate != nil {
				test.mutate(&manifest)
			}
			err := manifest.Validate()
			if test.want == "" && err != nil {
				t.Fatalf("Validate() error=%v", err)
			}
			if test.want != "" && (err == nil || !strings.Contains(err.Error(), test.want)) {
				t.Fatalf("Validate() error=%v, want %q", err, test.want)
			}
		})
	}
}

func TestManifestJSONFieldNames(t *testing.T) {
	raw, err := json.Marshal(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{
		`"schema_version":2`, `"scope":"runtime_managed_heap"`,
		`"mode":"fast"`, `"tgid":42`, `"starttime_ticks":99`,
		`"capture_started_monotonic_ns":100`, `"entry_count":0`,
	} {
		if !strings.Contains(string(raw), field) {
			t.Errorf("manifest JSON %s does not contain %s", raw, field)
		}
	}
	for _, legacy := range []string{`"object_count"`, `"stack_count"`} {
		if strings.Contains(string(raw), legacy) {
			t.Errorf("manifest JSON %s contains legacy field %s", raw, legacy)
		}
	}
}

func TestRuntimePayloadUnifiesObjectsAndAllocationSitesWithoutDataLoss(t *testing.T) {
	result := &Result{
		Manifest: validManifest(),
		Objects: []ObjectAggregate{{
			TypeName: "service.Payload", RawTypeName: "Lservice/Payload;",
			ModuleSuffix: "app", Count: 3, ShallowBytes: 96, AverageBytes: 32,
			LengthBuckets: []ShapeBucket{{Name: "1-8", Count: 2}},
			Fields: []FieldShape{{
				Name: "data", ReferencedType: "bytes",
				ReferenceCount: 3, UniqueReferencedObjects: 2,
				ReferencedShallowBytes: 64, AverageReferencedBytes: 32,
			}},
		}},
		Allocations: []AllocationSample{{
			Stack:        []string{"main.(*Cache).Put", "main.serve"},
			SampledBytes: 4096, SampledCount: 4,
			InuseBytes: 8192, InuseObjects: 8,
		}},
	}
	result.Manifest.GateRelease = "timeout_or_ack_missed"
	payload := RuntimePayloadFromResult(result)
	if payload == nil || len(payload.Entries) != 2 {
		t.Fatalf("payload=%+v", payload)
	}
	if payload.CaptureDurationMilliseconds != 1 || payload.EntryCount != 2 {
		t.Fatalf("duration_ms=%d entry_count=%d", payload.CaptureDurationMilliseconds,
			payload.EntryCount)
	}
	if payload.GateRelease != "timeout_or_ack_missed" {
		t.Fatalf("gate_release=%q", payload.GateRelease)
	}
	object := payload.Entries[0]
	if object.Kind != EntryKindObjectType || object.Name != "service.Payload" ||
		object.RawTypeName != "Lservice/Payload;" || object.ModuleSuffix != "app" ||
		object.InuseBytes != 96 || object.InuseObjects != 3 ||
		len(object.LengthBuckets) != 1 || len(object.Fields) != 1 {
		t.Fatalf("object entry=%+v", object)
	}
	allocation := payload.Entries[1]
	if allocation.Kind != EntryKindAllocationSite ||
		allocation.Name != "main.(*Cache).Put" || allocation.InuseBytes != 8192 ||
		allocation.InuseObjects != 8 || allocation.SampledBytes != 4096 ||
		allocation.SampledCount != 4 || len(allocation.AllocationStack) != 2 {
		t.Fatalf("allocation entry=%+v", allocation)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(raw)
	for _, required := range []string{
		`"schema_version":2`, `"status":"COMPLETE"`,
		`"gate_release":"timeout_or_ack_missed"`,
		`"capture_duration_ms":1`, `"entry_count":2`, `"coverage":`,
	} {
		if !strings.Contains(encoded, required) {
			t.Fatalf("compact payload does not contain %s: %s", required, encoded)
		}
	}
	for _, forbidden := range []string{
		`"objects":`, `"allocations":`, `"snapshot_id":`,
		`"oom_request_cookie":`, `"oom_monotonic_ns":`,
		`"gate_deadline_monotonic_ns":`, `"gate_ack_monotonic_ns":`,
		`"identity":`, `"language":`, `"scope":`, `"mode":`,
		`"trigger":`, `"capture_started_wall_time":`,
		`"capture_completed_wall_time":`,
		`"capture_started_monotonic_ns":`,
		`"capture_completed_monotonic_ns":`, `"expires_at":`,
	} {
		if strings.Contains(encoded, forbidden) {
			t.Fatalf("compact payload contains internal field %s: %s", forbidden, encoded)
		}
	}
}

func TestRequestValidate(t *testing.T) {
	now := time.Unix(100, 0)
	request := Request{
		SnapshotID: "snap-1", OOMRequestCookie: 1,
		Identity: ProcessIdentity{TGID: 1, StartTimeTicks: 2, BootID: "boot"},
		Trigger:  TriggerOOMVictim, GateDeadline: now.Add(time.Second),
		MaxOutputBytes: 1024, MaxObjects: 10, MaxStacks: 10, MaxStackDepth: 10,
	}
	if err := request.Validate(now); err != nil {
		t.Fatalf("Validate() error=%v", err)
	}
	request.GateDeadline = now
	if err := request.Validate(now); err == nil {
		t.Fatal("expired request accepted")
	}
}
