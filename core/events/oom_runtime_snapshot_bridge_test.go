// Copyright 2026 The HuaTuo Authors
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

package events

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"huatuo-bamai/internal/memsnap"
)

func TestOOMRuntimeSnapshotBridgeHandlesEitherArrivalOrder(t *testing.T) {
	for _, publishFirst := range []bool{false, true} {
		bridge := newOOMRuntimeSnapshotBridge(time.Second)
		key := oomRuntimeSnapshotKey{victimTGID: 42, oomMonotonicNS: 99}
		want := runtimeSnapshotStatus(key, memsnap.StatusComplete, "captured")
		if publishFirst {
			bridge.publish(key, want)
		}
		if !publishFirst {
			go bridge.publish(key, want)
		}
		got, ok := bridge.wait(context.Background(), key, time.Second)
		if !ok || got != want {
			t.Fatalf("publishFirst=%v got=%p ok=%v", publishFirst, got, ok)
		}
	}
}

func TestOOMRuntimeSnapshotBridgeSeparatesReusedPIDByEventTime(t *testing.T) {
	bridge := newOOMRuntimeSnapshotBridge(time.Second)
	firstKey := oomRuntimeSnapshotKey{victimTGID: 42, oomMonotonicNS: 100}
	secondKey := oomRuntimeSnapshotKey{victimTGID: 42, oomMonotonicNS: 200}
	first := runtimeSnapshotStatus(firstKey, memsnap.StatusComplete, "first")
	second := runtimeSnapshotStatus(secondKey, memsnap.StatusPartialDeadline, "second")
	bridge.publish(secondKey, second)
	bridge.publish(firstKey, first)

	gotFirst, ok := bridge.wait(context.Background(), firstKey, 0)
	if !ok || gotFirst != first {
		t.Fatalf("first event got=%p ok=%v", gotFirst, ok)
	}
	gotSecond, ok := bridge.wait(context.Background(), secondKey, 0)
	if !ok || gotSecond != second {
		t.Fatalf("second event got=%p ok=%v", gotSecond, ok)
	}
}

func TestOOMRuntimeSnapshotGateTimeoutRecordsRelease(t *testing.T) {
	snapshot := runtimeSnapshotStatus(oomRuntimeSnapshotKey{},
		memsnap.StatusGateTimeout, "deadline")
	if snapshot.GateRelease != "timeout_or_ack_missed" {
		t.Fatalf("gate release=%q", snapshot.GateRelease)
	}
}

func TestOOMRuntimeSnapshotIsEmbeddedInOOMJSON(t *testing.T) {
	key := oomRuntimeSnapshotKey{victimTGID: 42, oomMonotonicNS: 99}
	snapshot := runtimeSnapshotStatus(key, memsnap.StatusComplete, "captured")
	snapshot.EntryCount = 1
	snapshot.Entries = []memsnap.Entry{{
		Kind: memsnap.EntryKindObjectType, Name: "example.Payload",
		InuseObjects: 10, InuseBytes: 1024, AverageBytes: 102.4,
	}}
	raw, err := json.Marshal(OOMTracingData{RuntimeMemorySnapshot: snapshot})
	if err != nil {
		t.Fatal(err)
	}
	encoded := string(raw)
	for _, required := range []string{
		`"runtime_memory_snapshot"`, `"status":"COMPLETE"`,
		`"entry_count":1`,
		`"kind":"object_type"`, `"name":"example.Payload"`,
		`"inuse_bytes":1024`,
	} {
		if !strings.Contains(encoded, required) {
			t.Fatalf("OOM JSON %s does not contain %s", encoded, required)
		}
	}
	if strings.Contains(encoded, `"manifest"`) {
		t.Fatalf("runtime snapshot should be flat inside OOM JSON: %s", encoded)
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	runtimePayload := string(document["runtime_memory_snapshot"])
	for _, internal := range []string{
		`"snapshot_id"`, `"oom_request_cookie"`, `"identity"`,
		`"scope"`, `"mode"`, `"trigger"`,
	} {
		if strings.Contains(runtimePayload, internal) {
			t.Fatalf("OOM JSON contains internal snapshot field %s: %s",
				internal, runtimePayload)
		}
	}
}

func TestOOMRuntimeSnapshotBridgeTimeoutDoesNotLeak(t *testing.T) {
	bridge := newOOMRuntimeSnapshotBridge(time.Second)
	key := oomRuntimeSnapshotKey{victimTGID: 42, oomMonotonicNS: 99}
	if _, ok := bridge.wait(context.Background(), key, time.Millisecond); ok {
		t.Fatal("unexpected snapshot")
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if len(bridge.entries) != 0 {
		t.Fatalf("entries=%d, want 0", len(bridge.entries))
	}
}

func TestOOMRuntimeSnapshotBridgeTimeoutRaceDoesNotDropSnapshot(t *testing.T) {
	bridge := newOOMRuntimeSnapshotBridge(time.Second)
	key := oomRuntimeSnapshotKey{victimTGID: 42, oomMonotonicNS: 99}
	snapshot := runtimeSnapshotStatus(key, memsnap.StatusComplete, "captured")

	// Simulate publish having set the snapshot in the same instant the waiter's
	// timer fired: consume must return the snapshot rather than a timeout.
	entry := &oomRuntimeSnapshotEntry{ready: make(chan struct{}), snapshot: snapshot}
	bridge.mu.Lock()
	bridge.entries[key] = entry
	bridge.mu.Unlock()

	got, ok := bridge.consume(key, entry)
	if !ok || got != snapshot {
		t.Fatalf("consume = (%p, %v), want (%p, true)", got, ok, snapshot)
	}
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	if len(bridge.entries) != 0 {
		t.Fatalf("entries=%d, want 0", len(bridge.entries))
	}
}

func TestOOMRuntimeSnapshotWaitBudgetIncludesPostGateFinalization(t *testing.T) {
	eventTime := time.Unix(100, 0)
	gateTimeout := 50 * time.Millisecond
	now := eventTime.Add(gateTimeout + 25*time.Millisecond)
	want := oomRuntimeSnapshotFinalizeGrace - 25*time.Millisecond
	if got := oomRuntimeSnapshotWaitBudget(eventTime, gateTimeout, now); got != want {
		t.Fatalf("wait budget=%s, want %s", got, want)
	}
	if got := oomRuntimeSnapshotWaitBudget(eventTime, gateTimeout,
		eventTime.Add(gateTimeout+oomRuntimeSnapshotFinalizeGrace+time.Millisecond)); got != 0 {
		t.Fatalf("expired wait budget=%s, want 0", got)
	}
}
