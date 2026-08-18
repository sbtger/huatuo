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
	"sync"
	"time"

	"huatuo-bamai/internal/memsnap"
)

const oomRuntimeSnapshotBridgeTTL = 5 * time.Second

// Finalization only sorts, limits and encodes memory already owned by Huatuo.
// It is outside the synchronous kernel gate, so allow it a separate bounded
// publication window instead of discarding a useful prefix at the gate deadline.
const oomRuntimeSnapshotFinalizeGrace = 100 * time.Millisecond

func oomRuntimeSnapshotWaitBudget(eventTime time.Time,
	gateTimeout time.Duration, now time.Time,
) time.Duration {
	remaining := eventTime.Add(gateTimeout).
		Add(oomRuntimeSnapshotFinalizeGrace).Sub(now)
	if remaining < 0 {
		return 0
	}
	return remaining
}

type oomRuntimeSnapshotKey struct {
	victimTGID     uint32
	oomMonotonicNS uint64
}

// OOMRuntimeMemorySnapshot is embedded directly in the original oom tracing
// document. All languages use the same entries array; optional fields retain
// language-specific object shapes and allocation-stack semantics.
type OOMRuntimeMemorySnapshot = memsnap.RuntimeSnapshotPayload

func runtimeSnapshotFromResult(result *memsnap.Result) *OOMRuntimeMemorySnapshot {
	return memsnap.RuntimePayloadFromResult(result)
}

func runtimeSnapshotStatus(_ oomRuntimeSnapshotKey,
	status memsnap.CompletionStatus, reason string,
) *OOMRuntimeMemorySnapshot {
	snapshot := &OOMRuntimeMemorySnapshot{
		SchemaVersion: memsnap.SchemaVersion,
		Status:        status,
		Coverage: memsnap.Coverage{
			Consistency: "not_captured", SizeSemantics: "unavailable",
			KnownGaps: []string{reason},
		},
	}
	if status == memsnap.StatusGateTimeout {
		snapshot.GateRelease = "timeout_or_ack_missed"
	}
	return snapshot
}

type oomRuntimeSnapshotEntry struct {
	ready    chan struct{}
	snapshot *OOMRuntimeMemorySnapshot
	timer    *time.Timer
}

// oomRuntimeSnapshotBridge is an in-memory rendezvous between the kill-gate
// reader and the existing OOM event collector. It never persists a second
// document. Entries are bounded by OOM rate and expire even when either event
// stream is missing.
type oomRuntimeSnapshotBridge struct {
	mu      sync.Mutex
	entries map[oomRuntimeSnapshotKey]*oomRuntimeSnapshotEntry
	ttl     time.Duration
}

func newOOMRuntimeSnapshotBridge(ttl time.Duration) *oomRuntimeSnapshotBridge {
	return &oomRuntimeSnapshotBridge{
		entries: make(map[oomRuntimeSnapshotKey]*oomRuntimeSnapshotEntry),
		ttl:     ttl,
	}
}

func (b *oomRuntimeSnapshotBridge) publish(key oomRuntimeSnapshotKey,
	snapshot *OOMRuntimeMemorySnapshot,
) {
	if key.victimTGID == 0 || key.oomMonotonicNS == 0 || snapshot == nil {
		return
	}
	b.mu.Lock()
	entry := b.entries[key]
	if entry == nil {
		entry = &oomRuntimeSnapshotEntry{ready: make(chan struct{})}
		b.entries[key] = entry
	}
	if entry.snapshot == nil {
		entry.snapshot = snapshot
		close(entry.ready)
	}
	if entry.timer == nil {
		entry.timer = time.AfterFunc(b.ttl, func() { b.expire(key, entry) })
	}
	b.mu.Unlock()
}

func (b *oomRuntimeSnapshotBridge) wait(ctx context.Context,
	key oomRuntimeSnapshotKey, timeout time.Duration,
) (*OOMRuntimeMemorySnapshot, bool) {
	if key.victimTGID == 0 || key.oomMonotonicNS == 0 {
		return nil, false
	}
	b.mu.Lock()
	entry := b.entries[key]
	if entry != nil && entry.snapshot != nil {
		snapshot := entry.snapshot
		delete(b.entries, key)
		if entry.timer != nil {
			entry.timer.Stop()
		}
		b.mu.Unlock()
		return snapshot, true
	}
	if timeout <= 0 {
		b.mu.Unlock()
		return nil, false
	}
	if entry == nil {
		entry = &oomRuntimeSnapshotEntry{ready: make(chan struct{})}
		b.entries[key] = entry
	}
	ready := entry.ready
	b.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ready:
		return b.consume(key, entry)
	case <-timer.C:
		// Re-check under the lock before expiring: publish may have closed
		// ready in the same instant the timeout fired, in which case the
		// snapshot is already here and must not be misreported as a timeout.
		return b.consume(key, entry)
	case <-ctx.Done():
		return b.consume(key, entry)
	}
}

// consume removes the entry (if it is still the one tracked under key), stops
// its TTL timer, and returns whatever snapshot arrived, if any.
func (b *oomRuntimeSnapshotBridge) consume(key oomRuntimeSnapshotKey,
	entry *oomRuntimeSnapshotEntry,
) (*OOMRuntimeMemorySnapshot, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if current := b.entries[key]; current == entry {
		delete(b.entries, key)
	}
	if entry.timer != nil {
		entry.timer.Stop()
	}
	snapshot := entry.snapshot
	return snapshot, snapshot != nil
}

func (b *oomRuntimeSnapshotBridge) expire(key oomRuntimeSnapshotKey,
	entry *oomRuntimeSnapshotEntry,
) {
	b.mu.Lock()
	if current := b.entries[key]; current == entry {
		delete(b.entries, key)
	}
	b.mu.Unlock()
}

var runtimeSnapshotBridge = newOOMRuntimeSnapshotBridge(
	oomRuntimeSnapshotBridgeTTL)
