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
	"errors"
	"fmt"
	"sync"
	"time"

	"huatuo-bamai/internal/javastack"
	"huatuo-bamai/internal/profiler"
	"huatuo-bamai/pkg/tracing"
)

const (
	oomJavaStackTracerName        = "oom-java-stack"
	defaultOOMJavaStackPendingTTL = 30 * time.Second
	defaultOOMJavaStackMaxPending = 128
)

type oomJavaStackKey struct {
	victimPID    uint32 //nolint:unused // used by map key equality
	oomTimestamp uint64 //nolint:unused // used by map key equality
}

type oomJavaStackEvent struct {
	tracerID    string
	containerID string
	eventTime   time.Time
}

type pendingOOMJavaStack struct {
	event     *oomJavaStackEvent
	snapshot  *javastack.Snapshot
	createdAt time.Time
	expiresAt time.Time
}

type oomJavaStackCorrelation struct {
	VictimPID            uint32 `json:"victim_pid"`
	VictimTID            uint32 `json:"victim_tid"`
	VictimStartTimeTicks uint64 `json:"victim_start_time_ticks"`
	OOMTimestamp         uint64 `json:"oom_timestamp"`
	CaptureTimestamp     uint64 `json:"capture_timestamp"`
	SignalDelayNS        uint64 `json:"signal_delay_ns"`
	CgroupID             uint64 `json:"cgroup_id"`
}

type oomJavaStackCaptureMetadata struct {
	StackSize            int32  `json:"stack_size"`
	StackError           int32  `json:"stack_error,omitempty"`
	Flags                uint32 `json:"flags"`
	RawDepth             int    `json:"raw_depth"`
	ResolvedFrames       int    `json:"resolved_frames"`
	UnresolvedFrames     int    `json:"unresolved_frames"`
	DirectAvailable      bool   `json:"hotspot_direct_available"`
	DirectErrors         uint32 `json:"hotspot_direct_errors"`
	BPFCaptureDurationNS uint64 `json:"bpf_capture_duration_ns"`
	HotspotUnwound       bool   `json:"hotspot_unwound"`
	ThreadGroupScanned   bool   `json:"thread_group_scanned"`
	SnapshotSemantics    string `json:"snapshot_semantics"`
	Complete             bool   `json:"complete"`
}

type oomJavaStackProfileData struct {
	FlameData   *profiler.ProfileData       `json:"flamedata"`
	Correlation oomJavaStackCorrelation     `json:"oom_correlation"`
	Capture     oomJavaStackCaptureMetadata `json:"capture"`
	Frames      []javastack.Frame           `json:"frames"`
}

type oomJavaStackPair struct {
	event    oomJavaStackEvent
	snapshot *javastack.Snapshot
}

type oomJavaStackProfiler struct {
	mu         sync.Mutex
	pending    map[oomJavaStackKey]*pendingOOMJavaStack
	pendingTTL time.Duration
	maxPending int
	now        func() time.Time
	resolve    func(snapshot *javastack.Snapshot) javastack.Resolution
	save       func(request *tracing.WriteRequest) error
}

func newOOMJavaStackProfiler(symbols *javastack.SymbolManager) *oomJavaStackProfiler {
	return &oomJavaStackProfiler{
		pending:    make(map[oomJavaStackKey]*pendingOOMJavaStack),
		pendingTTL: defaultOOMJavaStackPendingTTL, maxPending: defaultOOMJavaStackMaxPending,
		now: time.Now, resolve: symbols.Resolve, save: tracing.SaveProfile,
	}
}

func (p *oomJavaStackProfiler) ObserveOOM(victimPID uint32, oomTimestamp uint64,
	tracerID, containerID string, eventTime time.Time,
) error {
	if victimPID == 0 || oomTimestamp == 0 {
		return nil
	}
	event := &oomJavaStackEvent{
		tracerID: tracerID, containerID: containerID, eventTime: eventTime,
	}
	pair := p.add(oomJavaStackKey{victimPID, oomTimestamp}, event, nil)
	return p.process(pair)
}

func (p *oomJavaStackProfiler) HandleSnapshot(snapshot *javastack.Snapshot) error {
	if snapshot == nil {
		return errors.New("oom Java stack: nil snapshot")
	}
	if snapshot.Target.PID == 0 || snapshot.OOMTimestamp == 0 {
		return errors.New("oom Java stack: snapshot has no correlation key")
	}
	pair := p.add(oomJavaStackKey{snapshot.Target.PID, snapshot.OOMTimestamp}, nil, snapshot)
	return p.process(pair)
}

func (p *oomJavaStackProfiler) add(key oomJavaStackKey,
	event *oomJavaStackEvent, snapshot *javastack.Snapshot,
) *oomJavaStackPair {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	for pendingKey, entry := range p.pending {
		if !now.Before(entry.expiresAt) {
			delete(p.pending, pendingKey)
		}
	}
	entry := p.pending[key]
	if entry == nil {
		if len(p.pending) >= p.maxPending {
			var oldestKey oomJavaStackKey
			var oldest time.Time
			for pendingKey, candidate := range p.pending {
				if oldest.IsZero() || candidate.createdAt.Before(oldest) {
					oldestKey, oldest = pendingKey, candidate.createdAt
				}
			}
			delete(p.pending, oldestKey)
		}
		entry = &pendingOOMJavaStack{createdAt: now, expiresAt: now.Add(p.pendingTTL)}
		p.pending[key] = entry
	}
	if event != nil {
		entry.event = event
	}
	if snapshot != nil {
		entry.snapshot = snapshot
	}
	if entry.event == nil || entry.snapshot == nil {
		return nil
	}
	delete(p.pending, key)
	return &oomJavaStackPair{event: *entry.event, snapshot: entry.snapshot}
}

func (p *oomJavaStackProfiler) process(pair *oomJavaStackPair) error {
	if pair == nil {
		return nil
	}
	resolution := p.resolve(pair.snapshot)
	stack := make([][]byte, 0, len(resolution.Frames)+1)
	stack = append(stack, []byte(fmt.Sprintf("process %d:java", pair.snapshot.Target.PID)))
	for _, frame := range resolution.Frames {
		stack = append(stack, []byte(frame.Name))
	}
	if len(resolution.Frames) == 0 {
		name := "[java_stack_empty]"
		if pair.snapshot.StackSize < 0 {
			name = fmt.Sprintf("[java_stack_capture_error_%d]", pair.snapshot.StackSize)
		}
		stack = append(stack, []byte(name))
	}
	profile, err := profiler.ParseTree(pair.event.eventTime,
		profiler.ProfileTypeEventSample,
		[]*profiler.TreeItem{{Stack: stack, Value: 1}}, nil)
	if err != nil {
		return fmt.Errorf("oom Java stack: convert snapshot: %w", err)
	}
	delay := uint64(0)
	if pair.snapshot.CaptureTimestamp >= pair.snapshot.OOMTimestamp {
		delay = pair.snapshot.CaptureTimestamp - pair.snapshot.OOMTimestamp
	}
	stackError := int32(0)
	if pair.snapshot.StackSize < 0 {
		stackError = pair.snapshot.StackSize
	}
	snapshotSemantics := "current_signal_thread"
	if pair.snapshot.Flags&javastack.CaptureFlagThreadScanned != 0 {
		snapshotSemantics = "selected_thread_group_member"
	}
	data := &oomJavaStackProfileData{
		FlameData: profile,
		Correlation: oomJavaStackCorrelation{
			VictimPID: pair.snapshot.Target.PID, VictimTID: pair.snapshot.VictimTID,
			VictimStartTimeTicks: pair.snapshot.Target.StartTimeTicks,
			OOMTimestamp:         pair.snapshot.OOMTimestamp,
			CaptureTimestamp:     pair.snapshot.CaptureTimestamp,
			SignalDelayNS:        delay, CgroupID: pair.snapshot.CgroupID,
		},
		Capture: oomJavaStackCaptureMetadata{
			StackSize: pair.snapshot.StackSize, StackError: stackError,
			Flags: pair.snapshot.Flags, RawDepth: len(pair.snapshot.PCs),
			ResolvedFrames:       resolution.ResolvedFrames,
			UnresolvedFrames:     resolution.UnresolvedFrames,
			DirectAvailable:      resolution.DirectAvailable,
			DirectErrors:         resolution.DirectErrors,
			BPFCaptureDurationNS: pair.snapshot.CaptureDurationNS,
			HotspotUnwound:       pair.snapshot.Flags&javastack.CaptureFlagHotspotUnwound != 0,
			ThreadGroupScanned:   pair.snapshot.Flags&javastack.CaptureFlagThreadScanned != 0,
			SnapshotSemantics:    snapshotSemantics,
			Complete:             false,
		},
		Frames: resolution.Frames,
	}
	return p.save(&tracing.WriteRequest{
		TracerName: oomJavaStackTracerName, TracerID: pair.event.tracerID,
		ContainerID: pair.event.containerID, TracerTime: pair.event.eventTime,
		TracerData: data, TracerRunType: tracing.TracerRunTypeEvent,
	})
}
