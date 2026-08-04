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

	"huatuo-bamai/internal/goheap"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/internal/profiler"
	"huatuo-bamai/pkg/tracing"
)

const (
	oomGoHeapTracerName        = "oom-go-heap"
	defaultOOMGoHeapPendingTTL = 30 * time.Second
	defaultOOMGoHeapMaxPending = 128
)

type oomGoHeapKey struct {
	victimPID    uint32
	oomTimestamp uint64
}

type oomGoHeapEvent struct {
	tracerID    string
	containerID string
	eventTime   time.Time
}

type pendingOOMGoHeap struct {
	event     *oomGoHeapEvent
	capture   *goheap.Capture
	createdAt time.Time
	expiresAt time.Time
}

type oomGoHeapCorrelation struct {
	VictimPID            uint32 `json:"victim_pid"`
	VictimStartTimeTicks uint64 `json:"victim_start_time_ticks"`
	OOMTimestamp         uint64 `json:"oom_timestamp"`
	GoVersion            string `json:"go_version,omitempty"`
	BuildID              string `json:"build_id,omitempty"`
}

type oomGoHeapCaptureMetadata struct {
	CaptureID         uint32 `json:"capture_id"`
	CaptureStartedNS  uint64 `json:"capture_started_ns"`
	CaptureDurationNS uint64 `json:"capture_duration_ns"`
	BucketCount       int    `json:"bucket_count"`
	SkippedBuckets    uint32 `json:"skipped_buckets"`
	Flags             uint32 `json:"flags"`
	EmittedBuckets    int    `json:"emitted_buckets"`
	InvalidBuckets    int    `json:"invalid_buckets"`
	CounterUnderflows int    `json:"counter_underflows"`
	CounterOverflows  int    `json:"counter_overflows"`
	ValueClamps       int    `json:"value_clamps"`
}

// oomGoHeapProfileData keeps the regular flamedata shape understood by the
// profiling service while retaining the exact OOM and capture correlation.
type oomGoHeapProfileData struct {
	FlameData   *profiler.ProfileData    `json:"flamedata"`
	Correlation oomGoHeapCorrelation     `json:"oom_correlation"`
	Capture     oomGoHeapCaptureMetadata `json:"capture"`
}

type oomGoHeapPair struct {
	event   oomGoHeapEvent
	capture *goheap.Capture
}

// oomGoHeapProfiler pairs the independent base OOM and heap perf streams.
// Pairing is order-independent and bounded, so a lost event cannot grow state
// indefinitely during an OOM storm.
type oomGoHeapProfiler struct {
	mu         sync.Mutex
	pending    map[oomGoHeapKey]*pendingOOMGoHeap
	pendingTTL time.Duration
	maxPending int
	now        func() time.Time
	symbolize  func(goheap.Target) (goheap.Symbolizer, error)
	convert    func(goheap.Target, []goheap.Bucket, time.Time, goheap.Symbolizer) (*goheap.Profiles, error)
	save       func(*tracing.WriteRequest) error
}

func newOOMGoHeapProfiler() *oomGoHeapProfiler {
	return &oomGoHeapProfiler{
		pending:    make(map[oomGoHeapKey]*pendingOOMGoHeap),
		pendingTTL: defaultOOMGoHeapPendingTTL,
		maxPending: defaultOOMGoHeapMaxPending,
		now:        time.Now,
		symbolize: func(target goheap.Target) (goheap.Symbolizer, error) {
			return goheap.NewELFSymbolizer(target.Executable, target.LoadBias)
		},
		convert: goheap.Convert,
		save:    tracing.SaveProfile,
	}
}

// ObserveOOM records the storage metadata from the base OOM event. tracerID
// must also be used for the base OOM document, making both profile views
// directly queryable from that event.
func (p *oomGoHeapProfiler) ObserveOOM(victimPID uint32, oomTimestamp uint64,
	tracerID, containerID string, eventTime time.Time,
) error {
	if victimPID == 0 || oomTimestamp == 0 {
		return nil
	}
	event := &oomGoHeapEvent{
		tracerID: tracerID, containerID: containerID, eventTime: eventTime,
	}
	pair := p.add(oomGoHeapKey{victimPID: victimPID, oomTimestamp: oomTimestamp}, event, nil)
	return p.process(pair)
}

// HandleCapture records one heap snapshot from the optional BPF stream.
func (p *oomGoHeapProfiler) HandleCapture(capture *goheap.Capture) error {
	if capture == nil {
		return errors.New("oom go heap: nil capture")
	}
	if capture.Target.PID == 0 || capture.OOMTimestamp == 0 {
		return errors.New("oom go heap: capture has no correlation key")
	}
	pair := p.add(oomGoHeapKey{
		victimPID: capture.Target.PID, oomTimestamp: capture.OOMTimestamp,
	}, nil, capture)
	return p.process(pair)
}

func (p *oomGoHeapProfiler) add(key oomGoHeapKey, event *oomGoHeapEvent,
	capture *goheap.Capture,
) *oomGoHeapPair {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := p.now()
	p.expireLocked(now)
	entry := p.pending[key]
	if entry == nil {
		p.makeRoomLocked()
		entry = &pendingOOMGoHeap{
			createdAt: now,
			expiresAt: now.Add(p.pendingTTL),
		}
		p.pending[key] = entry
	}
	if event != nil {
		entry.event = event
	}
	if capture != nil {
		entry.capture = capture
	}
	if entry.event == nil || entry.capture == nil {
		return nil
	}
	delete(p.pending, key)
	return &oomGoHeapPair{event: *entry.event, capture: entry.capture}
}

func (p *oomGoHeapProfiler) expireLocked(now time.Time) {
	for key, entry := range p.pending {
		if !now.Before(entry.expiresAt) {
			delete(p.pending, key)
		}
	}
}

func (p *oomGoHeapProfiler) makeRoomLocked() {
	if len(p.pending) < p.maxPending {
		return
	}
	var oldestKey oomGoHeapKey
	var oldestTime time.Time
	for key, entry := range p.pending {
		if oldestTime.IsZero() || entry.createdAt.Before(oldestTime) {
			oldestKey = key
			oldestTime = entry.createdAt
		}
	}
	delete(p.pending, oldestKey)
}

func (p *oomGoHeapProfiler) process(pair *oomGoHeapPair) error {
	if pair == nil {
		return nil
	}

	symbolizer, err := p.symbolize(pair.capture.Target)
	if err != nil {
		// Raw PCs are still actionable and are preferable to losing the only
		// pre-exit heap snapshot when a binary was replaced or deleted.
		log.Warnf("oom go heap symbolization disabled for pid %d: %v",
			pair.capture.Target.PID, err)
		symbolizer = nil
	}
	profiles, err := p.convert(pair.capture.Target, pair.capture.Buckets,
		pair.event.eventTime, symbolizer)
	if err != nil {
		return fmt.Errorf("oom go heap: convert capture: %w", err)
	}

	correlation := oomGoHeapCorrelation{
		VictimPID:            pair.capture.Target.PID,
		VictimStartTimeTicks: pair.capture.Target.StartTimeTicks,
		OOMTimestamp:         pair.capture.OOMTimestamp,
		GoVersion:            pair.capture.Target.GoVersion,
		BuildID:              pair.capture.Target.BuildID,
	}
	metadata := oomGoHeapCaptureMetadata{
		CaptureID:         pair.capture.CaptureID,
		CaptureStartedNS:  pair.capture.CaptureStartedNS,
		CaptureDurationNS: pair.capture.CaptureDurationNS,
		BucketCount:       len(pair.capture.Buckets),
		SkippedBuckets:    pair.capture.SkippedBuckets,
		Flags:             pair.capture.Flags,
		EmittedBuckets:    profiles.Stats.EmittedBuckets,
		InvalidBuckets:    profiles.Stats.InvalidStackDepths,
		CounterUnderflows: profiles.Stats.CounterUnderflows,
		CounterOverflows:  profiles.Stats.CounterOverflows,
		ValueClamps:       profiles.Stats.ProfileValueClamps,
	}

	saveProfile := func(data *profiler.ProfileData) error {
		return p.save(&tracing.WriteRequest{
			TracerName:    oomGoHeapTracerName,
			TracerID:      pair.event.tracerID,
			ContainerID:   pair.event.containerID,
			TracerTime:    pair.event.eventTime,
			TracerData:    &oomGoHeapProfileData{FlameData: data, Correlation: correlation, Capture: metadata},
			TracerRunType: tracing.TracerRunTypeEvent,
		})
	}
	return errors.Join(saveProfile(profiles.InuseSpace), saveProfile(profiles.InuseObjects))
}
