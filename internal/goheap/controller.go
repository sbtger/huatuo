// Copyright 2022-2025 The Parca Authors
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
//
// This file contains work derived from github.com/parca-dev/oomprof.
// It was modified by The HuaTuo Authors for integration with HuaTuo.

package goheap

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/bpf/abi"
	"huatuo-bamai/internal/log"
)

const (
	// MaxCaptureBuckets must match GO_HEAP_MAX_BUCKETS in the BPF ABI.
	MaxCaptureBuckets = 4096

	defaultCaptureBudget    = 2 * time.Millisecond
	defaultReconcilePeriod  = 10 * time.Second
	defaultPerfBufferSize   = 8192
	retiredTargetRetention  = 30 * time.Second
	goHeapObjectName        = "oom_go_heap.o"
	goHeapTargetsMapName    = "go_heap_targets"
	goHeapBucketsMapName    = "go_heap_buckets"
	goHeapControlMapName    = "go_heap_control"
	goHeapEventsMapName     = "go_heap_events"
	sharedOOMVictimsMapName = "oom_victims"
)

// Capture flags mirror the bounded BPF capture result.
const (
	CaptureFlagComplete      uint32 = 1 << 0
	CaptureFlagDeadline             = 1 << 1
	CaptureFlagLimit                = 1 << 2
	CaptureFlagReadError            = 1 << 3
	CaptureFlagTailCallError        = 1 << 4
)

// ControllerOptions controls the optional OOM Go heap capture path.
type ControllerOptions struct {
	CaptureBudget   time.Duration
	ReconcilePeriod time.Duration
	PerfBufferSize  uint32
}

// Capture is one stable copy of the BPF bucket array and its correlation key.
type Capture struct {
	Target            Target
	OOMTimestamp      uint64
	CaptureStartedNS  uint64
	CaptureDurationNS uint64
	CaptureID         uint32
	SkippedBuckets    uint32
	Flags             uint32
	Buckets           []Bucket
}

type captureObject interface {
	MapIDByName(string) uint32
	AttachWithOptions([]bpf.AttachOption) error
	EventPipeByName(context.Context, string, uint32) (bpf.PerfEventReader, error)
	ReadMap(uint32, []byte) ([]byte, error)
	WriteMapItems(uint32, []bpf.MapItem) error
	DeleteMapItems(uint32, [][]byte) error
	Close() error
}

type retiredTarget struct {
	target    Target
	expiresAt time.Time
}

// Controller owns the optional heap BPF object, target reconciliation, and
// single-flight capture acknowledgement. It is safe for concurrent close,
// reconciliation, and capture reads; only one capture reader may run at once.
type Controller struct {
	ctx    context.Context
	cancel context.CancelFunc

	registry *Registry
	object   captureObject
	reader   bpf.PerfEventReader
	period   time.Duration

	targetsMapID uint32
	bucketsMapID uint32
	controlMapID uint32

	reconcileMu sync.Mutex
	targetsMu   sync.RWMutex
	applied     map[uint32]Target
	retired     map[Identity]retiredTarget
	readMu      sync.Mutex
	closeOnce   sync.Once
	closeErr    error
}

// OpenController loads and attaches the optional heap object. The oomVictims
// map is shared with the already loaded base OOM object, so both programs use
// the exact same kernel correlation state.
func OpenController(ctx context.Context, oomObject bpf.BPF, registry *Registry, opts ControllerOptions) (*Controller, error) {
	if oomObject == nil {
		return nil, errors.New("goheap: nil OOM BPF object")
	}
	if registry == nil {
		return nil, errors.New("goheap: nil target registry")
	}
	if oomObject.MapIDByName(sharedOOMVictimsMapName) == 0 {
		return nil, fmt.Errorf("goheap: base OOM object has no %q map", sharedOOMVictimsMapName)
	}

	opts = withControllerDefaults(opts)
	object, err := bpf.LoadBPFWithOptions(goHeapObjectName, &bpf.LoadOptions{
		Constants: map[string]any{
			"go_heap_capture_enabled":   uint32(1),
			"go_heap_capture_budget_ns": uint64(opts.CaptureBudget),
		},
		MapReplacements: map[string]bpf.MapReplacement{
			sharedOOMVictimsMapName: {Source: oomObject},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("goheap: load capture BPF: %w", err)
	}

	controllerCtx, cancel := context.WithCancel(ctx)
	c := &Controller{
		ctx:          controllerCtx,
		cancel:       cancel,
		registry:     registry,
		object:       object,
		period:       opts.ReconcilePeriod,
		targetsMapID: object.MapIDByName(goHeapTargetsMapName),
		bucketsMapID: object.MapIDByName(goHeapBucketsMapName),
		controlMapID: object.MapIDByName(goHeapControlMapName),
		applied:      make(map[uint32]Target),
		retired:      make(map[Identity]retiredTarget),
	}
	if c.targetsMapID == 0 || c.bucketsMapID == 0 || c.controlMapID == 0 {
		_ = c.Close()
		return nil, errors.New("goheap: capture BPF is missing required maps")
	}

	c.reader, err = object.EventPipeByName(controllerCtx, goHeapEventsMapName, opts.PerfBufferSize)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("goheap: open capture event pipe: %w", err)
	}
	if _, err := c.Reconcile(controllerCtx); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("goheap: initial target reconciliation: %w", err)
	}
	if err := object.AttachWithOptions([]bpf.AttachOption{{
		ProgramName: "go_heap_signal_deliver",
		Symbol:      "signal/signal_deliver",
	}}); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("goheap: attach signal tracepoint: %w", err)
	}
	return c, nil
}

func withControllerDefaults(opts ControllerOptions) ControllerOptions {
	if opts.CaptureBudget <= 0 {
		opts.CaptureBudget = defaultCaptureBudget
	}
	if opts.ReconcilePeriod <= 0 {
		opts.ReconcilePeriod = defaultReconcilePeriod
	}
	if opts.PerfBufferSize == 0 {
		opts.PerfBufferSize = defaultPerfBufferSize
	}
	return opts
}

// Reconcile discovers current Go processes and makes the BPF target map match
// the registry snapshot. Applied state is changed only after each successful
// map operation, so a transient failure is retried on the next pass.
func (c *Controller) Reconcile(ctx context.Context) (Changes, error) {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()

	changes, err := c.registry.Reconcile(ctx)
	if err != nil {
		return Changes{}, err
	}
	desiredTargets := c.registry.Snapshot()
	desired := make(map[uint32]Target, len(desiredTargets))
	for _, target := range desiredTargets {
		desired[target.PID] = target
	}
	if err := c.syncTargets(desired, time.Now()); err != nil {
		return changes, err
	}
	return changes, nil
}

func (c *Controller) syncTargets(desired map[uint32]Target, now time.Time) error {
	c.targetsMu.Lock()
	defer c.targetsMu.Unlock()

	for identity, retired := range c.retired {
		if !now.Before(retired.expiresAt) {
			delete(c.retired, identity)
		}
	}

	for pid, current := range c.applied {
		target, ok := desired[pid]
		if ok && target.Identity == current.Identity {
			continue
		}
		if err := c.object.DeleteMapItems(c.targetsMapID, [][]byte{uint32Key(pid)}); err != nil {
			return fmt.Errorf("goheap: delete target %d: %w", pid, err)
		}
		delete(c.applied, pid)
		c.retired[current.Identity] = retiredTarget{
			target: current, expiresAt: now.Add(retiredTargetRetention),
		}
	}

	for pid, target := range desired {
		if current, ok := c.applied[pid]; ok && current == target {
			continue
		}
		value, err := nativeBytes(abi.GoHeapTarget{
			MbucketsAddress: target.MBucketsAddress(),
			StartTimeTicks:  target.StartTimeTicks,
		})
		if err != nil {
			return err
		}
		if err := c.object.WriteMapItems(c.targetsMapID, []bpf.MapItem{{
			Key: uint32Key(pid), Value: value,
		}}); err != nil {
			return fmt.Errorf("goheap: write target %d: %w", pid, err)
		}
		c.applied[pid] = target
		delete(c.retired, target.Identity)
	}
	return nil
}

// ReadCapture copies one stable bucket array and then acknowledges the BPF
// single-flight owner. The acknowledgement is attempted on every path after a
// decoded event, including validation and map-read failures.
func (c *Controller) ReadCapture() (capture *Capture, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	var event abi.GoHeapEvent
	if err := c.reader.ReadInto(&event); err != nil {
		return nil, err
	}
	defer func() {
		ackErr := c.object.DeleteMapItems(c.controlMapID, [][]byte{uint32Key(0)})
		if ackErr != nil {
			err = errors.Join(err, fmt.Errorf("goheap: acknowledge capture: %w", ackErr))
		}
	}()

	if event.BucketCount > MaxCaptureBuckets {
		return nil, fmt.Errorf("goheap: invalid bucket count %d", event.BucketCount)
	}
	identity := Identity{PID: event.VictimTGID, StartTimeTicks: event.StartTimeTicks}
	target, ok := c.targetFor(identity)
	if !ok {
		return nil, fmt.Errorf("goheap: target pid=%d start_ticks=%d is no longer known", identity.PID, identity.StartTimeTicks)
	}

	buckets := make([]Bucket, event.BucketCount)
	for i := range buckets {
		raw, readErr := c.object.ReadMap(c.bucketsMapID, uint32Key(uint32(i)))
		if readErr != nil {
			return nil, fmt.Errorf("goheap: read bucket %d: %w", i, readErr)
		}
		var bucket abi.GoHeapBucket
		if _, decodeErr := binary.Decode(raw, binary.NativeEndian, &bucket); decodeErr != nil {
			return nil, fmt.Errorf("goheap: decode bucket %d: %w", i, decodeErr)
		}
		buckets[i] = bucketFromABI(bucket)
	}

	return &Capture{
		Target:            target,
		OOMTimestamp:      event.OOMTimestamp,
		CaptureStartedNS:  event.CaptureStartedNS,
		CaptureDurationNS: event.CaptureDurationNS,
		CaptureID:         event.CaptureID,
		SkippedBuckets:    event.SkippedBuckets,
		Flags:             event.Flags,
		Buckets:           buckets,
	}, nil
}

func (c *Controller) targetFor(identity Identity) (Target, bool) {
	c.targetsMu.RLock()
	defer c.targetsMu.RUnlock()
	if target, ok := c.applied[identity.PID]; ok && target.Identity == identity {
		return target, true
	}
	retired, ok := c.retired[identity]
	return retired.target, ok
}

func bucketFromABI(bucket abi.GoHeapBucket) Bucket {
	result := Bucket{StackDepth: bucket.StackDepth, Stack: bucket.Stack}
	result.Record.Active = cycleFromABI(bucket.Record.Active)
	for i := range bucket.Record.Future {
		result.Record.Future[i] = cycleFromABI(bucket.Record.Future[i])
	}
	return result
}

func cycleFromABI(cycle abi.GoHeapMemCycle) MemRecordCycle {
	return MemRecordCycle{
		Allocs: cycle.Allocs, Frees: cycle.Frees,
		AllocBytes: cycle.AllocBytes, FreeBytes: cycle.FreeBytes,
	}
}

func nativeBytes(value any) ([]byte, error) {
	var output bytes.Buffer
	if err := binary.Write(&output, binary.NativeEndian, value); err != nil {
		return nil, fmt.Errorf("goheap: encode BPF value: %w", err)
	}
	return output.Bytes(), nil
}

func uint32Key(value uint32) []byte {
	key := make([]byte, 4)
	binary.NativeEndian.PutUint32(key, value)
	return key
}

// Run reconciles targets periodically and delivers captures until cancellation
// or a fatal reader/handler error. Discovery failures are logged and retried.
func (c *Controller) Run(handler func(*Capture) error) error {
	if handler == nil {
		return errors.New("goheap: nil capture handler")
	}

	runCtx, cancel := context.WithCancel(c.ctx)
	defer cancel()
	ticker := time.NewTicker(c.period)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				if _, err := c.Reconcile(runCtx); err != nil && runCtx.Err() == nil {
					log.Warnf("goheap target reconciliation failed: %v", err)
				}
			}
		}
	}()

	for {
		capture, err := c.ReadCapture()
		if err != nil {
			if c.ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, bpf.ErrPerfEventSamplesLost) {
				log.WithError(err).Warn("lost Go heap BPF perf event samples")
				continue
			}
			return err
		}
		if err := handler(capture); err != nil {
			return err
		}
	}
}

// Close stops readers and releases the optional BPF object.
func (c *Controller) Close() error {
	c.closeOnce.Do(func() {
		if c.cancel != nil {
			c.cancel()
		}
		var readerErr error
		if c.reader != nil {
			readerErr = c.reader.Close()
		}
		var objectErr error
		if c.object != nil {
			objectErr = c.object.Close()
		}
		c.closeErr = errors.Join(readerErr, objectErr)
	})
	return c.closeErr
}
