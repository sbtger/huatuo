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

package javastack

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"
	"sync"
	"time"

	"golang.org/x/sys/unix"
	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/bpf/abi"
	"huatuo-bamai/internal/log"
)

const (
	MaxStackDepth   = 64
	MaxDirectFrames = 16

	defaultReconcilePeriod = 10 * time.Second
	defaultPerfBufferSize  = 8192
	retiredTargetRetention = 30 * time.Second
	javaStackObjectName    = "oom_java_stack.o"
	javaTargetsMapName     = "java_stack_targets"
	javaCapturesMapName    = "java_stack_captures"
	javaEventsMapName      = "java_stack_events"
	javaSystemConfigMap    = "java_stack_system_config"
	sharedOOMVictimsMap    = "oom_victims"
	minStackPtRegsOffset   = 4096
	maxStackPtRegsOffset   = 64 * 1024
)

// Capture flags mirror the BPF event result.
const (
	CaptureFlagCaptured       uint32 = 1 << 0
	CaptureFlagError                 = 1 << 1
	CaptureFlagHotspotUnwound        = 1 << 2
	CaptureFlagPtRegsError           = 1 << 3
	CaptureFlagThreadScanned         = 1 << 4

	DirectFrameResolved    uint32 = 1 << 0
	DirectFrameNotNmethod         = 1 << 1
	DirectFrameHeapMiss           = 1 << 2
	DirectFrameReadError          = 1 << 3
	DirectFrameTruncated          = 1 << 4
	DirectFrameInterpreter        = 1 << 5
)

// ControllerOptions controls target reconciliation and perf buffering.
type ControllerOptions struct {
	ReconcilePeriod time.Duration
	PerfBufferSize  uint32
	InspectTarget   func(target Target) (HotspotMetadata, error)
}

// DirectFrame is Java method metadata copied before SIGKILL returns.
type DirectFrame struct {
	PC         uint64
	CompileID  uint32
	Flags      uint32
	ClassName  string
	MethodName string
}

// Snapshot is one stable copy of a Java OOM stack event.
type Snapshot struct {
	Target            Target
	OOMTimestamp      uint64
	CaptureTimestamp  uint64
	CaptureDurationNS uint64
	CgroupID          uint64
	VictimTID         uint32
	StackSize         int32
	Flags             uint32
	PCs               []uint64
	DirectFrames      []DirectFrame
	DirectErrorCount  uint32
}

type captureObject interface {
	MapIDByName(name string) uint32
	AttachWithOptions(options []bpf.AttachOption) error
	EventPipeByName(ctx context.Context, name string, size uint32) (bpf.PerfEventReader, error)
	WriteMapItems(mapID uint32, items []bpf.MapItem) error
	DeleteMapItems(mapID uint32, keys [][]byte) error
	Close() error
}

type retiredTarget struct {
	target    Target
	expiresAt time.Time
}

// Controller owns the Java stack BPF object and target lifecycle.
type Controller struct {
	ctx    context.Context
	cancel context.CancelFunc

	registry *Registry
	object   captureObject
	reader   bpf.PerfEventReader
	period   time.Duration
	inspect  func(target Target) (HotspotMetadata, error)

	targetsMapID  uint32
	capturesMapID uint32

	reconcileMu sync.Mutex
	targetsMu   sync.RWMutex
	applied     map[uint32]Target
	retired     map[Identity]retiredTarget
	inspectWarn map[Identity]bool
	readMu      sync.Mutex
	closeOnce   sync.Once
	closeErr    error
}

// discoverStackPtRegsOffset briefly attaches to raw sys_enter so its context
// supplies the exact address of the current task's entry pt_regs. This avoids
// hard-coding THREAD_SIZE on older kernels that lack bpf_task_pt_regs().
func discoverStackPtRegsOffset() (uint32, error) {
	if runtime.GOARCH != "amd64" {
		return 0, nil
	}
	pid := uint32(os.Getpid())
	object, err := bpf.LoadBPFWithOptions(javaStackObjectName, &bpf.LoadOptions{
		Constants: map[string]any{
			"java_stack_capture_enabled": uint32(0),
			"java_stack_discovery_pid":   pid,
			"java_stack_ptregs_offset":   uint32(0),
		},
	})
	if err != nil {
		return 0, fmt.Errorf("load discovery BPF: %w", err)
	}
	defer object.Close()
	mapID := object.MapIDByName(javaSystemConfigMap)
	if mapID == 0 {
		return 0, errors.New("discovery BPF is missing system config map")
	}
	if err := object.AttachWithOptions([]bpf.AttachOption{{
		ProgramName: "java_stack_discover_pt_regs", Symbol: "sys_enter",
	}}); err != nil {
		return 0, fmt.Errorf("attach discovery BPF: %w", err)
	}
	if _, _, errno := unix.RawSyscall(unix.SYS_GETPID, 0, 0, 0); errno != 0 {
		return 0, fmt.Errorf("trigger pt_regs discovery: %w", errno)
	}
	value, err := object.ReadMap(mapID, uint32Key(0))
	if err != nil {
		return 0, fmt.Errorf("read pt_regs discovery: %w", err)
	}
	if len(value) != 8 {
		return 0, fmt.Errorf("invalid pt_regs discovery size %d", len(value))
	}
	offset := binary.NativeEndian.Uint64(value)
	if offset < minStackPtRegsOffset || offset >= maxStackPtRegsOffset {
		return 0, fmt.Errorf("invalid pt_regs offset %d", offset)
	}
	return uint32(offset), nil
}

// OpenController loads the Java stack object with the base OOM victim map.
func OpenController(ctx context.Context, oomObject bpf.BPF, registry *Registry, opts ControllerOptions) (*Controller, error) {
	if oomObject == nil {
		return nil, errors.New("javastack: nil OOM BPF object")
	}
	if registry == nil {
		return nil, errors.New("javastack: nil target registry")
	}
	if oomObject.MapIDByName(sharedOOMVictimsMap) == 0 {
		return nil, fmt.Errorf("javastack: base OOM object has no %q map", sharedOOMVictimsMap)
	}
	if opts.ReconcilePeriod <= 0 {
		opts.ReconcilePeriod = defaultReconcilePeriod
	}
	if opts.PerfBufferSize == 0 {
		opts.PerfBufferSize = defaultPerfBufferSize
	}
	if opts.InspectTarget == nil {
		inspector := newHotspotInspector("/proc")
		opts.InspectTarget = inspector.Inspect
	}
	ptRegsOffset, discoveryErr := discoverStackPtRegsOffset()
	if discoveryErr != nil {
		log.Warnf("HotSpot custom unwinding unavailable: %v", discoveryErr)
	}

	object, err := bpf.LoadBPFWithOptions(javaStackObjectName, &bpf.LoadOptions{
		Constants: map[string]any{
			"java_stack_capture_enabled": uint32(1),
			"java_stack_discovery_pid":   uint32(0),
			"java_stack_ptregs_offset":   ptRegsOffset,
		},
		MapReplacements: map[string]bpf.MapReplacement{
			sharedOOMVictimsMap: {Source: oomObject},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("javastack: load capture BPF: %w", err)
	}

	controllerCtx, cancel := context.WithCancel(ctx)
	c := &Controller{
		ctx: controllerCtx, cancel: cancel, registry: registry, object: object,
		period: opts.ReconcilePeriod, inspect: opts.InspectTarget,
		targetsMapID:  object.MapIDByName(javaTargetsMapName),
		capturesMapID: object.MapIDByName(javaCapturesMapName),
		applied:       make(map[uint32]Target), retired: make(map[Identity]retiredTarget),
		inspectWarn: make(map[Identity]bool),
	}
	if c.targetsMapID == 0 || c.capturesMapID == 0 {
		_ = c.Close()
		return nil, errors.New("javastack: capture BPF is missing required maps")
	}
	c.reader, err = object.EventPipeByName(controllerCtx, javaEventsMapName, opts.PerfBufferSize)
	if err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("javastack: open capture event pipe: %w", err)
	}
	if _, err := c.Reconcile(controllerCtx); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("javastack: initial target reconciliation: %w", err)
	}
	if err := object.AttachWithOptions([]bpf.AttachOption{{
		ProgramName: "java_stack_signal_deliver", Symbol: "signal/signal_deliver",
	}}); err != nil {
		_ = c.Close()
		return nil, fmt.Errorf("javastack: attach signal tracepoint: %w", err)
	}
	return c, nil
}

// Reconcile makes the BPF target map match the registry snapshot.
func (c *Controller) Reconcile(ctx context.Context) (Changes, error) {
	c.reconcileMu.Lock()
	defer c.reconcileMu.Unlock()
	changes, err := c.registry.Reconcile(ctx)
	if err != nil {
		return Changes{}, err
	}
	desired := make(map[uint32]Target)
	for _, target := range c.registry.Snapshot() {
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
			delete(c.inspectWarn, identity)
		}
	}
	for pid, current := range c.applied {
		target, ok := desired[pid]
		if ok && target.Identity == current.Identity {
			continue
		}
		if err := c.object.DeleteMapItems(c.targetsMapID, [][]byte{uint32Key(pid)}); err != nil {
			return fmt.Errorf("javastack: delete target %d: %w", pid, err)
		}
		delete(c.applied, pid)
		c.retired[current.Identity] = retiredTarget{current, now.Add(retiredTargetRetention)}
	}
	for pid, target := range desired {
		if current, ok := c.applied[pid]; ok && current == target {
			continue
		}
		metadata, err := c.inspect(target)
		if err != nil {
			if !c.inspectWarn[target.Identity] {
				log.Warnf("HotSpot direct metadata unavailable for pid %d: %v", pid, err)
				c.inspectWarn[target.Identity] = true
			}
			continue
		}
		bpfTarget := abi.JavaStackTarget{
			StartTimeTicks:       target.StartTimeTicks,
			HeapCount:            metadata.HeapCount,
			NmethodMethod:        metadata.NmethodMethod,
			NmethodCompileID:     metadata.NmethodCompileID,
			ConstantPoolSize:     metadata.ConstantPoolSize,
			KlassName:            metadata.KlassName,
			SegmentShift:         metadata.SegmentShift,
			HeapBlockSize:        metadata.HeapBlockSize,
			CodeblobName:         metadata.CodeBlobName,
			MethodConstMethod:    metadata.MethodConstMethod,
			ConstMethodConstants: metadata.ConstMethodConstants,
			ConstMethodNameIndex: metadata.ConstMethodNameIndex,
			ConstantPoolHolder:   metadata.ConstantPoolHolder,
			SymbolLength:         metadata.SymbolLength,
			SymbolBody:           metadata.SymbolBody,
		}
		for index := range metadata.Heaps {
			bpfTarget.Heaps[index] = abi.JavaStackHotspotCodeHeap{
				CodeStart:   metadata.Heaps[index].CodeStart,
				CodeEnd:     metadata.Heaps[index].CodeEnd,
				SegmapStart: metadata.Heaps[index].SegmapStart,
				SegmapEnd:   metadata.Heaps[index].SegmapEnd,
			}
		}
		value, err := nativeBytes(bpfTarget)
		if err != nil {
			return err
		}
		if err := c.object.WriteMapItems(c.targetsMapID, []bpf.MapItem{{
			Key: uint32Key(pid), Value: value,
		}}); err != nil {
			return fmt.Errorf("javastack: write target %d: %w", pid, err)
		}
		c.applied[pid] = target
		delete(c.retired, target.Identity)
		delete(c.inspectWarn, target.Identity)
	}
	return nil
}

// ReadSnapshot validates and copies one perf event before acknowledging it.
func (c *Controller) ReadSnapshot() (snapshot *Snapshot, err error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	var event abi.JavaStackEvent
	if err := c.reader.ReadInto(&event); err != nil {
		return nil, err
	}
	defer func() {
		key, keyErr := nativeBytes(abi.JavaStackCaptureKey{
			VictimTGID: event.VictimTGID, OOMTimestamp: event.OOMTimestamp,
		})
		if keyErr != nil {
			err = errors.Join(err, keyErr)
			return
		}
		ackErr := c.object.DeleteMapItems(c.capturesMapID, [][]byte{key})
		if ackErr != nil {
			err = errors.Join(err, fmt.Errorf("javastack: acknowledge capture: %w", ackErr))
		}
	}()

	identity := Identity{PID: event.VictimTGID, StartTimeTicks: event.StartTimeTicks}
	target, ok := c.targetFor(identity)
	if !ok {
		return nil, fmt.Errorf("javastack: target pid=%d start_ticks=%d is no longer known", identity.PID, identity.StartTimeTicks)
	}
	if event.StackSize > int32(len(event.Ips)*8) || (event.StackSize > 0 && event.StackSize%8 != 0) {
		return nil, fmt.Errorf("javastack: invalid stack size %d", event.StackSize)
	}
	pcCount := 0
	if event.StackSize > 0 {
		pcCount = int(event.StackSize / 8)
	}
	pcs := append([]uint64(nil), event.Ips[:pcCount]...)
	if event.DirectFrameCount > uint32(len(event.DirectFrames)) ||
		event.DirectFrameCount > uint32(pcCount) ||
		event.DirectErrorCount > event.DirectFrameCount {
		return nil, fmt.Errorf("javastack: invalid direct frame counts %d/%d", event.DirectFrameCount, event.DirectErrorCount)
	}
	directFrames := make([]DirectFrame, 0, event.DirectFrameCount)
	for index := uint32(0); index < event.DirectFrameCount; index++ {
		frame := event.DirectFrames[index]
		if frame.Pc != event.Ips[index] ||
			frame.ClassNameLen > uint16(len(frame.ClassName)) ||
			frame.MethodNameLen > uint16(len(frame.MethodName)) {
			return nil, fmt.Errorf("javastack: invalid direct frame %d", index)
		}
		directFrames = append(directFrames, DirectFrame{
			PC: frame.Pc, CompileID: frame.CompileID, Flags: frame.Flags,
			ClassName:  string(frame.ClassName[:frame.ClassNameLen]),
			MethodName: string(frame.MethodName[:frame.MethodNameLen]),
		})
	}
	return &Snapshot{
		Target: target, OOMTimestamp: event.OOMTimestamp,
		CaptureTimestamp:  event.CaptureTimestamp,
		CaptureDurationNS: event.CaptureDurationNS, CgroupID: event.CgroupID,
		VictimTID: event.VictimTID, StackSize: event.StackSize,
		Flags: event.Flags, PCs: pcs, DirectFrames: directFrames,
		DirectErrorCount: event.DirectErrorCount,
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

// Run reconciles targets and delivers snapshots until cancellation.
func (c *Controller) Run(handler func(snapshot *Snapshot) error) error {
	if handler == nil {
		return errors.New("javastack: nil snapshot handler")
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
					log.Warnf("Java stack target reconciliation failed: %v", err)
				}
			}
		}
	}()
	for {
		snapshot, err := c.ReadSnapshot()
		if err != nil {
			if c.ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, bpf.ErrPerfEventSamplesLost) {
				log.WithError(err).Warn("lost Java stack BPF perf event samples")
				continue
			}
			return err
		}
		if err := handler(snapshot); err != nil {
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

func nativeBytes(value any) ([]byte, error) {
	var output bytes.Buffer
	if err := binary.Write(&output, binary.NativeEndian, value); err != nil {
		return nil, fmt.Errorf("javastack: encode BPF value: %w", err)
	}
	return output.Bytes(), nil
}

func uint32Key(value uint32) []byte {
	key := make([]byte, 4)
	binary.NativeEndian.PutUint32(key, value)
	return key
}
