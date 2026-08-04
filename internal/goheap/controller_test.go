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
	"context"
	"encoding/binary"
	"errors"
	"sync"
	"testing"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/bpf/abi"

	"github.com/stretchr/testify/require"
)

type sequenceDiscoverer struct {
	mu      sync.Mutex
	results [][]Target
}

func (d *sequenceDiscoverer) Discover(context.Context) ([]Target, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	result := d.results[0]
	if len(d.results) > 1 {
		d.results = d.results[1:]
	}
	return result, nil
}

type fakeCaptureObject struct {
	maps       map[uint32]map[string][]byte
	mapIDs     map[string]uint32
	deleteKeys [][]byte
	readErr    error
}

func newFakeCaptureObject() *fakeCaptureObject {
	return &fakeCaptureObject{
		maps: map[uint32]map[string][]byte{
			1: {}, 2: {}, 3: {},
		},
		mapIDs: map[string]uint32{
			goHeapTargetsMapName: 1,
			goHeapBucketsMapName: 2,
			goHeapControlMapName: 3,
		},
	}
}

func (f *fakeCaptureObject) MapIDByName(name string) uint32             { return f.mapIDs[name] }
func (f *fakeCaptureObject) AttachWithOptions([]bpf.AttachOption) error { return nil }
func (f *fakeCaptureObject) EventPipeByName(context.Context, string, uint32) (bpf.PerfEventReader, error) {
	return nil, errors.New("unused")
}
func (f *fakeCaptureObject) ReadMap(mapID uint32, key []byte) ([]byte, error) {
	if f.readErr != nil {
		return nil, f.readErr
	}
	return f.maps[mapID][string(key)], nil
}
func (f *fakeCaptureObject) WriteMapItems(mapID uint32, items []bpf.MapItem) error {
	for _, item := range items {
		f.maps[mapID][string(item.Key)] = append([]byte(nil), item.Value...)
	}
	return nil
}
func (f *fakeCaptureObject) DeleteMapItems(mapID uint32, keys [][]byte) error {
	for _, key := range keys {
		f.deleteKeys = append(f.deleteKeys, append([]byte(nil), key...))
		delete(f.maps[mapID], string(key))
	}
	return nil
}
func (f *fakeCaptureObject) Close() error { return nil }

type fakeCaptureReader struct {
	event abi.GoHeapEvent
	err   error
}

func (r *fakeCaptureReader) ReadInto(dst any) error {
	if r.err != nil {
		return r.err
	}
	*(dst.(*abi.GoHeapEvent)) = r.event
	return nil
}
func (r *fakeCaptureReader) ReadBatch(func() any) ([]any, error) { return nil, errors.New("unused") }
func (r *fakeCaptureReader) Close() error                        { return nil }

func newTestController(registry *Registry, object *fakeCaptureObject) *Controller {
	ctx, cancel := context.WithCancel(context.Background())
	return &Controller{
		ctx: ctx, cancel: cancel, registry: registry, object: object,
		targetsMapID: 1, bucketsMapID: 2, controlMapID: 3,
		applied: make(map[uint32]Target), retired: make(map[Identity]retiredTarget),
	}
}

func TestControllerReconcileTargets(t *testing.T) {
	first := Target{
		Identity: Identity{PID: 10, StartTimeTicks: 100}, GoVersion: "go1.24",
		Executable: "/first", SymbolAddress: 0x1000, LoadBias: 0x2000,
	}
	second := Target{
		Identity: Identity{PID: 20, StartTimeTicks: 200}, GoVersion: "go1.24",
		Executable: "/second", SymbolAddress: 0x4000,
	}
	updatedSecond := second
	updatedSecond.LoadBias = 0x3000
	discoverer := &sequenceDiscoverer{results: [][]Target{{first, second}, {updatedSecond}}}
	object := newFakeCaptureObject()
	c := newTestController(NewRegistry(discoverer, 10), object)

	changes, err := c.Reconcile(t.Context())
	require.NoError(t, err)
	require.Len(t, changes.Added, 2)

	var rawTarget abi.GoHeapTarget
	_, err = binary.Decode(object.maps[1][string(uint32Key(second.PID))], binary.NativeEndian, &rawTarget)
	require.NoError(t, err)
	require.Equal(t, second.MBucketsAddress(), rawTarget.MbucketsAddress)
	require.Equal(t, second.StartTimeTicks, rawTarget.StartTimeTicks)

	changes, err = c.Reconcile(t.Context())
	require.NoError(t, err)
	require.Equal(t, []Target{first}, changes.Removed)
	require.Equal(t, []Target{updatedSecond}, changes.Updated)
	require.NotContains(t, object.maps[1], string(uint32Key(first.PID)))
	_, retired := c.retired[first.Identity]
	require.True(t, retired)

	_, err = binary.Decode(object.maps[1][string(uint32Key(second.PID))], binary.NativeEndian, &rawTarget)
	require.NoError(t, err)
	require.Equal(t, updatedSecond.MBucketsAddress(), rawTarget.MbucketsAddress)
}

func TestControllerReadCaptureAndAcknowledge(t *testing.T) {
	target := Target{
		Identity: Identity{PID: 42, StartTimeTicks: 900}, GoVersion: "go1.24",
		Executable: "/go/app", SymbolAddress: 0x1000,
	}
	object := newFakeCaptureObject()
	c := newTestController(NewRegistry(&sequenceDiscoverer{results: [][]Target{{target}}}, 10), object)
	c.applied[target.PID] = target

	rawBucket := abi.GoHeapBucket{StackDepth: 2}
	rawBucket.Stack[0], rawBucket.Stack[1] = 0x111, 0x222
	rawBucket.Record.Active = abi.GoHeapMemCycle{Allocs: 7, Frees: 2, AllocBytes: 70, FreeBytes: 20}
	raw, err := nativeBytes(rawBucket)
	require.NoError(t, err)
	object.maps[2][string(uint32Key(0))] = raw
	object.maps[3][string(uint32Key(0))] = []byte{1}
	c.reader = &fakeCaptureReader{event: abi.GoHeapEvent{
		OOMTimestamp: 1234, CaptureStartedNS: 2000, CaptureDurationNS: 300,
		StartTimeTicks: target.StartTimeTicks, VictimTGID: target.PID,
		CaptureID: 77, BucketCount: 1, SkippedBuckets: 2, Flags: CaptureFlagComplete,
	}}

	capture, err := c.ReadCapture()
	require.NoError(t, err)
	require.Equal(t, target, capture.Target)
	require.Equal(t, uint64(1234), capture.OOMTimestamp)
	require.Equal(t, uint32(77), capture.CaptureID)
	require.Equal(t, CaptureFlagComplete, capture.Flags)
	require.Len(t, capture.Buckets, 1)
	require.Equal(t, uint64(2), capture.Buckets[0].StackDepth)
	require.Equal(t, uint64(0x222), capture.Buckets[0].Stack[1])
	require.Equal(t, uint64(7), capture.Buckets[0].Record.Active.Allocs)
	require.NotContains(t, object.maps[3], string(uint32Key(0)))
}

func TestControllerReadCaptureAcknowledgesInvalidEvent(t *testing.T) {
	object := newFakeCaptureObject()
	c := newTestController(NewRegistry(&sequenceDiscoverer{results: [][]Target{{}}}, 10), object)
	object.maps[3][string(uint32Key(0))] = []byte{1}
	c.reader = &fakeCaptureReader{event: abi.GoHeapEvent{BucketCount: MaxCaptureBuckets + 1}}

	_, err := c.ReadCapture()
	require.EqualError(t, err, "goheap: invalid bucket count 4097")
	require.NotContains(t, object.maps[3], string(uint32Key(0)))
}

func TestControllerTargetForDistinguishesPIDReuse(t *testing.T) {
	object := newFakeCaptureObject()
	c := newTestController(NewRegistry(&sequenceDiscoverer{results: [][]Target{{}}}, 10), object)
	oldTarget := Target{Identity: Identity{PID: 42, StartTimeTicks: 100}, Executable: "/old"}
	newTarget := Target{Identity: Identity{PID: 42, StartTimeTicks: 200}, Executable: "/new"}
	c.applied[newTarget.PID] = newTarget
	c.retired[oldTarget.Identity] = retiredTarget{target: oldTarget}

	got, ok := c.targetFor(oldTarget.Identity)
	require.True(t, ok)
	require.Equal(t, oldTarget, got)
	got, ok = c.targetFor(newTarget.Identity)
	require.True(t, ok)
	require.Equal(t, newTarget, got)
	_, ok = c.targetFor(Identity{PID: 42, StartTimeTicks: 300})
	require.False(t, ok)
}
