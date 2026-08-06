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
	"testing"
	"time"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/bpf/abi"
)

type fakeReader struct {
	event abi.JavaStackEvent
	err   error
}

func (r *fakeReader) ReadInto(value any) error {
	if r.err != nil {
		return r.err
	}
	*value.(*abi.JavaStackEvent) = r.event
	return nil
}

func (*fakeReader) ReadBatch(func() any) ([]any, error) { return nil, errors.New("unused") }
func (*fakeReader) Close() error                        { return nil }

type fakeObject struct {
	deleted [][]byte
}

func (*fakeObject) MapIDByName(string) uint32                  { return 1 }
func (*fakeObject) AttachWithOptions([]bpf.AttachOption) error { return nil }
func (*fakeObject) EventPipeByName(context.Context, string, uint32) (bpf.PerfEventReader, error) {
	return nil, errors.New("unused")
}
func (*fakeObject) WriteMapItems(uint32, []bpf.MapItem) error { return nil }
func (o *fakeObject) DeleteMapItems(_ uint32, keys [][]byte) error {
	o.deleted = append(o.deleted, keys...)
	return nil
}
func (*fakeObject) Close() error { return nil }

func TestReadSnapshotCopiesOnlyValidPCsAndAcknowledges(t *testing.T) {
	target := Target{Identity: Identity{PID: 42, StartTimeTicks: 99}}
	event := abi.JavaStackEvent{
		OOMTimestamp: 10, CaptureTimestamp: 20, StartTimeTicks: 99,
		VictimTGID: 42, VictimTID: 43, StackSize: 16, Flags: CaptureFlagCaptured,
	}
	event.Ips[0], event.Ips[1], event.Ips[2] = 0x1000, 0x2000, 0xdead
	event.DirectFrameCount = 1
	event.DirectFrames[0].Pc = event.Ips[0]
	event.DirectFrames[0].Flags = DirectFrameResolved
	event.DirectFrames[0].ClassNameLen = 8
	event.DirectFrames[0].MethodNameLen = 3
	copy(event.DirectFrames[0].ClassName[:], "demo/App")
	copy(event.DirectFrames[0].MethodName[:], "run")
	object := &fakeObject{}
	c := &Controller{
		object: object, reader: &fakeReader{event: event}, capturesMapID: 2,
		applied: map[uint32]Target{42: target}, retired: make(map[Identity]retiredTarget),
	}
	snapshot, err := c.ReadSnapshot()
	if err != nil {
		t.Fatalf("ReadSnapshot: %v", err)
	}
	if len(snapshot.PCs) != 2 || snapshot.PCs[1] != 0x2000 {
		t.Fatalf("PCs = %#x", snapshot.PCs)
	}
	if len(snapshot.DirectFrames) != 1 ||
		snapshot.DirectFrames[0].ClassName != "demo/App" ||
		snapshot.DirectFrames[0].MethodName != "run" {
		t.Fatalf("direct frames = %+v", snapshot.DirectFrames)
	}
	if len(object.deleted) != 1 {
		t.Fatalf("acknowledgements = %d, want 1", len(object.deleted))
	}
	var captureKey abi.JavaStackCaptureKey
	if err := binary.Read(bytes.NewReader(object.deleted[0]), binary.NativeEndian, &captureKey); err != nil {
		t.Fatalf("decode capture key: %v", err)
	}
	if captureKey.VictimTGID != 42 || captureKey.OOMTimestamp != 10 {
		t.Fatalf("capture key = %+v", captureKey)
	}
}

func TestReadSnapshotRejectsInvalidLengthAndAcceptsRetiredTarget(t *testing.T) {
	target := Target{Identity: Identity{PID: 42, StartTimeTicks: 99}}
	object := &fakeObject{}
	c := &Controller{
		object: object, capturesMapID: 2, applied: make(map[uint32]Target),
		retired: map[Identity]retiredTarget{
			target.Identity: {target: target, expiresAt: time.Now().Add(time.Second)},
		},
	}
	c.reader = &fakeReader{event: abi.JavaStackEvent{
		VictimTGID: 42, StartTimeTicks: 99, StackSize: 7,
	}}
	if _, err := c.ReadSnapshot(); err == nil {
		t.Fatal("ReadSnapshot accepted a non-PC-aligned stack")
	}
	if len(object.deleted) != 1 {
		t.Fatalf("acknowledgements = %d, want 1", len(object.deleted))
	}
}
