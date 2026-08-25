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

package python

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"huatuo-bamai/internal/memsnap"
)

type sparseMemory map[uint64]byte

type countingMemory struct {
	memoryReader
	reads map[uint64]int
}

type boundedReadMemory struct {
	sparseMemory
	maxRead int
}

func (m boundedReadMemory) read(address uint64, size int) ([]byte, error) {
	if size > m.maxRead {
		return nil, errors.New("read crosses mapping boundary")
	}
	return m.sparseMemory.read(address, size)
}

func (m *countingMemory) read(address uint64, size int) ([]byte, error) {
	m.reads[address]++
	return m.memoryReader.read(address, size)
}

type readIntoFailureMemory struct {
	memoryReader
	failAddress uint64
}

func (m readIntoFailureMemory) readInto(address uint64,
	destination []byte,
) error {
	if address == m.failAddress {
		return errors.New("injected owned-buffer read failure")
	}
	return m.memoryReader.readInto(address, destination)
}

func (m sparseMemory) read(address uint64, size int) ([]byte, error) {
	result := make([]byte, size)
	_ = m.readInto(address, result)
	return result, nil
}

func (m sparseMemory) readInto(address uint64, destination []byte) error {
	for offset := range destination {
		destination[offset] = m[address+uint64(offset)]
	}
	return nil
}

func (m sparseMemory) put(address uint64, data []byte) {
	for offset, value := range data {
		m[address+uint64(offset)] = value
	}
}

func (m sparseMemory) put64(address, value uint64) {
	raw := make([]byte, 8)
	binary.LittleEndian.PutUint64(raw, value)
	m.put(address, raw)
}

func (m sparseMemory) put32(address uint64, value uint32) {
	raw := make([]byte, 4)
	binary.LittleEndian.PutUint32(raw, value)
	m.put(address, raw)
}

func putDebugHeader(memory sparseMemory, runtimeAddress uint64, minor int) {
	layout := runtimeLayouts[minor]
	memory.put(runtimeAddress, []byte("xdebugpy"))
	memory.put64(runtimeAddress+debugVersion,
		uint64(uint32(3<<24|minor<<16)))
	memory.put64(runtimeAddress+layout.debugObjectType, pyObjectTypeOffset)
	memory.put64(runtimeAddress+layout.debugTypeName, pyTypeNameOffset)
	memory.put64(runtimeAddress+layout.debugTypeFlags, pyTypeFlagsOffset)
}

func putGenerationHeads(memory sparseMemory, firstHead uint64, threshold uint32) {
	for generation, value := range []uint32{threshold, 10, 10} {
		head := firstHead + uint64(generation)*pyGenerationSize
		memory.put64(head, head)
		memory.put64(head+8, head)
		memory.put32(head+16, value)
	}
}

func cpython312Interpreters(cycle bool) (sparseMemory, uint64, uint64, uint64) {
	memory := sparseMemory{}
	const runtimeAddress = uint64(0x10000)
	const firstInterpreter = uint64(0x20000)
	const secondInterpreter = uint64(0x30000)
	memory.put64(runtimeAddress+40, firstInterpreter)
	memory.put64(firstInterpreter, secondInterpreter)
	if cycle {
		memory.put64(secondInterpreter, firstInterpreter)
	}
	putGenerationHeads(memory, firstInterpreter+136, 700)
	putGenerationHeads(memory, secondInterpreter+136, 700)
	return memory, runtimeAddress, firstInterpreter, secondInterpreter
}

func newTestScanner(memory memoryReader, target *image,
	deadline time.Time,
) *scanner {
	targetCopy := *target
	if targetCopy.layout.interpreterMode == interpreterLayoutUnknown {
		targetCopy.layout, _ = layoutFor(targetCopy.version)
	}
	if targetCopy.layout.objectTypeOffset == 0 {
		targetCopy.layout.objectTypeOffset = pyObjectTypeOffset
		targetCopy.layout.objectSizeOffset = pyObjectSizeOffset
		targetCopy.layout.typeNameOffset = pyTypeNameOffset
		targetCopy.layout.typeFlagsOffset = pyTypeFlagsOffset
	}
	return newScanner(memory, &targetCopy, deadline)
}

func TestAllInterpreters(t *testing.T) {
	memory, runtimeAddress, firstInterpreter, secondInterpreter := cpython312Interpreters(false)
	census := newTestScanner(memory, &image{
		version:        version{major: 3, minor: 12, micro: 3},
		runtimeAddress: runtimeAddress, order: binary.LittleEndian,
	}, zeroTime())

	interpreters, err := census.findInterpreters()
	if err != nil {
		t.Fatal(err)
	}
	if len(interpreters) != 2 ||
		interpreters[0].heads[0] != firstInterpreter+136 ||
		interpreters[1].heads[0] != secondInterpreter+136 {
		t.Fatalf("interpreters=%+v, want both CPython 3.12 interpreters",
			interpreters)
	}
}

func TestInterpreterCycle(t *testing.T) {
	memory, runtimeAddress, _, _ := cpython312Interpreters(true)
	census := newTestScanner(memory, &image{
		version: version{major: 3, minor: 12}, runtimeAddress: runtimeAddress,
		order: binary.LittleEndian,
	}, zeroTime())

	_, err := census.findInterpreters()
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("error=%v, want interpreter cycle rejection", err)
	}
}

func TestInterpreterBound(t *testing.T) {
	memory := sparseMemory{}
	const firstInterpreter = uint64(0x10000)
	const interpreterStride = uint64(0x1000)
	for index := 0; index < maxInterpreterCount; index++ {
		interpreter := firstInterpreter + uint64(index)*interpreterStride
		memory.put64(interpreter, interpreter+interpreterStride)
		putGenerationHeads(memory, interpreter+136, 700)
	}
	census := newTestScanner(memory, &image{
		version: version{major: 3, minor: 12}, order: binary.LittleEndian,
	}, zeroTime())

	_, err := census.interpreterList(firstInterpreter, 0, 112)
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("error=%v, want interpreter-count bound", err)
	}
}

func TestDebugOffsets(t *testing.T) {
	for _, test := range []struct {
		minor     int
		threshold uint32
	}{{minor: 13, threshold: 700}, {minor: 14, threshold: 2000}} {
		t.Run(fmt.Sprintf("CPython3.%d", test.minor), func(t *testing.T) {
			memory := sparseMemory{}
			const runtimeAddress = uint64(0x10000)
			const interpreterAddress = uint64(0x20000)
			const runtimeHeadOffset = uint64(632)
			const interpreterNextOffset = uint64(7264)
			const interpreterGCOffset = uint64(7400)
			putDebugHeader(memory, runtimeAddress, test.minor)
			memory.put64(runtimeAddress+debugRuntimeHead, runtimeHeadOffset)
			memory.put64(runtimeAddress+debugInterpreterSize, 9000)
			memory.put64(runtimeAddress+debugInterpreterNext, interpreterNextOffset)
			memory.put64(runtimeAddress+runtimeLayouts[test.minor].debugInterpreterGC,
				interpreterGCOffset)
			memory.put64(runtimeAddress+runtimeHeadOffset, interpreterAddress)
			memory.put64(interpreterAddress+interpreterNextOffset, 0)
			firstHead := interpreterAddress + interpreterGCOffset + gcGenerationsOffset
			putGenerationHeads(memory, firstHead, test.threshold)
			census := newTestScanner(memory, &image{
				version:        version{major: 3, minor: test.minor},
				runtimeAddress: runtimeAddress, order: binary.LittleEndian,
			}, zeroTime())

			interpreters, err := census.findInterpreters()
			if err != nil {
				t.Fatal(err)
			}
			if len(interpreters) != 1 || interpreters[0].heads[0] != firstHead {
				t.Fatalf("interpreters=%+v, want first head %#x", interpreters, firstHead)
			}
		})
	}
}

func TestFreeThreadedRuntime(t *testing.T) {
	memory := sparseMemory{}
	runtimeAddress := uint64(0x10000)
	putDebugHeader(memory, runtimeAddress, 14)
	memory.put64(runtimeAddress+debugFreeThreaded, 1)
	census := newTestScanner(memory, &image{
		version: version{major: 3, minor: 14}, runtimeAddress: runtimeAddress,
		order: binary.LittleEndian,
	}, zeroTime())

	_, err := census.findInterpreters()
	if !errors.Is(err, errUnsupportedRuntime) {
		t.Fatalf("error=%v, want errUnsupportedRuntime", err)
	}
}

func TestMissingDebugOffsets(t *testing.T) {
	census := newTestScanner(sparseMemory{}, &image{
		version: version{major: 3, minor: 13}, order: binary.LittleEndian,
	}, zeroTime())

	_, err := census.findInterpreters()
	if !errors.Is(err, errUnsupportedRuntime) {
		t.Fatalf("error=%v, want errUnsupportedRuntime", err)
	}
}

func TestInterpreterMappingBoundary(t *testing.T) {
	const interpreter = uint64(0x10000)
	const generationOffset = uint64(128)
	backing := sparseMemory{}
	for generation := 0; generation < 3; generation++ {
		head := interpreter + generationOffset + uint64(generation)*pyGenerationSize
		backing.put64(head, head)
		backing.put64(head+8, head)
	}
	backing.put32(interpreter+generationOffset+16, 700)
	memory := boundedReadMemory{sparseMemory: backing, maxRead: 512}
	census := newTestScanner(memory, &image{
		version: version{major: 3, minor: 10}, order: binary.LittleEndian,
	}, zeroTime())

	heads, _, err := census.probeInterpreter(interpreter)
	if err != nil {
		t.Fatal(err)
	}
	if heads.heads[0] != interpreter+generationOffset {
		t.Fatalf("generation head=%#x, want %#x", heads.heads[0],
			interpreter+generationOffset)
	}
}

func TestPermanentGeneration(t *testing.T) {
	const first = uint64(0x10000)
	for _, test := range []struct {
		minor           int
		permanentOffset uint64
	}{
		{minor: 13, permanentOffset: 3*pyGenerationSize + 8},
		{minor: 14, permanentOffset: 3 * pyGenerationSize},
	} {
		census := newTestScanner(sparseMemory{}, &image{
			version: version{major: 3, minor: test.minor},
			order:   binary.LittleEndian,
		}, zeroTime())
		heads := census.generationHeads(first)
		if heads.heads[3] != first+test.permanentOffset {
			t.Fatalf("CPython 3.%d permanent head=%#x, want %#x", test.minor,
				heads.heads[3], first+test.permanentOffset)
		}
	}
}

func TestGCTraversal(t *testing.T) {
	memory := sparseMemory{}
	head := uint64(0x10000)
	first := uint64(0x20000)
	second := uint64(0x21000)
	memory.put64(head, first)
	memory.put64(head+8, second)
	memory.put64(first, second)
	memory.put64(first+8, head)
	memory.put64(second, head)
	memory.put64(second+8, first)

	census := newTestScanner(memory, &image{
		version: version{major: 3, minor: 12},
		order:   binary.LittleEndian,
	}, zeroTime())
	if !census.walkGeneration(context.Background(), head) {
		t.Fatalf("traversal failed: %s", census.partial)
	}
	if census.scannedObjects != 2 {
		t.Fatalf("scanned=%d, want 2", census.scannedObjects)
	}
}

func TestGCDeadline(t *testing.T) {
	memory := sparseMemory{}
	head := uint64(0x10000)
	object := uint64(0x20000)
	memory.put64(head, object)
	memory.put64(head+8, object)
	memory.put64(object, head)
	memory.put64(object+8, head)

	census := newTestScanner(memory, &image{
		version: version{major: 3, minor: 12}, order: binary.LittleEndian,
	}, time.Now().Add(-time.Second))
	if census.walkGeneration(context.Background(), head) ||
		!strings.Contains(census.partial, "deadline reached") ||
		census.scannedObjects != 0 {
		t.Fatalf("partial=%q scanned=%d", census.partial,
			census.scannedObjects)
	}
}

func TestGCObjectSafetyLimit(t *testing.T) {
	memory := sparseMemory{}
	head := uint64(0x10000)
	object := uint64(0x20000)
	memory.put64(head, object)
	memory.put64(head+8, object)
	memory.put64(object, head)
	memory.put64(object+8, head)
	census := newTestScanner(memory, &image{
		version: version{major: 3, minor: 12}, order: binary.LittleEndian,
	}, zeroTime())
	census.scannedObjects = maxScannedObjects
	if census.walkGeneration(context.Background(), head) ||
		!strings.Contains(census.partial, "safety limit") {
		t.Fatalf("object limit not enforced: %q", census.partial)
	}
}

type mutatingMemory struct {
	sparseMemory
	head      uint64
	headReads int
	mutate    func()
}

func (m *mutatingMemory) read(address uint64, size int) ([]byte, error) {
	result := make([]byte, size)
	if err := m.readInto(address, result); err != nil {
		return nil, err
	}
	return result, nil
}

func (m *mutatingMemory) readInto(address uint64, destination []byte) error {
	if address == m.head && len(destination) == 16 {
		m.headReads++
		if m.headReads == 2 && m.mutate != nil {
			m.mutate()
		}
	}
	return m.sparseMemory.readInto(address, destination)
}

func TestGCEndpointMutation(t *testing.T) {
	backing := sparseMemory{}
	head := uint64(0x10000)
	first := uint64(0x20000)
	inserted := uint64(0x21000)
	backing.put64(head, first)
	backing.put64(head+8, first)
	backing.put64(first, head)
	backing.put64(first+8, head)
	memory := &mutatingMemory{sparseMemory: backing, head: head}
	memory.mutate = func() {
		backing.put64(first, inserted)
		backing.put64(inserted, head)
		backing.put64(inserted+8, first)
		backing.put64(head+8, inserted)
	}
	census := newTestScanner(memory, &image{
		version: version{major: 3, minor: 12}, order: binary.LittleEndian,
	}, zeroTime())

	if census.walkGeneration(context.Background(), head) ||
		!strings.Contains(census.partial, "changed") {
		t.Fatalf("traversal succeeded with endpoint mutation: %q", census.partial)
	}
}

func TestMalformedGeneration(t *testing.T) {
	memory := sparseMemory{}
	head := uint64(0x10000)
	memory.put64(head, head)
	memory.put64(head+8, 0x20000)
	census := newTestScanner(memory, &image{
		version: version{major: 3, minor: 12}, order: binary.LittleEndian,
	}, zeroTime())

	if census.walkGeneration(context.Background(), head) ||
		!strings.Contains(census.partial, "endpoints") {
		t.Fatalf("malformed empty generation accepted: %q", census.partial)
	}
}

func TestGCTraversalAllocations(t *testing.T) {
	memory := sparseMemory{}
	head := uint64(0x10000)
	const objectCount = 256
	const typeAddress = uint64(0x50000)
	first := uint64(0x20000)
	previous := head
	for index := 0; index < objectCount; index++ {
		address := first + uint64(index)*0x100
		next := head
		if index+1 < objectCount {
			next = address + 0x100
		}
		memory.put64(address, next)
		memory.put64(address+8, previous)
		memory.put64(address+pyGCHeadSize+pyObjectTypeOffset, typeAddress)
		previous = address
	}
	memory.put64(head, first)
	memory.put64(head+8, previous)
	census := newTestScanner(memory, &image{
		version: version{major: 3, minor: 12}, order: binary.LittleEndian,
	}, zeroTime())
	census.types[typeAddress] = typeInfo{
		address: typeAddress, name: "fixture.Payload", basicsize: 32,
	}
	if !census.walkGeneration(context.Background(), head) {
		t.Fatalf("warm-up traversal failed: %s", census.partial)
	}
	var traversed bool
	allocations := testing.AllocsPerRun(10, func() {
		census.scannedObjects = 0
		census.partial = ""
		traversed = census.walkGeneration(context.Background(), head)
	})
	if !traversed {
		t.Fatalf("traversal failed: %s", census.partial)
	}
	if allocations > 2 {
		t.Fatalf("traversal allocations=%v for %d objects", allocations,
			objectCount)
	}
}

func TestCensusResponse(t *testing.T) {
	census := newTestScanner(sparseMemory{}, &image{
		version: version{major: 3, minor: 12}, order: binary.LittleEndian,
	}, zeroTime())
	census.skippedObjects = 2
	census.aggregates[0x10000] = &memsnap.ObjectAggregate{
		TypeName: "builtins.list", Count: 4, ShallowBytes: 320,
	}

	response := census.response()
	if response.Status != memsnap.StatusPartial ||
		!strings.Contains(response.Reason, "2 GC-tracked objects") {
		t.Fatalf("response=%+v", response)
	}
	if len(response.Entries) != 1 ||
		response.Entries[0].Kind != "gc_tracked_object_type" {
		t.Fatalf("entries=%+v", response.Entries)
	}
}

func TestCompactDictKeys(t *testing.T) {
	memory := sparseMemory{}
	keys := uint64(0x30000)
	firstName := uint64(0x40000)
	secondName := uint64(0x41000)
	memory.put(keys+8, []byte{3, 3, 2}) // size=8, indices bytes=8, split keys
	memory.put64(keys+24, 2)
	memory.put64(keys+40, firstName)
	memory.put64(keys+56, secondName)
	putASCIIUnicode(memory, firstName, "payload", 40)
	putASCIIUnicode(memory, secondName, "owner", 40)
	census := newTestScanner(memory, &image{
		version: version{major: 3, minor: 12}, order: binary.LittleEndian,
	},
		zeroTime())

	entries, err := census.dictEntries(keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].name != "payload" ||
		entries[1].name != "owner" {
		t.Fatalf("entries=%+v", entries)
	}
}

func TestCPython38Generations(t *testing.T) {
	memory := sparseMemory{}
	runtimeAddress := uint64(0x10000)
	firstHead := runtimeAddress + 368 // runtime.gc + gc.generations in 3.8
	for generation, threshold := range []uint32{700, 10, 10} {
		head := firstHead + uint64(generation)*pyGenerationSize
		memory.put64(head, head)
		memory.put64(head+8, head)
		memory.put32(head+16, threshold)
	}
	census := newTestScanner(memory, &image{
		version:        version{major: 3, minor: 8},
		runtimeAddress: runtimeAddress, order: binary.LittleEndian,
	}, zeroTime())

	interpreters, err := census.findInterpreters()
	if err != nil {
		t.Fatal(err)
	}
	if len(interpreters) != 1 || interpreters[0].heads[0] != firstHead {
		t.Fatalf("generations=%+v, want first head %#x", interpreters, firstHead)
	}
}

func TestLegacyDictKeys(t *testing.T) {
	memory := sparseMemory{}
	keys := uint64(0x50000)
	firstName := uint64(0x60000)
	secondName := uint64(0x61000)
	memory.put64(keys+8, 8)
	memory.put64(keys+24, 4)
	memory.put64(keys+32, 2)
	firstEntry := keys + 48
	memory.put64(firstEntry, 123)
	memory.put64(firstEntry+8, firstName)
	memory.put64(firstEntry+16, 0x70000)
	memory.put64(firstEntry+24, 456)
	memory.put64(firstEntry+32, secondName)
	memory.put64(firstEntry+40, 0x71000)
	putASCIIUnicode(memory, firstName, "payload", 48)
	putASCIIUnicode(memory, secondName, "owner", 48)
	census := newTestScanner(memory, &image{
		version: version{major: 3, minor: 9}, order: binary.LittleEndian,
	}, zeroTime())

	entries, err := census.dictEntries(keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].name != "payload" ||
		entries[0].value != 0x70000 || entries[1].name != "owner" {
		t.Fatalf("entries=%+v", entries)
	}
}

func TestLegacyVersionPath(t *testing.T) {
	version, err := versionFromModulePath(
		"/proc/42/root/lib64/libpython3.9.so.1.0")
	if err != nil {
		t.Fatal(err)
	}
	if version.String() != "3.9.x" {
		t.Fatalf("version=%s", version.String())
	}
}

func putASCIIUnicode(memory sparseMemory, address uint64, value string,
	dataOffset uint64,
) {
	memory.put64(address+16, uint64(len(value)))
	memory.put32(address+32, (1<<5)|(1<<6))
	memory.put(address+dataOffset, []byte(value))
}

func zeroTime() (result time.Time) { return result }

func TestListSubclassSize(t *testing.T) {
	memory := sparseMemory{}
	census := newTestScanner(memory, &image{
		order: binary.LittleEndian,
	}, zeroTime())
	const (
		listBase      = uint64(0x10000)
		typeAddress   = uint64(0x11000)
		objectAddress = uint64(0x20000)
	)
	census.types[listBase] = typeInfo{
		address: listBase, name: "builtins.list", basicsize: 40,
	}
	typeInfo := typeInfo{
		address: typeAddress, name: "fixture.ListSubclass", basicsize: 48,
		flags: pyTPFlagsManagedDict, base: listBase,
	}
	census.types[typeAddress] = typeInfo
	memory.put64(objectAddress+24, 0x21000)
	memory.put64(objectAddress+32, 16384)
	objectHead := make([]byte, 24)
	binary.LittleEndian.PutUint64(objectHead[pyObjectSizeOffset:], 1)
	total := census.objectSize(objectAddress, objectHead, typeInfo)
	expectedShell := alignUp(uint64(typeInfo.basicsize), 8) + pyGCHeadSize + 16
	const owned = uint64(16384 * 8)
	if total != expectedShell+owned {
		t.Fatalf("total=%d, want %d", total, expectedShell+owned)
	}
}

func TestVariableObjectSize(t *testing.T) {
	census := newTestScanner(sparseMemory{}, &image{order: binary.LittleEndian},
		zeroTime())
	objectHead := make([]byte, 24)
	binary.LittleEndian.PutUint64(objectHead[pyObjectSizeOffset:], 7)
	typeInfo := typeInfo{basicsize: 24, itemsize: 8}
	if size := census.objectSize(0x10000, objectHead, typeInfo); size != 96 {
		t.Fatalf("size=%d, want 96", size)
	}
}

func TestDistinctSameNameTypes(t *testing.T) {
	census := newTestScanner(sparseMemory{}, &image{order: binary.LittleEndian},
		zeroTime())
	const firstType = uint64(0x10000)
	const secondType = uint64(0x11000)
	census.types[firstType] = typeInfo{
		address: firstType, name: "fixture.Duplicate", basicsize: 32,
	}
	census.types[secondType] = typeInfo{
		address: secondType, name: "fixture.Duplicate", basicsize: 48,
	}
	firstHead := make([]byte, 24)
	secondHead := make([]byte, 24)
	binary.LittleEndian.PutUint64(firstHead[pyObjectTypeOffset:], firstType)
	binary.LittleEndian.PutUint64(secondHead[pyObjectTypeOffset:], secondType)
	census.addObject(0x20000, firstHead)
	census.addObject(0x21000, secondHead)

	results := census.entries()
	if len(results) != 2 || results[0].Name != "fixture.Duplicate" ||
		results[1].Name != "fixture.Duplicate" {
		t.Fatalf("same-name type identities were merged: %+v", results)
	}
}

func TestStableCensusOrder(t *testing.T) {
	census := newTestScanner(sparseMemory{}, &image{order: binary.LittleEndian},
		zeroTime())
	census.aggregates[1] = &memsnap.ObjectAggregate{
		TypeName: "fixture.Z", Count: 1, ShallowBytes: 64,
	}
	census.aggregates[2] = &memsnap.ObjectAggregate{
		TypeName: "fixture.A", Count: 1, ShallowBytes: 64,
	}
	results := census.entries()
	if len(results) != 2 || results[0].Name != "fixture.A" {
		t.Fatalf("results=%+v", results)
	}
}

func TestQualifiedTypeNameCache(t *testing.T) {
	const (
		typeAddress = uint64(0x10000)
		nameAddress = uint64(0x20000)
	)
	contents := sparseMemory{}
	contents.put64(typeAddress+pyTypeNameOffset, nameAddress)
	contents.put64(typeAddress+pyTypeBasicOffset, 32)
	contents.put(nameAddress, []byte("fixture.Qualified\x00"))
	memory := &countingMemory{
		memoryReader: contents, reads: make(map[uint64]int),
	}
	census := newTestScanner(memory, &image{order: binary.LittleEndian},
		zeroTime())

	first, err := census.typeInfo(typeAddress)
	if err != nil {
		t.Fatal(err)
	}
	second, err := census.typeInfo(typeAddress)
	if err != nil {
		t.Fatal(err)
	}
	if first.name != "fixture.Qualified" || second.name != first.name {
		t.Fatalf("type names=%q and %q", first.name, second.name)
	}
	if memory.reads[typeAddress] != 1 {
		t.Fatalf("type metadata reads=%d, want 1", memory.reads[typeAddress])
	}
}

func TestOwnedBufferReadFailure(t *testing.T) {
	const (
		typeAddress   = uint64(0x10000)
		objectAddress = uint64(0x20000)
	)
	contents := sparseMemory{}
	memory := readIntoFailureMemory{
		memoryReader: contents, failAddress: objectAddress + 24,
	}
	census := newTestScanner(memory, &image{order: binary.LittleEndian},
		zeroTime())
	census.types[typeAddress] = typeInfo{
		address: typeAddress, name: "builtins.list", basicsize: 40,
	}
	objectHead := make([]byte, 24)
	binary.LittleEndian.PutUint64(objectHead[pyObjectTypeOffset:], typeAddress)
	census.addObject(objectAddress, objectHead)

	response := census.response()
	if response.Status != memsnap.StatusComplete || response.Reason != "" {
		t.Fatalf("response=%+v, want complete census", response)
	}
	if len(response.Entries) != 1 || response.Entries[0].Objects != 1 ||
		response.Entries[0].Bytes != 56 {
		t.Fatalf("entries=%+v, want one base-size-only list", response.Entries)
	}
}
