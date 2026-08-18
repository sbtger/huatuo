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
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

type sparseMemory map[uint64]byte

func (m sparseMemory) read(address uint64, size int) ([]byte, error) {
	result := make([]byte, size)
	for offset := range result {
		result[offset] = m[address+uint64(offset)]
	}
	return result, nil
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

type trackingBatchMemory struct {
	maxRanges int
	calls     int
}

type failingBatchMemory struct {
	failedAddress uint64
}

func (m *failingBatchMemory) read(address uint64, size int) ([]byte, error) {
	if address == m.failedAddress {
		return nil, errors.New("fixture pool is unreadable")
	}
	return make([]byte, size), nil
}

func (*failingBatchMemory) readMany([]memoryRange) ([][]byte, error) {
	return nil, errors.New("fixture batch read failed")
}

func (m *trackingBatchMemory) read(_ uint64, size int) ([]byte, error) {
	return make([]byte, size), nil
}

func (m *trackingBatchMemory) readMany(ranges []memoryRange) ([][]byte, error) {
	m.calls++
	if len(ranges) > m.maxRanges {
		m.maxRanges = len(ranges)
	}
	result := make([][]byte, len(ranges))
	for index, item := range ranges {
		result[index] = make([]byte, item.size)
	}
	return result, nil
}

func TestExternalReaderDiscoversGenerationHeadsFromObservabilityPrefix(t *testing.T) {
	memory := sparseMemory{}
	runtimeAddress := uint64(0x10000)
	interpreterAddress := uint64(0x20000)
	memory.put64(runtimeAddress+40, interpreterAddress)
	memory.put64(interpreterAddress+96, runtimeAddress)
	firstHead := interpreterAddress + 136
	for generation, threshold := range []uint32{700, 10, 10} {
		head := firstHead + uint64(generation)*pyGenerationSize
		memory.put64(head, head)
		memory.put64(head+8, head)
		memory.put32(head+16, threshold)
	}
	census := newExternalCensus(memory, runtimeImage{
		version:        cpythonVersion{major: 3, minor: 12, micro: 3},
		runtimeAddress: runtimeAddress, order: binary.LittleEndian,
	}, 100, zeroTime())

	interpreters, err := census.findInterpreters()
	if err != nil {
		t.Fatal(err)
	}
	if len(interpreters) != 1 || interpreters[0].heads[0] != firstHead {
		t.Fatalf("interpreters=%+v, want first head %#x", interpreters, firstHead)
	}
}

func TestExternalReaderDiscoversCPython313DebugOffsets(t *testing.T) {
	memory := sparseMemory{}
	runtimeAddress := uint64(0x10000)
	interpreterAddress := uint64(0x20000)
	runtimeHeadOffset := uint64(632)
	interpreterSize := uint64(9000)
	interpreterNextOffset := uint64(7264)
	interpreterGCOffset := uint64(7400)
	memory.put(runtimeAddress, []byte("xdebugpy"))
	memory.put64(runtimeAddress+cpythonDebugRuntimeHeadOffset, runtimeHeadOffset)
	memory.put64(runtimeAddress+cpythonDebugInterpreterSize, interpreterSize)
	memory.put64(runtimeAddress+cpythonDebugInterpreterNext, interpreterNextOffset)
	memory.put64(runtimeAddress+cpythonDebugInterpreterGC, interpreterGCOffset)
	memory.put64(runtimeAddress+runtimeHeadOffset, interpreterAddress)
	memory.put64(interpreterAddress+interpreterNextOffset, 0)
	firstHead := interpreterAddress + interpreterGCOffset + cpythonGCGenerationsOffset
	for generation, threshold := range []uint32{700, 10, 10} {
		head := firstHead + uint64(generation)*pyGenerationSize
		memory.put64(head, head)
		memory.put64(head+8, head)
		memory.put32(head+16, threshold)
	}
	census := newExternalCensus(memory, runtimeImage{
		version: cpythonVersion{major: 3, minor: 13}, runtimeAddress: runtimeAddress,
		order: binary.LittleEndian,
	}, 100, zeroTime())

	interpreters, err := census.findInterpreters()
	if err != nil {
		t.Fatal(err)
	}
	if len(interpreters) != 1 || interpreters[0].heads[0] != firstHead {
		t.Fatalf("interpreters=%+v, want first head %#x", interpreters, firstHead)
	}
}

func TestExternalReaderUsesCPython314DebugGCOffset(t *testing.T) {
	memory := sparseMemory{}
	runtimeAddress := uint64(0x10000)
	interpreterAddress := uint64(0x20000)
	runtimeHeadOffset := uint64(632)
	interpreterSize := uint64(9000)
	interpreterNextOffset := uint64(7264)
	interpreterGCOffset := uint64(7400)
	memory.put(runtimeAddress, []byte("xdebugpy"))
	memory.put64(runtimeAddress+cpythonDebugRuntimeHeadOffset, runtimeHeadOffset)
	memory.put64(runtimeAddress+cpythonDebugInterpreterSize, interpreterSize)
	memory.put64(runtimeAddress+cpythonDebugInterpreterNext, interpreterNextOffset)
	memory.put64(runtimeAddress+cpythonDebugInterpreterGC314, interpreterGCOffset)
	memory.put64(interpreterAddress+interpreterNextOffset, 0)
	memory.put64(runtimeAddress+runtimeHeadOffset, interpreterAddress)
	firstHead := interpreterAddress + interpreterGCOffset + cpythonGCGenerationsOffset
	for generation, threshold := range []uint32{2000, 10, 10} {
		head := firstHead + uint64(generation)*pyGenerationSize
		memory.put64(head, head)
		memory.put64(head+8, head)
		memory.put32(head+16, threshold)
	}
	census := newExternalCensus(memory, runtimeImage{
		version: cpythonVersion{major: 3, minor: 14}, runtimeAddress: runtimeAddress,
		order: binary.LittleEndian,
	}, 100, zeroTime())
	interpreters, err := census.findInterpreters()
	if err != nil {
		t.Fatal(err)
	}
	if len(interpreters) != 1 || interpreters[0].heads[0] != firstHead {
		t.Fatalf("interpreters=%+v, want first head %#x", interpreters, firstHead)
	}
}

func TestShortGateBoundsExternalGCWorkAcrossSupportedVersions(t *testing.T) {
	for minor := 8; minor <= 14; minor++ {
		census := newExternalCensus(sparseMemory{}, runtimeImage{
			version: cpythonVersion{major: 3, minor: minor},
			order:   binary.LittleEndian,
		}, 200000, time.Now().Add(50*time.Millisecond))
		if !census.shortMode || census.maxObjects != shortGateMaxGCObjects {
			t.Fatalf("minor=%d short=%t max=%d", minor, census.shortMode,
				census.maxObjects)
		}
	}
}

func TestExternalReaderParsesCompactSplitDictionaryKeys(t *testing.T) {
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
	census := newExternalCensus(memory, runtimeImage{
		version: cpythonVersion{major: 3, minor: 12}, order: binary.LittleEndian,
	},
		100, zeroTime())

	names, err := census.parseDictKeys(keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "payload" || names[1] != "owner" {
		t.Fatalf("names=%q", names)
	}
}

func TestExternalReaderDiscoversCPython38RuntimeGenerationHeads(t *testing.T) {
	memory := sparseMemory{}
	runtimeAddress := uint64(0x10000)
	firstHead := runtimeAddress + 368 // runtime.gc + gc.generations in 3.8
	for generation, threshold := range []uint32{700, 10, 10} {
		head := firstHead + uint64(generation)*pyGenerationSize
		memory.put64(head, head)
		memory.put64(head+8, head)
		memory.put32(head+16, threshold)
	}
	census := newExternalCensus(memory, runtimeImage{
		version:        cpythonVersion{major: 3, minor: 8},
		runtimeAddress: runtimeAddress, order: binary.LittleEndian,
	}, 100, zeroTime())

	interpreters, err := census.findInterpreters()
	if err != nil {
		t.Fatal(err)
	}
	if len(interpreters) != 1 || interpreters[0].heads[0] != firstHead {
		t.Fatalf("generations=%+v, want first head %#x", interpreters, firstHead)
	}
}

func TestExternalReaderParsesLegacyGeneralDictionaryKeys(t *testing.T) {
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
	census := newExternalCensus(memory, runtimeImage{
		version: cpythonVersion{major: 3, minor: 9}, order: binary.LittleEndian,
	}, 100, zeroTime())

	entries, err := census.parseDictEntries(keys)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0].name != "payload" ||
		entries[0].value != 0x70000 || entries[1].name != "owner" {
		t.Fatalf("entries=%+v", entries)
	}
}

func TestVersionFromLegacyLibpythonPath(t *testing.T) {
	version, err := versionFromPythonModulePath(
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

func TestPymallocStratifiedEstimatePreservesSamples(t *testing.T) {
	pool := func(address, blocks uint64) pymallocPool {
		return pymallocPool{
			address: address, sizeClass: 3, blockSize: 64,
			allocatedBlocks: blocks, allocatedBytes: blocks * 64,
			occupancy: 2,
		}
	}
	strata := buildPymallocStrata([]pymallocPool{
		pool(0x100000, 100), pool(0x200000, 100),
		pool(0x300000, 100), pool(0x400000, 100), pool(0x500000, 100),
	}, 42)
	name := pymallocStratumName(pool(0, 0))
	samples := map[string]map[string]pymallocTypeSample{
		"builtins.tuple": {name: {count: 80, bytes: 5120}},
	}
	objects := estimatePymallocObjects(samples, strata, map[string]uint64{name: 100})
	if len(objects) != 1 {
		t.Fatalf("objects=%+v", objects)
	}
	object := objects[0]
	if object.SampledCount != 80 || object.SampledBytes != 5120 ||
		object.Count != 400 || object.ShallowBytes != 25600 || !object.Estimated {
		t.Fatalf("object=%+v", object)
	}
}

func TestPymallocCoverageReportsRawCoverage(t *testing.T) {
	pools := []pymallocPool{
		{
			address: 0x100000, blockSize: 64, allocatedBlocks: 100,
			allocatedBytes: 6400, occupancy: 2,
		},
		{
			address: 0x200000, blockSize: 64, allocatedBlocks: 100,
			allocatedBytes: 6400, occupancy: 2,
		},
	}
	strata := buildPymallocStrata(pools, 7)
	name := pymallocStratumName(pools[0])
	strata[name].sampledBlocks = 100
	strata[name].sampledBytes = 6400
	coverage := pymallocCoverage(strata, map[string]uint64{name: 1},
		map[string]uint64{name: 6400}, map[string]uint64{name: 5120}, 7,
		pymallocPopulation{})
	if !coverage.Estimated || coverage.EstimationMethod !=
		"python_pymalloc_stratified_v2" || coverage.RawCoverage != 0.5 ||
		coverage.ScannedRegions != 1 || coverage.TotalRegions != 2 {
		t.Fatalf("coverage=%+v", coverage)
	}
	if len(coverage.SamplingStrata) != 1 ||
		coverage.SamplingStrata[0].CompletedRegions != 1 {
		t.Fatalf("strata=%+v", coverage.SamplingStrata)
	}
	if err := coverage.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSamplePymallocArenasPreservesOuterPoolPopulation(t *testing.T) {
	const poolSize = uint64(4096)
	arenas := make([]pymallocArena, 96)
	var totalPools uint64
	for index := range arenas {
		address := uint64(0x100000 + index*0x100000)
		usedPools := uint64(8 + index%17)
		arenas[index] = pymallocArena{
			address: address, poolAddress: address + usedPools*poolSize,
			totalPools: 256,
		}
		totalPools += usedPools
	}
	sampled := samplePymallocArenas(arenas, pymallocShortGateMaxArenas,
		poolSize)
	if len(sampled) != pymallocShortGateMaxArenas {
		t.Fatalf("sampled arenas=%d", len(sampled))
	}
	var representedPools uint64
	for _, arena := range sampled {
		representedPools += arena.populationPools
	}
	if representedPools != totalPools {
		t.Fatalf("represented pools=%d total=%d", representedPools, totalPools)
	}
}

func TestPymallocOuterArenaWeightsReduceReportedRawCoverage(t *testing.T) {
	pools := []pymallocPool{
		{
			address: 0x100000, blockSize: 64, allocatedBlocks: 100,
			allocatedBytes: 6400, occupancy: 2, populationWeight: 4,
		},
		{
			address: 0x200000, blockSize: 64, allocatedBlocks: 100,
			allocatedBytes: 6400, occupancy: 2, populationWeight: 4,
		},
	}
	strata := buildPymallocStrata(pools, 11)
	name := pymallocStratumName(pools[0])
	coverage := pymallocCoverage(strata, map[string]uint64{name: 1},
		map[string]uint64{name: 6400}, map[string]uint64{name: 5120}, 11,
		pymallocPopulation{
			totalArenas: 8, sampledArenas: 2,
			totalPools: 8, sampledPoolHeaders: 2,
		})
	if coverage.HeapUsedBytes != 51200 || coverage.TotalRegions != 8 ||
		coverage.RawCoverage != 0.125 || !coverage.Estimated {
		t.Fatalf("coverage=%+v", coverage)
	}
	if coverage.EstimationMethod != "python_pymalloc_stratified_v2" ||
		len(coverage.KnownGaps) < 6 {
		t.Fatalf("coverage metadata=%+v", coverage)
	}
	samples := map[string]map[string]pymallocTypeSample{
		"workload.Hot": {name: {count: 80, bytes: 5120}},
	}
	objects := estimatePymallocObjects(samples, strata,
		map[string]uint64{name: 100})
	if len(objects) != 1 || objects[0].Count != 640 ||
		objects[0].ShallowBytes != 40960 {
		t.Fatalf("weighted objects=%+v", objects)
	}
}

func TestReadPymallocPoolBatchesBoundsWorkingSet(t *testing.T) {
	memory := &trackingBatchMemory{}
	census := newExternalCensus(memory, runtimeImage{}, 100, zeroTime())
	pools := make([]pymallocPool, pymallocPoolReadBatch*2+7)
	for index := range pools {
		pools[index].address = 0x100000 + uint64(index)*py312PoolSize
	}
	visited := 0
	skipped, err := census.readPymallocPoolBatches(pools,
		func(index int, pool pymallocPool,
			raw []byte,
		) bool {
			visited++
			return index == visited-1 && pool.address != 0 &&
				len(raw) == int(py312PoolSize)
		})
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 || visited != len(pools) ||
		memory.maxRanges != pymallocPoolReadBatch ||
		memory.calls != 3 {
		t.Fatalf("skipped=%d visited=%d max_ranges=%d calls=%d", skipped,
			visited, memory.maxRanges, memory.calls)
	}
}

func TestReadPymallocPoolBatchesPreservesReadablePrefix(t *testing.T) {
	pools := []pymallocPool{
		{address: 0x100000}, {address: 0x200000}, {address: 0x300000},
	}
	memory := &failingBatchMemory{failedAddress: pools[1].address}
	census := newExternalCensus(memory, runtimeImage{}, 100, zeroTime())
	visited := make([]int, 0, 2)
	skipped, err := census.readPymallocPoolBatches(pools,
		func(index int, _ pymallocPool, _ []byte) bool {
			visited = append(visited, index)
			return true
		})
	if err != nil || skipped != 1 || len(visited) != 2 ||
		visited[0] != 0 || visited[1] != 2 {
		t.Fatalf("skipped=%d visited=%v err=%v", skipped, visited, err)
	}
}
