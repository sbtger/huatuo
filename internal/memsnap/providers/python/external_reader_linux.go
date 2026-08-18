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
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"huatuo-bamai/internal/memsnap"
)

const (
	cpythonMinLegacyMinor = 8
	cpythonMaxLegacyMinor = 14

	pyGCHeadSize           = uint64(16)
	pyGenerationSize       = uint64(24)
	pyTypeReadSize         = 320
	pyTypeNameOffset       = 24
	pyTypeBasicOffset      = 32
	pyTypeItemOffset       = 40
	pyTypeFlagsOffset      = 168
	pyTypeDictionaryOffset = 264
	pyTypeDictOffset       = 288
	pyObjectTypeOffset     = 8
	pyObjectSizeOffset     = 16

	pyTPFlagsManagedWeakref = uint64(1 << 3)
	pyTPFlagsManagedDict    = uint64(1 << 4)
	pyTPFlagsInlineValues   = uint64(1 << 2)
	pyTPFlagsPreheader      = pyTPFlagsManagedWeakref | pyTPFlagsManagedDict
	pyTPFlagsHeapType       = uint64(1 << 9)

	maxRuntimeProbeBytes  = 1024
	maxInterpreterBytes   = 4096
	maxTypeAllocation     = 4096
	maxInstanceFields     = 64
	maxCStringBytes       = 512
	externalResultReserve = 12 * time.Millisecond

	py312InterpreterObmallocOffset  = uint64(3960)
	py312RuntimeInterpretersHead    = uint64(40)
	py312InterpreterGC              = uint64(112)
	py312PymallocPoolsBytes         = uint64(512)
	py312ArenaObjectSize            = uint64(48)
	py312ArenaSize                  = uint64(1 << 20)
	py312PoolSize                   = uint64(1 << 14)
	py312PoolOverhead               = uint64(48)
	pymallocPoolReadBatch           = 8
	py312SmallSizeClasses           = uint32(32)
	pymallocSampleNumerator         = 1
	pymallocSampleDenominator       = 2
	maxPymallocArenas               = uint32(1 << 20)
	maxPymallocSampleBytes          = uint64(12 << 20)
	maxPymallocSampleBlocks         = uint64(75000)
	pymallocShortGateThreshold      = 100 * time.Millisecond
	pymallocShortGateMaxArenas      = 32
	pymallocShortGateMaxPoolHeaders = 2048
	shortGateMaxGCObjects           = 6000
	cpythonDebugOffsetsBytes        = 88
	cpythonDebugRuntimeHeadOffset   = 40
	cpythonDebugInterpreterSize     = 48
	cpythonDebugInterpreterNext     = 64
	cpythonDebugInterpreterGC       = 80
	cpythonDebugInterpreterGC314    = 88
	cpythonGCGenerationsOffset      = 24
)

// RuntimeExecutor reads a concrete OOM victim without installing resident
// state or executing code in the victim.
type RuntimeExecutor struct {
	ProcRoot string
}

//nolint:gocritic // Executors receive an isolated request value from the provider.
func (e RuntimeExecutor) Execute(ctx context.Context,
	request memsnap.Request,
) (*CaptureResponse, error) {
	return (ExternalExecutor(e)).Execute(ctx, request)
}

// ExternalExecutor reads CPython's own GC and object metadata from the named
// victim. It does not execute code in the victim and does not require a Python
// package, agent, hook, debug build, or periodic discovery.
type ExternalExecutor struct {
	ProcRoot string
}

type cpythonVersion struct {
	major      int
	minor      int
	micro      int
	microKnown bool
}

func (v cpythonVersion) String() string {
	if !v.microKnown {
		return fmt.Sprintf("%d.%d.x", v.major, v.minor)
	}
	return fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.micro)
}

type runtimeImage struct {
	version        cpythonVersion
	runtimeAddress uint64
	allocator      pymallocAllocator
	order          binary.ByteOrder
}

type pymallocAllocator struct {
	managementAddress uint64
	interpreterOffset uint64
	indirect          bool
	legacyGlobals     bool
	arenaSize         uint64
	poolSize          uint64
	poolOverhead      uint64
	alignment         uint64
	sizeClasses       uint32
}

//nolint:gocritic // Executors receive an isolated request value from the provider.
func (e ExternalExecutor) Execute(ctx context.Context,
	request memsnap.Request,
) (*CaptureResponse, error) {
	// ReadPID prefers the frozen gate thread TID and falls back to the
	// thread-group leader PID, whose TID equals its PID.
	readTID := request.ReadPID()
	reader := &processMemory{pid: readTID}
	image, err := discoverRuntimeImage(ctx, e.procRoot(), readTID, reader)
	if err != nil {
		return nil, err
	}
	if image.version.major != 3 || image.version.minor < cpythonMinLegacyMinor ||
		image.version.minor > cpythonMaxLegacyMinor {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedRuntime,
			image.version.String())
	}
	deadline, _ := memsnap.OOMSnapshotDeadlineWithReserve(ctx,
		externalResultReserve)
	census := newExternalCensus(reader, image, request.MaxObjects, deadline)
	census.samplingSeed = request.OOMRequestCookie
	return census.capture(ctx)
}

func (e ExternalExecutor) procRoot() string {
	if e.ProcRoot == "" {
		return "/proc"
	}
	return e.ProcRoot
}

type remoteMemory interface {
	read(address uint64, size int) ([]byte, error)
}

type memoryRange struct {
	address uint64
	size    int
}

type batchRemoteMemory interface {
	readMany(ranges []memoryRange) ([][]byte, error)
}

type processMemory struct {
	pid int
}

func (m *processMemory) read(address uint64, size int) ([]byte, error) {
	if address == 0 || size <= 0 {
		return nil, errors.New("CPython process memory range is invalid")
	}
	data := make([]byte, size)
	local := []unix.Iovec{{Base: &data[0], Len: uint64(size)}}
	remote := []unix.RemoteIovec{{Base: uintptr(address), Len: size}}
	read, err := unix.ProcessVMReadv(m.pid, local, remote, 0)
	if err != nil {
		return nil, err
	}
	if read != size {
		return nil, fmt.Errorf("short CPython process memory read: got %d, want %d",
			read, size)
	}
	return data, nil
}

func (m *processMemory) readMany(ranges []memoryRange) ([][]byte, error) {
	result := make([][]byte, len(ranges))
	const batchSize = 512
	for start := 0; start < len(ranges); start += batchSize {
		end := start + batchSize
		if end > len(ranges) {
			end = len(ranges)
		}
		local := make([]unix.Iovec, end-start)
		remote := make([]unix.RemoteIovec, end-start)
		expected := 0
		for index := start; index < end; index++ {
			item := ranges[index]
			if item.address == 0 || item.size <= 0 {
				return nil, errors.New("CPython process memory range is invalid")
			}
			buffer := make([]byte, item.size)
			result[index] = buffer
			local[index-start] = unix.Iovec{Base: &buffer[0], Len: uint64(item.size)}
			remote[index-start] = unix.RemoteIovec{
				Base: uintptr(item.address), Len: item.size,
			}
			expected += item.size
		}
		read, err := unix.ProcessVMReadv(m.pid, local, remote, 0)
		if err != nil {
			return nil, err
		}
		if read != expected {
			return nil, fmt.Errorf("short CPython process memory batch read: got %d, want %d",
				read, expected)
		}
	}
	return result, nil
}

type procMap struct {
	start  uint64
	offset uint64
	inode  uint64
	path   string
}

func discoverRuntimeImage(ctx context.Context, procRoot string, pid int,
	memory remoteMemory,
) (runtimeImage, error) {
	if err := ctx.Err(); err != nil {
		return runtimeImage{}, err
	}
	maps, err := readProcMaps(filepath.Join(procRoot, strconv.Itoa(pid), "maps"))
	if err != nil {
		return runtimeImage{}, fmt.Errorf("read CPython victim maps: %w", err)
	}
	candidates := candidateRuntimeModules(procRoot, pid, maps)
	var failures []string
	for _, candidate := range candidates {
		image, imageErr := inspectRuntimeModule(candidate.hostPath, candidate.maps,
			memory)
		if imageErr == nil {
			return image, nil
		}
		failures = append(failures, imageErr.Error())
	}
	return runtimeImage{}, fmt.Errorf("locate CPython _PyRuntime: %s",
		strings.Join(failures, "; "))
}

type runtimeModule struct {
	hostPath string
	maps     []procMap
}

func candidateRuntimeModules(procRoot string, pid int, maps []procMap) []runtimeModule {
	byInode := make(map[uint64][]procMap)
	order := make([]uint64, 0)
	for _, mapping := range maps {
		if mapping.inode == 0 || mapping.path == "" || strings.HasPrefix(mapping.path, "[") {
			continue
		}
		if _, ok := byInode[mapping.inode]; !ok {
			order = append(order, mapping.inode)
		}
		byInode[mapping.inode] = append(byInode[mapping.inode], mapping)
	}
	modules := []runtimeModule{{
		hostPath: filepath.Join(procRoot, strconv.Itoa(pid), "exe"),
	}}
	for _, inode := range order {
		group := byInode[inode]
		path := strings.TrimSuffix(group[0].path, " (deleted)")
		if !strings.Contains(strings.ToLower(path), "python") {
			continue
		}
		hostPath := filepath.Join(procRoot, strconv.Itoa(pid), "root", path)
		modules = append(modules, runtimeModule{hostPath: hostPath, maps: group})
	}
	// The executable entry needs its maps for PIE load-bias calculation.
	if target, err := os.Readlink(modules[0].hostPath); err == nil {
		target = strings.TrimSuffix(target, " (deleted)")
		for _, group := range byInode {
			if strings.TrimSuffix(group[0].path, " (deleted)") == target {
				modules[0].maps = group
				break
			}
		}
	}
	return modules
}

func inspectRuntimeModule(path string, maps []procMap,
	memory remoteMemory,
) (runtimeImage, error) {
	file, err := elf.Open(path)
	if err != nil {
		return runtimeImage{}, err
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.ByteOrder != binary.LittleEndian {
		return runtimeImage{}, errors.New("CPython external reader requires little-endian ELF64")
	}
	// Keep the synchronous OOM path focused on the three observability symbols
	// that are actually consumed. Building an index for every ELF symbol costs
	// more than the sampling itself on some CPython 3.9/3.10 builds.
	dynamicSymbols := targetDynamicELFSymbols(file, "_PyRuntime", "Py_Version", "arenas")
	runtimeSymbol, err := indexedELFSymbol(dynamicSymbols, "_PyRuntime")
	if err != nil {
		return runtimeImage{}, err
	}
	bias := uint64(0)
	if file.Type == elf.ET_DYN {
		bias, err = moduleLoadBias(file, maps)
		if err != nil {
			return runtimeImage{}, err
		}
	}
	version := cpythonVersion{}
	if versionSymbol, versionErr := indexedELFSymbol(dynamicSymbols, "Py_Version"); versionErr == nil {
		versionRaw, readErr := memory.read(bias+versionSymbol.Value, 4)
		if readErr != nil {
			return runtimeImage{}, fmt.Errorf("read Py_Version: %w", readErr)
		}
		packed := file.ByteOrder.Uint32(versionRaw)
		version = cpythonVersion{
			major: int(packed >> 24),
			minor: int((packed >> 16) & 0xff), micro: int((packed >> 8) & 0xff),
			microKnown: true,
		}
		if version.major != 3 {
			return runtimeImage{}, fmt.Errorf("unexpected Py_Version %#x", packed)
		}
	} else {
		version, err = versionFromPythonModulePath(path)
		if err != nil {
			return runtimeImage{}, err
		}
	}
	allocator, allocatorErr := discoverPymallocAllocator(file, dynamicSymbols, bias, version)
	if allocatorErr != nil && version.minor >= 12 {
		return runtimeImage{}, allocatorErr
	}
	return runtimeImage{
		version:        version,
		runtimeAddress: bias + runtimeSymbol.Value, allocator: allocator,
		order: file.ByteOrder,
	}, nil
}

func discoverPymallocAllocator(file *elf.File, dynamicSymbols map[string]elf.Symbol, bias uint64,
	version cpythonVersion,
) (pymallocAllocator, error) {
	allocator := pymallocAllocator{
		arenaSize: 1 << 20, poolSize: 1 << 14, poolOverhead: 48,
		alignment: 16, sizeClasses: 32,
	}
	switch version.minor {
	case 8, 9:
		allocator.arenaSize = 1 << 18
		allocator.poolSize = 1 << 12
		fallthrough
	case 10:
		arenas, err := indexedELFSymbol(dynamicSymbols, "arenas")
		if err != nil {
			arenas, err = staticELFSymbol(file, "arenas")
		}
		if err != nil {
			return pymallocAllocator{}, err
		}
		allocator.managementAddress = bias + arenas.Value
		allocator.legacyGlobals = true
		return allocator, nil
	case 11:
		arenas, err := indexedELFSymbol(dynamicSymbols, "arenas")
		if err != nil {
			arenas, err = staticELFSymbol(file, "arenas")
		}
		if err != nil {
			return pymallocAllocator{}, err
		}
		allocator.managementAddress = bias + arenas.Value
		allocator.legacyGlobals = true
		return allocator, nil
	case 12:
		allocator.interpreterOffset = 3960 + py312PymallocPoolsBytes
		return allocator, nil
	case 13:
		allocator.interpreterOffset = 10800
		allocator.indirect = true
		return allocator, nil
	case 14:
		allocator.interpreterOffset = 10904
		allocator.indirect = true
		return allocator, nil
	default:
		return pymallocAllocator{}, fmt.Errorf("unsupported CPython %s pymalloc layout",
			version.String())
	}
}

func versionFromPythonModulePath(path string) (cpythonVersion, error) {
	name := strings.ToLower(filepath.Base(path))
	marker := strings.Index(name, "python3.")
	if marker < 0 {
		return cpythonVersion{}, errors.New("Py_Version and a versioned libpython name are unavailable")
	}
	minorText := name[marker+len("python3."):]
	end := 0
	for end < len(minorText) && minorText[end] >= '0' && minorText[end] <= '9' {
		end++
	}
	if end == 0 {
		return cpythonVersion{}, errors.New("libpython name has no minor version")
	}
	minor, err := strconv.Atoi(minorText[:end])
	if err != nil {
		return cpythonVersion{}, err
	}
	return cpythonVersion{major: 3, minor: minor}, nil
}

func targetDynamicELFSymbols(file *elf.File, names ...string) map[string]elf.Symbol {
	wanted := make(map[string]struct{}, len(names))
	for _, name := range names {
		wanted[name] = struct{}{}
	}
	result := make(map[string]elf.Symbol, len(names))
	if symbols, err := file.DynamicSymbols(); err == nil {
		for _, symbol := range symbols {
			if _, ok := wanted[symbol.Name]; ok {
				result[symbol.Name] = symbol
				if len(result) == len(wanted) {
					break
				}
			}
		}
	}
	return result
}

func indexedELFSymbol(symbols map[string]elf.Symbol, name string) (elf.Symbol, error) {
	if symbol, ok := symbols[name]; ok {
		return symbol, nil
	}
	return elf.Symbol{}, fmt.Errorf("ELF symbol %s is unavailable", name)
}

func staticELFSymbol(file *elf.File, name string) (elf.Symbol, error) {
	if symbols, err := file.Symbols(); err == nil {
		for _, symbol := range symbols {
			if symbol.Name == name {
				return symbol, nil
			}
		}
	}
	return elf.Symbol{}, fmt.Errorf("ELF symbol %s is unavailable", name)
}

func moduleLoadBias(file *elf.File, maps []procMap) (uint64, error) {
	page := uint64(os.Getpagesize())
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD {
			continue
		}
		loadOffset := program.Off &^ (page - 1)
		loadAddress := program.Vaddr &^ (page - 1)
		for _, mapping := range maps {
			if mapping.offset == loadOffset && mapping.start >= loadAddress {
				return mapping.start - loadAddress, nil
			}
		}
	}
	return 0, errors.New("cannot determine CPython module load bias")
}

func readProcMaps(path string) ([]procMap, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var result []procMap
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		ranges := strings.SplitN(fields[0], "-", 2)
		if len(ranges) != 2 {
			continue
		}
		start, startErr := strconv.ParseUint(ranges[0], 16, 64)
		offset, offsetErr := strconv.ParseUint(fields[2], 16, 64)
		inode, inodeErr := strconv.ParseUint(fields[4], 10, 64)
		if startErr != nil || offsetErr != nil || inodeErr != nil {
			continue
		}
		mappedPath := ""
		if len(fields) > 5 {
			mappedPath = strings.Join(fields[5:], " ")
		}
		result = append(result, procMap{
			start: start, offset: offset,
			inode: inode, path: mappedPath,
		})
	}
	return result, nil
}

type generationHeads struct {
	interpreter uint64
	heads       [3]uint64
}

type pymallocPool struct {
	address          uint64
	poolSize         uint64
	sizeClass        uint32
	blockSize        uint64
	allocatedBlocks  uint64
	allocatedBytes   uint64
	occupancy        uint32
	spatialBucket    uint32
	hash             uint64
	populationWeight float64
}

type pymallocStratum struct {
	pools         []pymallocPool
	totalPools    uint64
	totalBlocks   uint64
	totalBytes    uint64
	plannedPools  uint64
	sampledBlocks uint64
	sampledBytes  uint64
}

type pymallocArena struct {
	address     uint64
	poolAddress uint64
	totalPools  uint32
}

type pymallocPopulation struct {
	totalArenas        uint64
	sampledArenas      uint64
	totalPools         uint64
	sampledPoolHeaders uint64
}

type pymallocInventory struct {
	pools      []pymallocPool
	population pymallocPopulation
}

type pymallocTypeSample struct {
	count        uint64
	bytes        uint64
	sampledCount uint64
	sampledBytes uint64
}

type pythonObjectObservation struct {
	typeName     string
	count        uint64
	shallowBytes uint64
	sampledCount uint64
	sampledBytes uint64
	typeAddress  uint64
}

type externalCensus struct {
	memory            remoteMemory
	image             runtimeImage
	maxObjects        int
	deadline          time.Time
	types             map[uint64]pythonType
	invalidTypes      map[uint64]struct{}
	aggregates        map[string]*externalAggregate
	seenObjects       map[uint64]struct{}
	fieldShapes       int
	fieldValues       int
	partial           string
	samplingSeed      uint64
	shortMode         bool
	generationLimited bool
}

type pythonType struct {
	address    uint64
	meta       uint64
	name       string
	basicsize  int64
	itemsize   int64
	flags      uint64
	dictoffset int64
}

type externalAggregate struct {
	object        memsnap.ObjectAggregate
	lengthBuckets map[string]uint64
	fields        map[string]*externalField
}

type externalField struct {
	shape         memsnap.FieldShape
	lengthBuckets map[string]uint64
	seen          map[uint64]struct{}
}

func newExternalCensus(memory remoteMemory, image runtimeImage, maxObjects int,
	deadline time.Time,
) *externalCensus {
	shortMode := shortGateDeadline(deadline)
	if shortMode && (maxObjects <= 0 || maxObjects > shortGateMaxGCObjects) {
		maxObjects = shortGateMaxGCObjects
	}
	return &externalCensus{
		memory: memory, image: image, maxObjects: maxObjects,
		deadline: deadline, types: make(map[uint64]pythonType),
		invalidTypes: make(map[uint64]struct{}),
		aggregates:   make(map[string]*externalAggregate),
		seenObjects:  make(map[uint64]struct{}), shortMode: shortMode,
	}
}

func (c *externalCensus) capture(ctx context.Context) (*CaptureResponse, error) {
	var interpreters []generationHeads
	var err error
	// CPython 3.8-3.11 keep pymalloc's arena vector in process-global
	// storage. It does not require finding interpreter GC lists first; doing
	// that pointer-chasing pass consumed most of a 50ms gate on 3.8-3.10.
	if !c.image.allocator.legacyGlobals {
		interpreters, err = c.findInterpreters()
		if err != nil {
			return nil, err
		}
	}
	if response, sampled := c.capturePymalloc(ctx, interpreters); sampled {
		return response, nil
	}
	if c.image.allocator.legacyGlobals {
		interpreters, err = c.findInterpreters()
		if err != nil {
			return nil, err
		}
	}
	generationBudget := 0
	if c.shortMode {
		headCount := len(interpreters) * len(generationHeads{}.heads)
		if headCount != 0 {
			generationBudget = c.maxObjects / headCount
			if generationBudget == 0 {
				generationBudget = 1
			}
		}
	}
	if c.shortMode {
		// Give every generation a small head/tail sample before spending the
		// remaining budget. This keeps a slow generation from hiding types in
		// later generations when the OOM gate has only a few milliseconds left.
		const minimumGenerationBudget = 256
		firstBudget := generationBudget
		if firstBudget > minimumGenerationBudget {
			firstBudget = minimumGenerationBudget
		}
		if c.traverseAllGenerations(ctx, interpreters, firstBudget) {
			remaining := generationBudget - firstBudget
			if remaining > 0 {
				c.traverseAllGenerations(ctx, interpreters, remaining)
			}
		}
	} else {
		c.traverseAllGenerations(ctx, interpreters, 0)
	}
	if c.partial == "" && c.generationLimited {
		c.partial = "per-generation object sample limit reached"
	}
	status := memsnap.StatusComplete
	truncated := false
	var reasons []string
	if c.partial != "" {
		truncated = true
		reasons = []string{c.partial}
		status = memsnap.OOMSnapshotPartialCaptureStatus(c.partial, false)
	}
	consistency := "cpython_external_gc_tracked_census"
	if c.shortMode {
		consistency = "cpython_external_gc_bounded_sample"
		if !truncated {
			status = memsnap.StatusPartialRecordLimit
			truncated = true
			reasons = []string{"50ms gate uses a bounded GC-tracked object sample"}
		}
	}
	response := &CaptureResponse{
		RuntimeVersion: c.image.version.String(), Status: status,
		Truncated: truncated, TruncationReasons: reasons,
		Coverage: memsnap.Coverage{
			Consistency:   consistency,
			SizeSemantics: "estimated_allocated_shallow_bytes",
			Impact:        "on_demand_process_vm_readv",
			KnownGaps: []string{
				"only objects reachable from CPython GC generation lists are counted",
				"independent non-GC-tracked objects and native extension allocations are absent",
				"shallow bytes are layout estimates, not retained size",
				"allocation traceback and retaining paths are unavailable",
				"instance fields are best-effort for standard managed and split dictionaries",
			},
		},
	}
	response.FinalizeLocal = func() error {
		response.Objects = c.finishAggregates()
		return nil
	}
	return response, nil
}

func (c *externalCensus) traverseAllGenerations(ctx context.Context,
	interpreters []generationHeads, budget int,
) bool {
	for _, interpreter := range interpreters {
		for _, head := range interpreter.heads {
			forwardBudget := budget
			backwardBudget := 0
			if budget > 1 {
				forwardBudget = (budget + 1) / 2
				backwardBudget = budget - forwardBudget
			}
			if !c.traverseGeneration(ctx, head, forwardBudget, false) ||
				(backwardBudget != 0 &&
					!c.traverseGeneration(ctx, head, backwardBudget, true)) {
				return false
			}
		}
	}
	return true
}

func (c *externalCensus) findInterpreters() ([]generationHeads, error) {
	runtimeRaw, err := c.memory.read(c.image.runtimeAddress, maxRuntimeProbeBytes)
	if err != nil {
		return nil, fmt.Errorf("read _PyRuntime observability prefix: %w", err)
	}
	if c.image.version.minor == 8 {
		offset := c.findGenerationOffset(c.image.runtimeAddress, runtimeRaw)
		if offset < 0 {
			return nil, errors.New("CPython 3.8 runtime GC generations were not found")
		}
		result := generationHeads{interpreter: c.image.runtimeAddress}
		for generation := range result.heads {
			result.heads[generation] = c.image.runtimeAddress + uint64(offset) +
				uint64(generation)*pyGenerationSize
		}
		return []generationHeads{result}, nil
	}
	if c.image.version.minor >= 13 {
		return c.findInterpretersFromDebugOffsets(runtimeRaw)
	}
	if c.image.version.minor == 12 && c.shortGate() {
		return c.findPython312Interpreter(runtimeRaw)
	}
	seen := make(map[uint64]struct{})
	var result []generationHeads
	for offset := 0; offset+8 <= len(runtimeRaw); offset += 8 {
		candidate := c.image.order.Uint64(runtimeRaw[offset : offset+8])
		for isPlausiblePointer(candidate) {
			if _, ok := seen[candidate]; ok {
				break
			}
			seen[candidate] = struct{}{}
			generation, next, generationErr := c.inspectInterpreter(candidate)
			if generationErr != nil {
				break
			}
			result = append(result, generation)
			candidate = next
		}
	}
	if len(result) == 0 {
		return nil, errors.New("CPython interpreter GC generations were not found")
	}
	return result, nil
}

func (c *externalCensus) findPython312Interpreter(runtimeRaw []byte) (
	[]generationHeads, error,
) {
	if py312RuntimeInterpretersHead+8 > uint64(len(runtimeRaw)) {
		return nil, errors.New("CPython 3.12 interpreter head is unavailable")
	}
	address := c.image.order.Uint64(
		runtimeRaw[py312RuntimeInterpretersHead : py312RuntimeInterpretersHead+8])
	if !isPlausiblePointer(address) {
		return nil, errors.New("CPython 3.12 interpreter head is invalid")
	}
	firstHead := address + py312InterpreterGC + cpythonGCGenerationsOffset
	result := generationHeads{interpreter: address}
	for index := range result.heads {
		result.heads[index] = firstHead + uint64(index)*pyGenerationSize
	}
	return []generationHeads{result}, nil
}

func (c *externalCensus) findInterpretersFromDebugOffsets(runtimeRaw []byte) (
	[]generationHeads, error,
) {
	if len(runtimeRaw) < cpythonDebugOffsetsBytes ||
		string(runtimeRaw[:8]) != "xdebugpy" {
		return nil, errors.New("CPython debug offsets are unavailable")
	}
	read := func(offset int) uint64 {
		return c.image.order.Uint64(runtimeRaw[offset : offset+8])
	}
	runtimeHead := read(cpythonDebugRuntimeHeadOffset)
	interpreterSize := read(cpythonDebugInterpreterSize)
	interpreterNext := read(cpythonDebugInterpreterNext)
	interpreterGCOffset := cpythonDebugInterpreterGC
	if c.image.version.minor >= 14 {
		interpreterGCOffset = cpythonDebugInterpreterGC314
	}
	interpreterGC := read(interpreterGCOffset)
	if runtimeHead+8 > uint64(len(runtimeRaw)) || interpreterSize == 0 ||
		interpreterSize > 1<<20 || interpreterNext+8 > interpreterSize ||
		interpreterGC+cpythonGCGenerationsOffset+3*pyGenerationSize > interpreterSize {
		return nil, errors.New("CPython debug offsets are invalid")
	}
	address := c.image.order.Uint64(runtimeRaw[runtimeHead : runtimeHead+8])
	seen := make(map[uint64]struct{})
	var result []generationHeads
	for isPlausiblePointer(address) {
		if _, ok := seen[address]; ok {
			return nil, errors.New("CPython interpreter list contains a cycle")
		}
		seen[address] = struct{}{}
		nextRaw, err := c.memory.read(address+interpreterNext, 8)
		if err != nil {
			return nil, fmt.Errorf("read CPython interpreter next pointer: %w", err)
		}
		firstHead := address + interpreterGC + cpythonGCGenerationsOffset
		generationRaw, err := c.memory.read(firstHead, int(3*pyGenerationSize))
		if err != nil || c.findGenerationOffset(firstHead, generationRaw) != 0 {
			return nil, errors.New("CPython interpreter GC generations are invalid")
		}
		generation := generationHeads{interpreter: address}
		for index := range generation.heads {
			generation.heads[index] = firstHead + uint64(index)*pyGenerationSize
		}
		result = append(result, generation)
		address = c.image.order.Uint64(nextRaw)
	}
	if len(result) == 0 {
		return nil, errors.New("CPython interpreter GC generations were not found")
	}
	return result, nil
}

func (c *externalCensus) inspectInterpreter(address uint64) (generationHeads,
	uint64, error,
) {
	raw, err := c.memory.read(address, maxInterpreterBytes)
	if err != nil {
		return generationHeads{}, 0, err
	}
	bestOffset := c.findGenerationOffset(address, raw)
	if bestOffset < 0 {
		return generationHeads{}, 0, errors.New("interpreter has no valid GC generation heads")
	}
	result := generationHeads{interpreter: address}
	for generation := range result.heads {
		result.heads[generation] = address + uint64(bestOffset) +
			uint64(generation)*pyGenerationSize
	}
	next := c.image.order.Uint64(raw[:8])
	return result, next, nil
}

func (c *externalCensus) findGenerationOffset(baseAddress uint64, raw []byte) int {
	bestOffset := -1
	bestScore := -1
	for offset := 0; offset+int(3*pyGenerationSize) <= len(raw); offset += 8 {
		score := 0
		valid := true
		for generation := 0; generation < 3; generation++ {
			base := offset + generation*int(pyGenerationSize)
			head := baseAddress + uint64(base)
			next := c.image.order.Uint64(raw[base:base+8]) &^ 3
			previous := c.image.order.Uint64(raw[base+8:base+16]) &^ 3
			threshold := int32(c.image.order.Uint32(raw[base+16 : base+20]))
			count := int32(c.image.order.Uint32(raw[base+20 : base+24]))
			if !c.validGenerationLinks(head, next, previous) || threshold < 0 ||
				threshold > 1_000_000_000 || count < 0 || count > 1_000_000_000 {
				valid = false
				break
			}
			if next == head && previous == head {
				score++
			}
			if generation == 0 && threshold > 0 {
				score += 2
			}
		}
		if valid && score > bestScore {
			bestOffset = offset
			bestScore = score
		}
	}
	return bestOffset
}

func (c *externalCensus) validGenerationLinks(head, next, previous uint64) bool {
	if !isPlausiblePointer(next) || !isPlausiblePointer(previous) {
		return false
	}
	if next != head {
		raw, err := c.memory.read(next, 16)
		if err != nil || c.image.order.Uint64(raw[8:16])&^3 != head {
			return false
		}
	}
	if previous != head {
		raw, err := c.memory.read(previous, 8)
		if err != nil || c.image.order.Uint64(raw[:8])&^3 != head {
			return false
		}
	}
	return true
}

func (c *externalCensus) capturePymalloc(ctx context.Context,
	interpreters []generationHeads,
) (*CaptureResponse, bool) {
	if c.image.allocator.poolSize == 0 {
		return nil, false
	}
	shortGate := c.shortGate()
	inventory, ok := c.inventoryPymallocPools(ctx, interpreters)
	if !ok || len(inventory.pools) == 0 {
		if shortGate {
			return &CaptureResponse{
				RuntimeVersion: c.image.version.String(),
				Status:         memsnap.StatusPartialDeadline, Truncated: true,
				TruncationReasons: []string{
					"short gate ended before pymalloc pools could be sampled",
				}, Coverage: pymallocCoverage(nil, nil, nil, nil,
					c.samplingSeed, inventory.population),
			}, true
		}
		return nil, false
	}
	strata := buildPymallocStrata(inventory.pools, c.samplingSeed)
	var totalBlocks uint64
	for _, stratum := range strata {
		totalBlocks = saturatedAdd(totalBlocks, stratum.totalBlocks)
	}
	// Below the object budget the legacy GC traversal preserves more useful
	// information: instance fields and auxiliary buffers allocated outside
	// pymalloc. Sampling is for the high-cardinality case that cannot finish
	// that traversal before the synchronous OOM gate deadline.
	if totalBlocks <= uint64(c.maxObjects) && !shortGate {
		return nil, false
	}
	sampleObjects := c.maxObjects
	if shortGate && sampleObjects < 75000 {
		// The GC-list fallback caps object pointer chasing at 6k. Pymalloc pool
		// reads are contiguous and batched, so use a separate budget here to
		// cover every spatial stratum instead of exhausting the quota on the
		// first few allocator classes.
		sampleObjects = 75000
	}
	selected := planPymallocSample(strata, sampleObjects, true)
	if len(selected) == 0 {
		return nil, false
	}
	typeSamples := make(map[string]map[string]pymallocTypeSample)
	completedPools := make(map[string]uint64)
	completedBlocks := make(map[string]uint64)
	completedBytes := make(map[string]uint64)
	classifiedBytes := make(map[string]uint64)
	partial := ""
	skippedPools, err := c.readPymallocPoolBatches(selected,
		func(index int, pool pymallocPool,
			raw []byte,
		) bool {
			if ctx.Err() != nil ||
				(!c.deadline.IsZero() && !time.Now().Before(c.deadline)) {
				partial = "deadline reached during pymalloc sampled object census"
				return false
			}
			stratumName := pymallocStratumName(pool)
			observations, valid := c.scanPymallocPool(pool, raw)
			if !valid {
				partial = "pymalloc pool changed during sampled object census"
				return true
			}
			completedPools[stratumName]++
			completedBlocks[stratumName] = saturatedAdd(completedBlocks[stratumName],
				pool.allocatedBlocks)
			completedBytes[stratumName] = saturatedAdd(completedBytes[stratumName],
				pool.allocatedBytes)
			for _, observation := range observations {
				observationCount := observation.count
				if observationCount == 0 {
					observationCount = 1
				}
				sampledCount := observation.sampledCount
				if sampledCount == 0 {
					sampledCount = 1
				}
				sampledBytes := observation.sampledBytes
				if sampledBytes == 0 {
					sampledBytes = observation.shallowBytes
				}
				classifiedBytes[stratumName] = saturatedAdd(
					classifiedBytes[stratumName], sampledBytes)
				byStratum := typeSamples[observation.typeName]
				if byStratum == nil {
					byStratum = make(map[string]pymallocTypeSample)
					typeSamples[observation.typeName] = byStratum
				}
				sample := byStratum[stratumName]
				sample.count = saturatedAdd(sample.count, observationCount)
				sample.bytes = saturatedAdd(sample.bytes, observation.shallowBytes)
				sample.sampledCount = saturatedAdd(sample.sampledCount, sampledCount)
				sample.sampledBytes = saturatedAdd(sample.sampledBytes, sampledBytes)
				byStratum[stratumName] = sample
			}
			return true
		})
	if err != nil {
		return nil, false
	}
	if skippedPools != 0 && partial == "" {
		partial = fmt.Sprintf(
			"%d pymalloc pools could not be read during sampled object census",
			skippedPools)
	}
	if c.shortGate() {
		var totalCompletedBlocks uint64
		for _, blocks := range completedBlocks {
			totalCompletedBlocks = saturatedAdd(totalCompletedBlocks, blocks)
		}
		// The ratio estimator extrapolates the completed (unweighted) block
		// sample to the full weighted heap. When the completed fraction is tiny
		// the estimate is dominated by arena/pool sampling bias, so report
		// size classes rather than biased Python types.
		if totalCompletedBlocks*10 < totalBlocks {
			return c.pymallocSizeClassSnapshot(strata), true
		}
	}
	status := memsnap.StatusComplete
	truncated := false
	var reasons []string
	if partial != "" {
		status = memsnap.OOMSnapshotPartialCaptureStatus(partial, false)
		truncated = true
		reasons = []string{partial}
	}
	response := &CaptureResponse{
		RuntimeVersion: c.image.version.String(), Status: status,
		Truncated: truncated, TruncationReasons: reasons,
	}
	response.FinalizeLocal = func() error {
		response.Objects = estimatePymallocObjects(typeSamples, strata,
			completedBlocks)
		response.Coverage = pymallocCoverage(strata, completedPools, completedBytes,
			classifiedBytes, c.samplingSeed, inventory.population)
		return nil
	}
	return response, true
}

func (c *externalCensus) pymallocSizeClassSnapshot(
	strata map[string]*pymallocStratum,
) *CaptureResponse {
	bySize := make(map[uint64]*memsnap.ObjectAggregate)
	for _, stratum := range strata {
		for _, pool := range stratum.pools {
			object := bySize[pool.blockSize]
			if object == nil {
				object = &memsnap.ObjectAggregate{
					TypeName: fmt.Sprintf("pymalloc.size_%d", pool.blockSize),
				}
				bySize[pool.blockSize] = object
			}
			object.Count = saturatedAdd(object.Count, pool.allocatedBlocks)
			object.ShallowBytes = saturatedAdd(object.ShallowBytes,
				pool.allocatedBytes)
		}
	}
	objects := make([]memsnap.ObjectAggregate, 0, len(bySize))
	for _, object := range bySize {
		if object.Count != 0 {
			object.AverageBytes = float64(object.ShallowBytes) /
				float64(object.Count)
		}
		objects = append(objects, *object)
	}
	sort.Slice(objects, func(i, j int) bool {
		return objects[i].ShallowBytes > objects[j].ShallowBytes
	})
	coverage := pymallocCoverage(strata, nil, nil, nil, c.samplingSeed,
		pymallocPopulation{})
	coverage.Consistency = "cpython_pymalloc_bounded_inventory"
	coverage.SizeSemantics = "observed_pymalloc_block_bytes"
	coverage.ObjectType = "allocator_size_class"
	coverage.Estimated = false
	coverage.EstimationMethod = ""
	coverage.SampleRateAssumption =
		"size-class totals cover the bounded arena inventory captured before the gate deadline"
	coverage.KnownGaps = append(coverage.KnownGaps,
		"short-gate entries are allocator size classes, not Python object types",
		"arenas beyond the bounded inventory are omitted rather than extrapolated")
	return &CaptureResponse{
		RuntimeVersion: c.image.version.String(),
		Status:         memsnap.StatusPartialDeadline, Truncated: true,
		TruncationReasons: []string{
			"50ms gate uses bounded pymalloc size-class inventory",
		}, Coverage: coverage, Objects: objects,
	}
}

func (c *externalCensus) shortGate() bool {
	return c.shortMode
}

func (c *externalCensus) deadlineReached() bool {
	return !c.deadline.IsZero() && !time.Now().Before(c.deadline)
}

func shortGateDeadline(deadline time.Time) bool {
	return !deadline.IsZero() &&
		time.Until(deadline) < pymallocShortGateThreshold
}

func (c *externalCensus) readPymallocPoolBatches(selected []pymallocPool,
	visit func(index int, pool pymallocPool, raw []byte) bool,
) (int, error) {
	defaultPoolSize := c.image.allocator.poolSize
	if defaultPoolSize == 0 {
		defaultPoolSize = py312PoolSize
	}
	batchPools := pymallocPoolReadBatch
	// Keep each process_vm_readv call near 128 KiB across allocator layouts.
	// CPython 3.8-3.10 use 4 KiB pools, so a fixed eight-pool batch spends four
	// times as many syscalls as 3.11+ and loses most of a 50ms gate to setup.
	if defaultPoolSize != 0 {
		batchPools = int((128 << 10) / defaultPoolSize)
		if batchPools < pymallocPoolReadBatch {
			batchPools = pymallocPoolReadBatch
		}
		if batchPools > 64 {
			batchPools = 64
		}
	}
	skipped := 0
	for start := 0; start < len(selected); start += batchPools {
		end := start + batchPools
		if end > len(selected) {
			end = len(selected)
		}
		poolRanges := make([]memoryRange, end-start)
		for index := start; index < end; index++ {
			poolSize := selected[index].poolSize
			if poolSize == 0 {
				poolSize = defaultPoolSize
			}
			poolRanges[index-start] = memoryRange{
				address: selected[index].address, size: int(poolSize),
			}
		}
		poolRaw, err := c.readMany(poolRanges)
		if err != nil {
			for offset, item := range poolRanges {
				raw, readErr := c.memory.read(item.address, item.size)
				if readErr != nil {
					skipped++
					continue
				}
				index := start + offset
				if !visit(index, selected[index], raw) {
					return skipped, nil
				}
			}
			continue
		}
		for index := start; index < end; index++ {
			if !visit(index, selected[index], poolRaw[index-start]) {
				return skipped, nil
			}
		}
	}
	return skipped, nil
}

func (c *externalCensus) inventoryPymallocPools(ctx context.Context,
	interpreters []generationHeads,
) (pymallocInventory, bool) {
	shortGate := c.shortGate()
	layout := c.image.allocator
	seenArenas := make(map[uint64]struct{})
	var arenaRanges []memoryRange
	managementAddresses := make([]uint64, 0, len(interpreters))
	if layout.legacyGlobals {
		managementAddresses = append(managementAddresses, layout.managementAddress)
	}
	for _, interpreter := range interpreters {
		if layout.legacyGlobals {
			break
		}
		if !isPlausiblePointer(interpreter.interpreter) {
			continue
		}
		mgmt := interpreter.interpreter + layout.interpreterOffset
		if layout.indirect {
			raw, err := c.memory.read(mgmt, 8)
			if err != nil {
				continue
			}
			mgmt = c.image.order.Uint64(raw)
			if !isPlausiblePointer(mgmt) {
				continue
			}
			mgmt += py312PymallocPoolsBytes
		}
		managementAddresses = append(managementAddresses, mgmt)
	}
	for _, mgmt := range managementAddresses {
		readAddress := mgmt
		if layout.legacyGlobals {
			readAddress -= 8
		}
		raw, err := c.memory.read(readAddress, 16)
		if err != nil {
			continue
		}
		arenas := c.image.order.Uint64(raw[:8])
		maxArenas := c.image.order.Uint32(raw[8:12])
		if layout.legacyGlobals {
			maxArenas = c.image.order.Uint32(raw[:4])
			arenas = c.image.order.Uint64(raw[8:16])
		}
		if !isPlausiblePointer(arenas) || maxArenas == 0 ||
			maxArenas > maxPymallocArenas {
			continue
		}
		arenaRanges = append(arenaRanges, memoryRange{
			address: arenas, size: int(uint64(maxArenas) * py312ArenaObjectSize),
		})
	}
	if len(arenaRanges) == 0 {
		return pymallocInventory{}, false
	}
	arenaVectors, err := c.readMany(arenaRanges)
	if err != nil {
		return pymallocInventory{}, false
	}
	var arenas []pymallocArena
	for _, vector := range arenaVectors {
		for offset := 0; offset+int(py312ArenaObjectSize) <= len(vector); offset += int(py312ArenaObjectSize) {
			entry := vector[offset : offset+int(py312ArenaObjectSize)]
			address := c.image.order.Uint64(entry[:8])
			poolAddress := c.image.order.Uint64(entry[8:16])
			totalPools := c.image.order.Uint32(entry[20:24])
			if address == 0 {
				continue
			}
			if _, duplicate := seenArenas[address]; duplicate {
				continue
			}
			seenArenas[address] = struct{}{}
			firstPool := alignUp(address, layout.poolSize)
			arenaEnd := address + layout.arenaSize
			if totalPools == 0 || uint64(totalPools) > layout.arenaSize/layout.poolSize ||
				poolAddress < firstPool || poolAddress > arenaEnd ||
				(poolAddress-firstPool)%layout.poolSize != 0 {
				return pymallocInventory{}, false
			}
			arenas = append(arenas, pymallocArena{
				address: address, poolAddress: poolAddress, totalPools: totalPools,
			})
		}
	}
	sort.Slice(arenas, func(i, j int) bool { return arenas[i].address < arenas[j].address })
	population := pymallocPopulation{totalArenas: uint64(len(arenas))}
	for _, arena := range arenas {
		population.totalPools = saturatedAdd(population.totalPools,
			pymallocArenaUsedPools(arena, layout.poolSize))
	}
	selectedArenas := samplePymallocArenas(arenas, len(arenas), layout.poolSize)
	if shortGate && len(arenas) > pymallocShortGateMaxArenas {
		selectedArenas = samplePymallocArenas(arenas,
			pymallocShortGateMaxArenas, layout.poolSize)
	}
	population.sampledArenas = uint64(len(selectedArenas))
	var poolRanges []memoryRange
	var poolAddresses []uint64
	var poolWeights []float64
	perArenaLimit := 0
	if shortGate && len(selectedArenas) != 0 {
		perArenaLimit = pymallocShortGateMaxPoolHeaders / len(selectedArenas)
		if perArenaLimit == 0 {
			perArenaLimit = 1
		}
	}
	for _, sampled := range selectedArenas {
		arena := sampled.arena
		firstPool := alignUp(arena.address, layout.poolSize)
		poolCount := int((arena.poolAddress - firstPool) / layout.poolSize)
		selectedPools := poolCount
		if perArenaLimit != 0 && selectedPools > perArenaLimit {
			selectedPools = perArenaLimit
		}
		if selectedPools == 0 {
			continue
		}
		weight := float64(sampled.populationPools) / float64(selectedPools)
		for sequence := 0; sequence < selectedPools; sequence++ {
			index := sequence
			if selectedPools < poolCount {
				index = sequence * poolCount / selectedPools
			}
			pool := firstPool + uint64(index)*layout.poolSize
			poolRanges = append(poolRanges, memoryRange{address: pool, size: 48})
			poolAddresses = append(poolAddresses, pool)
			poolWeights = append(poolWeights, weight)
		}
	}
	population.sampledPoolHeaders = uint64(len(poolRanges))
	if len(poolRanges) == 0 {
		return pymallocInventory{population: population}, false
	}
	headers, err := c.readMany(poolRanges)
	if err != nil {
		return pymallocInventory{population: population}, false
	}
	result := make([]pymallocPool, 0, len(headers))
	for index, header := range headers {
		if index&4095 == 0 && (ctx.Err() != nil ||
			(!c.deadline.IsZero() && !time.Now().Before(c.deadline))) {
			return pymallocInventory{population: population}, false
		}
		count := uint64(c.image.order.Uint32(header[:4]))
		sizeClass := c.image.order.Uint32(header[36:40])
		if count == 0 {
			continue
		}
		if sizeClass >= layout.sizeClasses {
			return pymallocInventory{population: population}, false
		}
		blockSize := uint64(sizeClass+1) * layout.alignment
		capacity := (layout.poolSize - layout.poolOverhead) / blockSize
		if count > capacity {
			return pymallocInventory{population: population}, false
		}
		occupancy := uint32((count * 4) / capacity)
		if occupancy > 3 {
			occupancy = 3
		}
		address := poolAddresses[index]
		result = append(result, pymallocPool{
			address: address, poolSize: layout.poolSize, sizeClass: sizeClass,
			blockSize:       blockSize,
			allocatedBlocks: count, allocatedBytes: count * blockSize,
			occupancy: occupancy, hash: pymallocHash(address ^ c.samplingSeed),
			populationWeight: poolWeights[index],
		})
	}
	return pymallocInventory{pools: result, population: population}, true
}

type sampledPymallocArena struct {
	arena           pymallocArena
	populationPools uint64
}

func pymallocArenaUsedPools(arena pymallocArena, poolSize uint64) uint64 {
	firstPool := alignUp(arena.address, poolSize)
	return (arena.poolAddress - firstPool) / poolSize
}

func samplePymallocArenas(arenas []pymallocArena, limit int,
	poolSize uint64,
) []sampledPymallocArena {
	if limit <= 0 || len(arenas) == 0 {
		return nil
	}
	if limit > len(arenas) {
		limit = len(arenas)
	}
	result := make([]sampledPymallocArena, 0, limit)
	for index := 0; index < limit; index++ {
		start := index * len(arenas) / limit
		end := (index + 1) * len(arenas) / limit
		position := start + (end-start-1)/2
		var populationPools uint64
		for _, arena := range arenas[start:end] {
			populationPools = saturatedAdd(populationPools,
				pymallocArenaUsedPools(arena, poolSize))
		}
		result = append(result, sampledPymallocArena{
			arena: arenas[position], populationPools: populationPools,
		})
	}
	return result
}

func (c *externalCensus) readMany(ranges []memoryRange) ([][]byte, error) {
	if batch, ok := c.memory.(batchRemoteMemory); ok {
		return batch.readMany(ranges)
	}
	result := make([][]byte, len(ranges))
	for index, item := range ranges {
		raw, err := c.memory.read(item.address, item.size)
		if err != nil {
			return nil, err
		}
		result[index] = raw
	}
	return result, nil
}

func buildPymallocStrata(pools []pymallocPool, seed uint64) map[string]*pymallocStratum {
	const spatialBuckets = 16
	byAllocatorClass := make(map[string][]pymallocPool)
	for _, pool := range pools {
		name := fmt.Sprintf("size_%d_occupancy_%d", pool.blockSize, pool.occupancy)
		byAllocatorClass[name] = append(byAllocatorClass[name], pool)
	}
	result := make(map[string]*pymallocStratum)
	for _, classPools := range byAllocatorClass {
		sort.Slice(classPools, func(i, j int) bool {
			return classPools[i].address < classPools[j].address
		})
		for index, pool := range classPools {
			weight := pool.populationWeight
			if weight <= 0 {
				weight = 1
			}
			pool.hash = pymallocHash(pool.address ^ seed)
			if len(classPools) >= spatialBuckets {
				pool.spatialBucket = uint32(index * spatialBuckets / len(classPools))
			}
			name := pymallocStratumName(pool)
			stratum := result[name]
			if stratum == nil {
				stratum = &pymallocStratum{}
				result[name] = stratum
			}
			stratum.pools = append(stratum.pools, pool)
			stratum.totalPools = saturatedAdd(stratum.totalPools,
				scalePymallocPopulation(1, weight))
			stratum.totalBlocks = saturatedAdd(stratum.totalBlocks,
				scalePymallocPopulation(pool.allocatedBlocks, weight))
			stratum.totalBytes = saturatedAdd(stratum.totalBytes,
				scalePymallocPopulation(pool.allocatedBytes, weight))
		}
	}
	for _, stratum := range result {
		sort.Slice(stratum.pools, func(i, j int) bool {
			return stratum.pools[i].address < stratum.pools[j].address
		})
	}
	return result
}

func scalePymallocPopulation(observed uint64, weight float64) uint64 {
	if observed == 0 || weight <= 0 {
		return 0
	}
	estimate := float64(observed) * weight
	if estimate >= float64(math.MaxUint64) {
		return math.MaxUint64
	}
	result := uint64(math.Round(estimate))
	if result < observed {
		return observed
	}
	return result
}

func planPymallocSample(strata map[string]*pymallocStratum,
	maxObjects int, allowFullCensus bool,
) []pymallocPool {
	if maxObjects <= 0 {
		return nil
	}
	var totalBlocks uint64
	for _, stratum := range strata {
		totalBlocks = saturatedAdd(totalBlocks, stratum.totalBlocks)
	}
	if totalBlocks == 0 {
		return nil
	}
	fullCensus := allowFullCensus && totalBlocks <= uint64(maxObjects)
	names := make([]string, 0, len(strata))
	for name := range strata {
		names = append(names, name)
	}
	sort.Strings(names)
	planned := make(map[string][]pymallocPool, len(strata))
	remaining := uint64(maxObjects)
	if fullCensus {
		remaining = totalBlocks
	} else if remaining > maxPymallocSampleBlocks {
		remaining = maxPymallocSampleBlocks
	}
	sampleBudget := remaining
	remainingBytes := maxPymallocSampleBytes
	for _, name := range names {
		stratum := strata[name]
		target := stratum.totalBlocks
		if !fullCensus {
			target = (stratum.totalBlocks*pymallocSampleNumerator +
				pymallocSampleDenominator - 1) / pymallocSampleDenominator
		}
		quota := sampleBudget * stratum.totalBlocks / totalBlocks
		if quota == 0 {
			quota = 1
		}
		if !fullCensus && target > quota {
			target = quota
		}
		var sampled uint64
		desiredPools := int((target*uint64(len(stratum.pools)) +
			stratum.totalBlocks - 1) / stratum.totalBlocks)
		if desiredPools < 1 {
			desiredPools = 1
		}
		if desiredPools > len(stratum.pools) {
			desiredPools = len(stratum.pools)
		}
		start := 0
		if len(stratum.pools) > 1 {
			start = int(pymallocHash(stratum.pools[0].hash) %
				uint64(len(stratum.pools)))
		}
		for sequence := 0; sequence < desiredPools; sequence++ {
			if sampled >= target || remaining == 0 {
				break
			}
			index := (start + sequence*len(stratum.pools)/desiredPools) %
				len(stratum.pools)
			pool := stratum.pools[index]
			if remainingBytes < pool.poolSize {
				break
			}
			if pool.allocatedBlocks > remaining && sampled != 0 {
				continue
			}
			planned[name] = append(planned[name], pool)
			stratum.plannedPools++
			sampled = saturatedAdd(sampled, pool.allocatedBlocks)
			stratum.sampledBlocks = saturatedAdd(stratum.sampledBlocks,
				pool.allocatedBlocks)
			stratum.sampledBytes = saturatedAdd(stratum.sampledBytes,
				pool.allocatedBytes)
			remainingBytes -= pool.poolSize
			if pool.allocatedBlocks >= remaining {
				remaining = 0
			} else {
				remaining -= pool.allocatedBlocks
			}
		}
	}
	// Remote reads support arbitrary iovec order. Interleave size classes so a
	// large class (for example 32-byte integers) cannot consume the entire
	// deadline prefix before the next important class is observed. Order the
	// classes by their heap contribution, then use a deterministic spread
	// within each class to retain occupancy and spatial diversity.
	type sizeClassPlan struct {
		blockSize     uint64
		totalBytes    uint64
		coveragePools int
		pools         []pymallocPool
	}
	bySize := make(map[uint64]*sizeClassPlan)
	for _, name := range names {
		for _, pool := range planned[name] {
			class := bySize[pool.blockSize]
			if class == nil {
				class = &sizeClassPlan{blockSize: pool.blockSize}
				bySize[pool.blockSize] = class
			}
			class.pools = append(class.pools, pool)
		}
	}
	for _, stratum := range strata {
		if len(stratum.pools) == 0 {
			continue
		}
		if class := bySize[stratum.pools[0].blockSize]; class != nil {
			class.totalBytes = saturatedAdd(class.totalBytes, stratum.totalBytes)
		}
	}
	classes := make([]*sizeClassPlan, 0, len(bySize))
	for _, class := range bySize {
		bySpatialBucket := make(map[uint32][]pymallocPool)
		for _, pool := range class.pools {
			bySpatialBucket[pool.spatialBucket] = append(
				bySpatialBucket[pool.spatialBucket], pool)
		}
		buckets := make([]uint32, 0, len(bySpatialBucket))
		for bucket, pools := range bySpatialBucket {
			sort.Slice(pools, func(i, j int) bool {
				return pools[i].address < pools[j].address
			})
			// Start at the bucket midpoint, then expand symmetrically. A random
			// first pool makes estimates vary with ASLR when applications allocate
			// large same-type runs; systematic midpoints give every address range
			// equal, reproducible representation.
			spread := make([]pymallocPool, 0, len(pools))
			middle := (len(pools) - 1) / 2
			spread = append(spread, pools[middle])
			for distance := 1; len(spread) < len(pools); distance++ {
				if right := middle + distance; right < len(pools) {
					spread = append(spread, pools[right])
				}
				if left := middle - distance; left >= 0 {
					spread = append(spread, pools[left])
				}
			}
			bySpatialBucket[bucket] = spread
			buckets = append(buckets, bucket)
		}
		sort.Slice(buckets, func(i, j int) bool {
			left := pymallocHash(uint64(buckets[i]) ^ class.blockSize)
			right := pymallocHash(uint64(buckets[j]) ^ class.blockSize)
			if left != right {
				return left < right
			}
			return buckets[i] < buckets[j]
		})
		class.pools = class.pools[:0]
		for round := 0; ; round++ {
			added := false
			for _, bucket := range buckets {
				pools := bySpatialBucket[bucket]
				if round >= len(pools) {
					continue
				}
				class.pools = append(class.pools, pools[round])
				added = true
			}
			if round == 0 {
				class.coveragePools = len(class.pools)
			}
			if !added {
				break
			}
		}
		classes = append(classes, class)
	}
	sort.Slice(classes, func(i, j int) bool {
		diagnosticRank := func(blockSize uint64) int {
			switch blockSize {
			case 48:
				return 0
			case 64:
				return 1
			case 80:
				return 2
			case 96:
				return 3
			default:
				return 4
			}
		}
		leftRank := diagnosticRank(classes[i].blockSize)
		rightRank := diagnosticRank(classes[j].blockSize)
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		if classes[i].totalBytes != classes[j].totalBytes {
			return classes[i].totalBytes > classes[j].totalBytes
		}
		return classes[i].blockSize < classes[j].blockSize
	})
	var result []pymallocPool
	cursors := make(map[*sizeClassPlan]int, len(classes))
	// Guarantee spatial coverage for the largest allocator classes first. The
	// top classes normally contain the application's dominant types. Give
	// each an initial pool, then schedule by heap contribution and per-pool
	// object cost: smaller blocks contain more objects and take longer to parse,
	// so totalBytes*blockSize approximates useful heap coverage per CPU budget.
	priorityClasses := len(classes)
	if priorityClasses > 8 {
		priorityClasses = 8
	}
	for _, class := range classes[:priorityClasses] {
		target := class.coveragePools
		switch class.blockSize {
		case 48:
			// Common user instances with a dict occupy 48-byte pymalloc blocks.
			// Plan the whole class first: ordinary heaps can then return exact
			// business-type counts, while large heaps are still bounded by the
			// same scan deadline.
			target = len(class.pools)
		case 64, 80, 96:
			if target < 32 {
				target = 32
			}
		}
		if target > len(class.pools) {
			target = len(class.pools)
		}
		class.coveragePools = target
		if target == 0 {
			continue
		}
		result = append(result, class.pools[0])
		cursors[class] = 1
	}
	// Finish the common application-instance class before lower-priority
	// allocator traffic. This is the diagnostic payload needed for Top-K type
	// attribution; other classes still consume any remaining gate budget.
	for _, class := range classes[:priorityClasses] {
		if class.blockSize != 48 {
			continue
		}
		for cursors[class] < class.coveragePools {
			result = append(result, class.pools[cursors[class]])
			cursors[class]++
		}
	}
	for {
		var chosen *sizeClassPlan
		bestScore := 0.0
		for _, class := range classes[:priorityClasses] {
			cursor := cursors[class]
			if cursor >= class.coveragePools {
				continue
			}
			weight := float64(class.totalBytes) * float64(class.blockSize)
			if weight == 0 {
				continue
			}
			score := float64(cursor) / weight
			if chosen == nil || score < bestScore {
				chosen = class
				bestScore = score
			}
		}
		if chosen == nil {
			break
		}
		result = append(result, chosen.pools[cursors[chosen]])
		cursors[chosen]++
	}
	for round := 0; ; round++ {
		added := false
		for _, class := range classes {
			index := cursors[class] + round
			if index >= len(class.pools) {
				continue
			}
			result = append(result, class.pools[index])
			added = true
		}
		if !added {
			break
		}
	}
	return result
}

func pymallocStratumName(pool pymallocPool) string {
	// Spatial buckets control which pools are selected, but they are not
	// independent estimation populations: a sequential allocation run can make
	// one bucket nearly pure in a single type. Estimate over the complete size
	// and occupancy class so every selected address range contributes to the
	// same ratio instead of amplifying one local run independently.
	return fmt.Sprintf("size_%d_occupancy_%d", pool.blockSize, pool.occupancy)
}

func pymallocHash(value uint64) uint64 {
	value += 0x9e3779b97f4a7c15
	value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9
	value = (value ^ (value >> 27)) * 0x94d049bb133111eb
	return value ^ (value >> 31)
}

func (c *externalCensus) scanPymallocPool(pool pymallocPool,
	raw []byte,
) ([]pythonObjectObservation, bool) {
	poolSize := c.image.allocator.poolSize
	poolOverhead := c.image.allocator.poolOverhead
	if len(raw) != int(poolSize) {
		return nil, false
	}
	count := uint64(c.image.order.Uint32(raw[:4]))
	sizeClass := c.image.order.Uint32(raw[36:40])
	if sizeClass != pool.sizeClass {
		return nil, false
	}
	free := make(map[uint64]struct{})
	freeAddress := c.image.order.Uint64(raw[8:16])
	for freeAddress != 0 {
		if freeAddress < pool.address+poolOverhead ||
			freeAddress+8 > pool.address+poolSize ||
			(freeAddress-(pool.address+poolOverhead))%pool.blockSize != 0 {
			return nil, false
		}
		if _, loop := free[freeAddress]; loop {
			return nil, false
		}
		free[freeAddress] = struct{}{}
		offset := freeAddress - pool.address
		freeAddress = c.image.order.Uint64(raw[offset : offset+8])
	}
	nextOffset := uint64(c.image.order.Uint32(raw[40:44]))
	maxNextOffset := uint64(c.image.order.Uint32(raw[44:48]))
	if nextOffset < poolOverhead || maxNextOffset >= poolSize ||
		nextOffset > maxNextOffset+pool.blockSize {
		return nil, false
	}
	carvedEnd := nextOffset
	if carvedEnd > poolSize {
		carvedEnd = poolSize
	}
	allocatedOffsets := make([]uint64, 0, pool.allocatedBlocks)
	for offset := poolOverhead; offset+pool.blockSize <= carvedEnd; offset += pool.blockSize {
		address := pool.address + offset
		if _, isFree := free[address]; !isFree {
			allocatedOffsets = append(allocatedOffsets, offset)
		}
	}
	if len(allocatedOffsets) == 0 || count == 0 {
		return nil, false
	}
	// Most pymalloc pools produced by application batch allocation contain a
	// single type. Fully classify the first probe, then validate four spread
	// probes against its already-known type pointer using only the copied pool
	// bytes. If all agree, count the pool locally instead of repeating remote
	// PyTypeObject work for every object. Reused or mixed pools automatically
	// fall back to the full census below.
	if len(allocatedOffsets) >= 8 {
		probeIndexes := [...]int{0, len(allocatedOffsets) / 4,
			len(allocatedOffsets) / 2, len(allocatedOffsets) * 3 / 4,
			len(allocatedOffsets) - 1}
		var homogeneous pythonObjectObservation
		preferredOffset := uint64(math.MaxUint64)
		matched := true
		for probeIndex, index := range probeIndexes {
			offset := allocatedOffsets[index]
			if probeIndex == 0 {
				observation, objectOffset, ok := c.observePymallocObject(
					pool.address+offset, raw[offset:offset+pool.blockSize],
					pool.blockSize, preferredOffset)
				if !ok {
					matched = false
					break
				}
				homogeneous = observation
				preferredOffset = objectOffset
				continue
			}
			block := raw[offset : offset+pool.blockSize]
			if preferredOffset+16 > uint64(len(block)) {
				matched = false
				break
			}
			object := block[preferredOffset:]
			referenceCount := int64(c.image.order.Uint64(object[:8]))
			if referenceCount <= 0 || referenceCount > 1<<50 ||
				c.image.order.Uint64(object[8:16]) != homogeneous.typeAddress {
				matched = false
				break
			}
		}
		if matched {
			homogeneous.count = uint64(len(allocatedOffsets))
			homogeneous.shallowBytes = pool.blockSize * homogeneous.count
			homogeneous.sampledCount = uint64(len(probeIndexes))
			homogeneous.sampledBytes = pool.blockSize * homogeneous.sampledCount
			return []pythonObjectObservation{homogeneous}, true
		}
	}
	scanOffsets := allocatedOffsets
	withinPoolSample := false
	maxMixedPoolProbes := 64
	if pool.poolSize == 4096 {
		maxMixedPoolProbes = 128
	}
	if c.shortGate() && len(scanOffsets) > maxMixedPoolProbes {
		spread := make([]uint64, 0, maxMixedPoolProbes)
		for index := 0; index < maxMixedPoolProbes; index++ {
			position := index * (len(scanOffsets) - 1) / (maxMixedPoolProbes - 1)
			spread = append(spread, scanOffsets[position])
		}
		scanOffsets = spread
		withinPoolSample = true
	}
	if c.shortGate() {
		type localKey struct {
			objectOffset uint64
			typeAddress  uint64
		}
		type localGroup struct {
			key     localKey
			offsets []uint64
		}
		groups := make(map[localKey][]uint64)
		objectOffsets := [...]uint64{16, 32, 0, 24}
		for _, offset := range scanOffsets {
			block := raw[offset : offset+pool.blockSize]
			for _, objectOffset := range objectOffsets {
				if objectOffset+16 > uint64(len(block)) {
					continue
				}
				object := block[objectOffset:]
				referenceCount := int64(c.image.order.Uint64(object[:8]))
				typeAddress := c.image.order.Uint64(object[8:16])
				if referenceCount <= 0 || referenceCount > 1<<50 ||
					!isPlausiblePointer(typeAddress) {
					continue
				}
				key := localKey{objectOffset: objectOffset,
					typeAddress: typeAddress}
				groups[key] = append(groups[key], offset)
			}
		}
		ordered := make([]localGroup, 0, len(groups))
		for key, offsets := range groups {
			if len(offsets) >= 2 {
				ordered = append(ordered, localGroup{key: key, offsets: offsets})
			}
		}
		sort.Slice(ordered, func(i, j int) bool {
			if len(ordered[i].offsets) != len(ordered[j].offsets) {
				return len(ordered[i].offsets) > len(ordered[j].offsets)
			}
			if ordered[i].key.objectOffset != ordered[j].key.objectOffset {
				return ordered[i].key.objectOffset < ordered[j].key.objectOffset
			}
			return ordered[i].key.typeAddress < ordered[j].key.typeAddress
		})
		claimed := make(map[uint64]struct{}, len(scanOffsets))
		observations := make([]pythonObjectObservation, 0, len(ordered))
		for _, group := range ordered {
			typeInfo, err := c.typeInfo(group.key.typeAddress)
			if err != nil {
				continue
			}
			expectedOffset := uint64(0)
			if typeInfo.flags&pyTPFlagsPreheader != 0 {
				expectedOffset += 16
			}
			if c.typeIsGCTracked(typeInfo) {
				expectedOffset += pyGCHeadSize
			}
			if group.key.objectOffset != expectedOffset {
				continue
			}
			var sampled uint64
			for _, offset := range group.offsets {
				if _, duplicate := claimed[offset]; duplicate {
					continue
				}
				block := raw[offset : offset+pool.blockSize]
				if size := c.objectBaseSizeFromBlock(
					block[group.key.objectOffset:], typeInfo); size == 0 ||
					size > pool.blockSize-group.key.objectOffset {
					continue
				}
				claimed[offset] = struct{}{}
				sampled++
			}
			if sampled == 0 {
				continue
			}
			count := sampled
			if withinPoolSample {
				count = scalePymallocEstimate(sampled,
					uint64(len(allocatedOffsets)), uint64(len(scanOffsets)))
			}
			observations = append(observations, pythonObjectObservation{
				typeName: typeInfo.name, typeAddress: group.key.typeAddress,
				count: count, shallowBytes: pool.blockSize * count,
				sampledCount: sampled, sampledBytes: pool.blockSize * sampled,
			})
		}
		return observations, true
	}
	observations := make([]pythonObjectObservation, 0, len(scanOffsets))
	preferredOffset := uint64(math.MaxUint64)
	for _, offset := range scanOffsets {
		address := pool.address + offset
		block := raw[offset : offset+pool.blockSize]
		if observation, objectOffset, ok := c.observePymallocObject(address, block,
			pool.blockSize, preferredOffset); ok {
			observations = append(observations, observation)
			preferredOffset = objectOffset
		}
	}
	return observations, true
}

func (c *externalCensus) observePymallocObject(address uint64, block []byte,
	blockSize, preferredOffset uint64,
) (pythonObjectObservation, uint64, bool) {
	if preferredOffset != math.MaxUint64 {
		if observation, ok := c.observePymallocObjectAt(address, block,
			blockSize, preferredOffset); ok {
			return observation, preferredOffset, true
		}
	}
	// Try the version's common GC-object offset first. A wrong offset can look
	// like a plausible PyObject header and cause an expensive failed remote
	// PyTypeObject read for every allocated block.
	objectOffsets := [...]uint64{16, 32, 0, 24}
	for _, objectOffset := range objectOffsets {
		if objectOffset == preferredOffset {
			continue
		}
		if observation, ok := c.observePymallocObjectAt(address, block,
			blockSize, objectOffset); ok {
			return observation, objectOffset, true
		}
	}
	return pythonObjectObservation{}, 0, false
}

func (c *externalCensus) observePymallocObjectAt(address uint64, block []byte,
	blockSize, objectOffset uint64,
) (pythonObjectObservation, bool) {
	if objectOffset+16 > uint64(len(block)) {
		return pythonObjectObservation{}, false
	}
	object := block[objectOffset:]
	referenceCount := int64(c.image.order.Uint64(object[:8]))
	if referenceCount <= 0 || referenceCount > 1<<50 {
		return pythonObjectObservation{}, false
	}
	typeAddress := c.image.order.Uint64(object[8:16])
	typeInfo, err := c.typeInfo(typeAddress)
	if err != nil {
		return pythonObjectObservation{}, false
	}
	expectedOffset := uint64(0)
	if typeInfo.flags&pyTPFlagsPreheader != 0 {
		expectedOffset += 16
	}
	if c.typeIsGCTracked(typeInfo) {
		expectedOffset += pyGCHeadSize
	}
	if objectOffset != expectedOffset {
		return pythonObjectObservation{}, false
	}
	baseSize := c.objectBaseSizeFromBlock(block[objectOffset:], typeInfo)
	if baseSize == 0 || baseSize > blockSize-objectOffset {
		return pythonObjectObservation{}, false
	}
	return pythonObjectObservation{
		typeName: typeInfo.name, shallowBytes: blockSize,
		typeAddress: typeAddress,
	}, true
}

func (c *externalCensus) objectBaseSizeFromBlock(object []byte,
	typeInfo pythonType,
) uint64 {
	size := uint64(typeInfo.basicsize)
	if typeInfo.itemsize == 0 {
		return alignUp(size, 8)
	}
	if len(object) < pyObjectSizeOffset+8 {
		return 0
	}
	items := int64(c.image.order.Uint64(
		object[pyObjectSizeOffset : pyObjectSizeOffset+8]))
	if items < 0 {
		items = -items
	}
	if items > 1<<40 || uint64(items) >
		(math.MaxUint64-size)/uint64(typeInfo.itemsize) {
		return 0
	}
	return alignUp(size+uint64(items)*uint64(typeInfo.itemsize), 8)
}

func (c *externalCensus) typeIsGCTracked(typeInfo pythonType) bool {
	const pyTPFlagsHaveGC = uint64(1 << 14)
	return typeInfo.flags&pyTPFlagsHaveGC != 0
}

func estimatePymallocObjects(samples map[string]map[string]pymallocTypeSample,
	strata map[string]*pymallocStratum,
	completedBlocks map[string]uint64,
) []memsnap.ObjectAggregate {
	result := make([]memsnap.ObjectAggregate, 0, len(samples))
	for typeName, byStratum := range samples {
		object := memsnap.ObjectAggregate{TypeName: typeName}
		for stratumName, sample := range byStratum {
			stratum := strata[stratumName]
			sampledBlocks := completedBlocks[stratumName]
			if stratum == nil || sampledBlocks == 0 {
				continue
			}
			sampledCount := sample.sampledCount
			if sampledCount == 0 {
				sampledCount = sample.count
			}
			sampledBytes := sample.sampledBytes
			if sampledBytes == 0 {
				sampledBytes = sample.bytes
			}
			object.SampledCount = saturatedAdd(object.SampledCount, sampledCount)
			object.SampledBytes = saturatedAdd(object.SampledBytes, sampledBytes)
			object.Count = saturatedAdd(object.Count,
				scalePymallocEstimate(sample.count, stratum.totalBlocks, sampledBlocks))
			object.ShallowBytes = saturatedAdd(object.ShallowBytes,
				scalePymallocEstimate(sample.bytes, stratum.totalBlocks, sampledBlocks))
			if sample.count != 0 {
				object.SampledRegions++
			}
		}
		if object.Count < object.SampledCount {
			object.Count = object.SampledCount
		}
		if object.ShallowBytes < object.SampledBytes {
			object.ShallowBytes = object.SampledBytes
		}
		object.Estimated = object.Count != object.SampledCount ||
			object.ShallowBytes != object.SampledBytes
		if object.Count != 0 {
			object.AverageBytes = float64(object.ShallowBytes) / float64(object.Count)
		}
		if object.Estimated {
			object.EstimateConfidence = "stratified_pool_ratio_no_ci"
		}
		result = append(result, object)
	}
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].ShallowBytes > result[j].ShallowBytes
	})
	return result
}

func scalePymallocEstimate(observed, totalBlocks, sampledBlocks uint64) uint64 {
	if observed == 0 || totalBlocks == 0 || sampledBlocks == 0 {
		return 0
	}
	estimate := float64(observed) * float64(totalBlocks) / float64(sampledBlocks)
	if estimate >= float64(math.MaxUint64) {
		return math.MaxUint64
	}
	result := uint64(math.Round(estimate))
	if result < observed {
		return observed
	}
	return result
}

func pymallocCoverage(strata map[string]*pymallocStratum,
	completedPools map[string]uint64,
	completedBytes map[string]uint64,
	classifiedBytes map[string]uint64,
	seed uint64,
	population pymallocPopulation,
) memsnap.Coverage {
	coverage := memsnap.Coverage{
		Consistency:          "cpython_pymalloc_block_census",
		SizeSemantics:        "pymalloc_block_bytes",
		Impact:               "on_demand_batched_process_vm_readv",
		SamplingSeed:         seed,
		SampleRateAssumption: "types within each pymalloc size-class and occupancy stratum are represented by deterministically selected pools",
		KnownGaps: []string{
			"only live PyObject headers validated inside CPython 3.12 pymalloc blocks are classified",
			"allocations larger than 512 bytes, external buffers, system malloc, and native extensions are absent",
			"allocator blocks used for non-object PyMem data are intentionally unclassified",
			"estimated shallow bytes describe pymalloc block contribution, not retained size",
			"allocation traceback, retaining paths, and instance fields are unavailable in sampled mode",
		},
	}
	if population.totalArenas > population.sampledArenas {
		coverage.SampleRateAssumption += "; arena address strata are represented by midpoint arenas weighted by the full used-pool population"
		coverage.KnownGaps = append(coverage.KnownGaps,
			"types confined to an unsampled arena inside an address stratum can be missed")
	}
	names := make([]string, 0, len(strata))
	for name := range strata {
		names = append(names, name)
	}
	sort.Strings(names)
	var totalPools uint64
	for _, name := range names {
		stratum := strata[name]
		totalPools = saturatedAdd(totalPools, stratum.totalPools)
		coverage.HeapUsedBytes = saturatedAdd(coverage.HeapUsedBytes,
			stratum.totalBytes)
		coverage.ScannedBytes = saturatedAdd(coverage.ScannedBytes,
			completedBytes[name])
		coverage.ScannedRegions = saturatedAdd(coverage.ScannedRegions,
			completedPools[name])
		coverage.ClassifiedBytes = saturatedAdd(coverage.ClassifiedBytes,
			classifiedBytes[name])
		coverage.PlannedRegions = saturatedAdd(coverage.PlannedRegions,
			stratum.plannedPools)
		coverage.SamplingStrata = append(coverage.SamplingStrata,
			memsnap.SamplingStratumCoverage{
				Name: name, TotalRegions: stratum.totalPools,
				PlannedRegions:   stratum.plannedPools,
				CompletedRegions: completedPools[name],
				TotalUsedBytes:   stratum.totalBytes,
				ClassifiedBytes:  classifiedBytes[name],
			})
	}
	coverage.TotalRegions = totalPools
	if population.totalPools != 0 {
		coverage.TotalRegions = population.totalPools
	}
	coverage.CompletedRegions = coverage.ScannedRegions
	if coverage.HeapUsedBytes != 0 {
		coverage.RawCoverage = float64(coverage.ScannedBytes) /
			float64(coverage.HeapUsedBytes)
	}
	coverage.Estimated = coverage.ScannedBytes < coverage.HeapUsedBytes ||
		population.totalArenas > population.sampledArenas ||
		population.totalPools > population.sampledPoolHeaders
	if coverage.Estimated {
		coverage.Consistency = "cpython_pymalloc_stratified_sample"
		coverage.SizeSemantics = "estimated_pymalloc_block_bytes"
		coverage.EstimationMethod = "python_pymalloc_stratified_v2"
	}
	return coverage
}

func (c *externalCensus) traverseGeneration(ctx context.Context, head uint64,
	budget int, backward bool,
) bool {
	headRaw, err := c.memory.read(head, 16)
	if err != nil {
		c.partial = "GC generation head became unreadable"
		return false
	}
	linkOffset := 0
	validationOffset := 8
	if backward {
		linkOffset = 8
		validationOffset = 0
	}
	next := c.image.order.Uint64(headRaw[linkOffset:linkOffset+8]) &^ 3
	previous := head
	visited := 0
	for next != head {
		if c.partial != "" {
			return false
		}
		if len(c.seenObjects) >= c.maxObjects {
			c.partial = "object scan limit reached"
			return false
		}
		if budget > 0 && visited >= budget {
			c.generationLimited = true
			return true
		}
		if len(c.seenObjects)&31 == 0 && (ctx.Err() != nil || c.deadlineReached()) {
			c.partial = "deadline reached during external object census"
			return false
		}
		if !isPlausiblePointer(next) {
			c.partial = "GC generation contains an invalid pointer"
			return false
		}
		header, readErr := c.memory.read(next, 40)
		if readErr != nil {
			c.partial = "GC object header became unreadable"
			return false
		}
		following := c.image.order.Uint64(header[linkOffset:linkOffset+8]) &^ 3
		linkedPrevious := c.image.order.Uint64(
			header[validationOffset:validationOffset+8]) &^ 3
		if linkedPrevious != previous {
			c.partial = "GC generation changed during external census"
			return false
		}
		objectAddress := next + pyGCHeadSize
		if _, duplicate := c.seenObjects[objectAddress]; duplicate {
			if c.shortMode {
				previous = next
				next = following
				continue
			}
			c.partial = "GC generation contains a loop"
			return false
		}
		c.seenObjects[objectAddress] = struct{}{}
		visited++
		c.consumeObject(objectAddress, header[16:])
		previous = next
		next = following
	}
	return true
}

func (c *externalCensus) consumeObject(address uint64, objectHead []byte) {
	if len(objectHead) < 24 {
		return
	}
	typeAddress := c.image.order.Uint64(objectHead[pyObjectTypeOffset : pyObjectTypeOffset+8])
	typeInfo, err := c.typeInfo(typeAddress)
	if err != nil {
		return
	}
	objectSize := c.objectShallowSize(address, objectHead, typeInfo)
	aggregate := c.aggregates[typeInfo.name]
	if aggregate == nil {
		aggregate = &externalAggregate{
			object: memsnap.ObjectAggregate{
				TypeName: typeInfo.name,
			}, lengthBuckets: make(map[string]uint64),
			fields: make(map[string]*externalField),
		}
		c.aggregates[typeInfo.name] = aggregate
	}
	aggregate.object.Count++
	aggregate.object.ShallowBytes = saturatedAdd(aggregate.object.ShallowBytes, objectSize)
	if !c.shortMode {
		if length, ok := c.objectLength(address, objectHead, typeInfo); ok {
			aggregate.lengthBuckets[lengthBucket(length)]++
		}
	}
	if !c.shortMode && !strings.HasPrefix(typeInfo.name, "builtins.") {
		for _, field := range c.instanceFields(address, typeInfo) {
			c.consumeField(aggregate, field)
		}
	}
}

type instanceField struct {
	name    string
	address uint64
}

type dictionaryEntry struct {
	name  string
	value uint64
}

func (c *externalCensus) instanceFields(address uint64,
	typeInfo pythonType,
) []instanceField {
	if typeInfo.flags&pyTPFlagsManagedDict != 0 {
		if fields := c.managedInstanceFields(address, typeInfo); len(fields) != 0 {
			return fields
		}
		if typeInfo.flags&pyTPFlagsInlineValues != 0 {
			return c.fieldsFromCachedKeys(typeInfo,
				address+alignUp(uint64(typeInfo.basicsize), 8))
		}
		return nil
	}
	if typeInfo.dictoffset == 0 {
		return nil
	}
	dictPointerAddress := uint64(0)
	if typeInfo.dictoffset > 0 {
		dictPointerAddress = address + uint64(typeInfo.dictoffset)
	} else {
		size := c.objectBaseSize(address, typeInfo)
		if size <= uint64(-typeInfo.dictoffset) {
			return nil
		}
		dictPointerAddress = address + size - uint64(-typeInfo.dictoffset)
	}
	raw, err := c.memory.read(dictPointerAddress, 8)
	if err != nil {
		return nil
	}
	dictAddress := c.image.order.Uint64(raw)
	return c.dictionaryFields(dictAddress)
}

func (c *externalCensus) managedInstanceFields(address uint64,
	typeInfo pythonType,
) []instanceField {
	if address < 48 {
		return nil
	}
	preheader, err := c.memory.read(address-48, 48)
	if err != nil {
		return nil
	}
	for offset := 0; offset+8 <= len(preheader); offset += 8 {
		encoded := c.image.order.Uint64(preheader[offset : offset+8])
		if encoded == 0 {
			continue
		}
		if encoded&1 != 0 {
			values := encoded + 1
			if isPlausiblePointer(values) {
				if fields := c.fieldsFromCachedKeys(typeInfo, values); len(fields) != 0 {
					return fields
				}
			}
		} else if isPlausiblePointer(encoded) {
			if fields := c.dictionaryFields(encoded); len(fields) != 0 {
				return fields
			}
		}
	}
	return nil
}

func (c *externalCensus) fieldsFromCachedKeys(typeInfo pythonType,
	values uint64,
) []instanceField {
	meta, err := c.typeInfo(typeInfo.meta)
	if err != nil || meta.basicsize <= pyTypeReadSize || meta.basicsize > maxTypeAllocation {
		return nil
	}
	raw, err := c.memory.read(typeInfo.address, int(meta.basicsize))
	if err != nil {
		return nil
	}
	var best []instanceField
	for offset := pyTypeReadSize; offset+8 <= len(raw); offset += 8 {
		keys := c.image.order.Uint64(raw[offset : offset+8])
		names, parseErr := c.parseDictKeys(keys)
		if parseErr != nil || len(names) == 0 || len(names) > maxInstanceFields {
			continue
		}
		valueRaw, readErr := c.memory.read(values, len(names)*8)
		if readErr != nil {
			continue
		}
		fields := make([]instanceField, 0, len(names))
		for index, name := range names {
			value := c.image.order.Uint64(valueRaw[index*8 : index*8+8])
			if name != "" && isPlausiblePointer(value) {
				fields = append(fields, instanceField{name: name, address: value})
			}
		}
		if len(fields) > len(best) {
			best = fields
		}
	}
	return best
}

func (c *externalCensus) dictionaryFields(address uint64) []instanceField {
	if !isPlausiblePointer(address) {
		return nil
	}
	raw, err := c.memory.read(address, 48)
	if err != nil {
		return nil
	}
	keys := c.image.order.Uint64(raw[32:40])
	values := c.image.order.Uint64(raw[40:48])
	entries, err := c.parseDictEntries(keys)
	if err != nil || len(entries) == 0 || len(entries) > maxInstanceFields {
		return nil
	}
	if values == 0 {
		fields := make([]instanceField, 0, len(entries))
		for _, entry := range entries {
			if entry.name != "" && isPlausiblePointer(entry.value) {
				fields = append(fields, instanceField{
					name:    entry.name,
					address: entry.value,
				})
			}
		}
		return fields
	}
	valueRaw, err := c.memory.read(values, len(entries)*8)
	if err != nil {
		return nil
	}
	fields := make([]instanceField, 0, len(entries))
	for index, entry := range entries {
		value := c.image.order.Uint64(valueRaw[index*8 : index*8+8])
		if entry.name != "" && isPlausiblePointer(value) {
			fields = append(fields, instanceField{name: entry.name, address: value})
		}
	}
	return fields
}

func (c *externalCensus) parseDictKeys(address uint64) ([]string, error) {
	entries, err := c.parseDictEntries(address)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for index, entry := range entries {
		names[index] = entry.name
	}
	return names, nil
}

func (c *externalCensus) parseDictEntries(address uint64) ([]dictionaryEntry,
	error,
) {
	if !isPlausiblePointer(address) {
		return nil, errors.New("invalid dictionary keys pointer")
	}
	header, err := c.memory.read(address, 40)
	if err != nil {
		return nil, err
	}
	// CPython 3.11+ compact keys header.
	logSize := header[8]
	logIndexBytes := header[9]
	kind := header[10]
	nentries := int64(c.image.order.Uint64(header[24:32]))
	if logSize <= 30 && logIndexBytes <= 30 && kind <= 2 && nentries > 0 &&
		nentries <= maxInstanceFields {
		indicesBytes := uint64(1) << logIndexBytes
		entryAddress := address + 32 + indicesBytes
		if entries := c.readKeyEntries(entryAddress, int(nentries), kind == 0); len(entries) != 0 {
			return entries, nil
		}
	}
	// CPython 3.8-3.10 keys header.
	dictSize := int64(c.image.order.Uint64(header[8:16]))
	oldEntries := int64(c.image.order.Uint64(header[32:40]))
	if dictSize <= 0 || dictSize > 1<<30 || oldEntries <= 0 ||
		oldEntries > maxInstanceFields || dictSize&(dictSize-1) != 0 {
		return nil, errors.New("unrecognized dictionary keys layout")
	}
	indexSize := uint64(1)
	if dictSize > 0xff {
		indexSize = 2
	}
	if dictSize > 0xffff {
		indexSize = 4
	}
	if uint64(dictSize) > math.MaxUint32 {
		indexSize = 8
	}
	entryAddress := alignUp(address+40+uint64(dictSize)*indexSize, 8)
	unicodeEntries := c.readKeyEntries(entryAddress, int(oldEntries), false)
	generalEntries := c.readKeyEntries(entryAddress, int(oldEntries), true)
	if validDictionaryEntries(generalEntries) > validDictionaryEntries(unicodeEntries) {
		return generalEntries, nil
	}
	if validDictionaryEntries(unicodeEntries) != 0 {
		return unicodeEntries, nil
	}
	return nil, errors.New("dictionary key entries are unreadable")
}

func (c *externalCensus) readKeyEntries(address uint64, count int,
	general bool,
) []dictionaryEntry {
	stride := 16
	keyOffset := 0
	valueOffset := 8
	if general {
		stride = 24
		keyOffset = 8
		valueOffset = 16
	}
	raw, err := c.memory.read(address, count*stride)
	if err != nil {
		return nil
	}
	entries := make([]dictionaryEntry, count)
	valid := 0
	for index := 0; index < count; index++ {
		key := c.image.order.Uint64(raw[index*stride+keyOffset : index*stride+keyOffset+8])
		if key == 0 {
			continue
		}
		name, nameErr := c.readASCIIUnicode(key, 256)
		if nameErr == nil && name != "" {
			entries[index] = dictionaryEntry{
				name:  name,
				value: c.image.order.Uint64(raw[index*stride+valueOffset : index*stride+valueOffset+8]),
			}
			valid++
		}
	}
	if valid == 0 {
		return nil
	}
	return entries
}

func validDictionaryEntries(entries []dictionaryEntry) int {
	valid := 0
	for _, entry := range entries {
		if entry.name != "" {
			valid++
		}
	}
	return valid
}

func (c *externalCensus) consumeField(aggregate *externalAggregate,
	field instanceField,
) {
	typeRaw, err := c.memory.read(field.address+pyObjectTypeOffset, 8)
	if err != nil {
		return
	}
	typeInfo, err := c.typeInfo(c.image.order.Uint64(typeRaw))
	if err != nil {
		return
	}
	key := field.name + "\x00" + typeInfo.name
	entry := aggregate.fields[key]
	if entry == nil {
		if c.fieldShapes >= c.maxObjects {
			c.partial = "field shape limit reached"
			return
		}
		entry = &externalField{
			shape: memsnap.FieldShape{
				Name:           field.name,
				ReferencedType: typeInfo.name,
			}, lengthBuckets: make(map[string]uint64),
			seen: make(map[uint64]struct{}),
		}
		aggregate.fields[key] = entry
		c.fieldShapes++
	}
	entry.shape.ReferenceCount++
	if _, duplicate := entry.seen[field.address]; duplicate {
		return
	}
	if c.fieldValues >= c.maxObjects {
		c.partial = "field referent limit reached"
		return
	}
	entry.seen[field.address] = struct{}{}
	c.fieldValues++
	entry.shape.UniqueReferencedObjects++
	head, err := c.memory.read(field.address, 40)
	if err != nil {
		return
	}
	size := c.objectShallowSize(field.address, head, typeInfo)
	entry.shape.ReferencedShallowBytes = saturatedAdd(
		entry.shape.ReferencedShallowBytes, size)
	if length, ok := c.objectLength(field.address, head, typeInfo); ok {
		entry.shape.TotalReferencedLength = saturatedAdd(
			entry.shape.TotalReferencedLength, length)
		entry.lengthBuckets[lengthBucket(length)]++
	}
}

func (c *externalCensus) typeInfo(address uint64) (pythonType, error) {
	if cached, ok := c.types[address]; ok {
		return cached, nil
	}
	if _, invalid := c.invalidTypes[address]; invalid {
		return pythonType{}, errors.New("invalid cached Python type pointer")
	}
	if !isPlausiblePointer(address) {
		return pythonType{}, errors.New("invalid Python type pointer")
	}
	raw, err := c.memory.read(address, pyTypeReadSize)
	if err != nil {
		c.invalidTypes[address] = struct{}{}
		return pythonType{}, err
	}
	nameAddress := c.image.order.Uint64(raw[pyTypeNameOffset : pyTypeNameOffset+8])
	name, err := c.readCString(nameAddress, maxCStringBytes)
	if err != nil || name == "" {
		c.invalidTypes[address] = struct{}{}
		return pythonType{}, errors.New("invalid Python type name")
	}
	result := pythonType{
		address:    address,
		meta:       c.image.order.Uint64(raw[pyObjectTypeOffset : pyObjectTypeOffset+8]),
		name:       name,
		basicsize:  int64(c.image.order.Uint64(raw[pyTypeBasicOffset : pyTypeBasicOffset+8])),
		itemsize:   int64(c.image.order.Uint64(raw[pyTypeItemOffset : pyTypeItemOffset+8])),
		flags:      c.image.order.Uint64(raw[pyTypeFlagsOffset : pyTypeFlagsOffset+8]),
		dictoffset: int64(c.image.order.Uint64(raw[pyTypeDictOffset : pyTypeDictOffset+8])),
	}
	if result.basicsize < 16 || result.basicsize > 1<<30 ||
		result.itemsize < 0 || result.itemsize > 1<<24 {
		c.invalidTypes[address] = struct{}{}
		return pythonType{}, errors.New("invalid Python type size")
	}
	// Cache the stable prefix before resolving heap-type metadata. The
	// metaclass of PyType_Type points back to itself, so recursive lookups must
	// be able to terminate here.
	c.types[address] = result
	if !strings.Contains(result.name, ".") {
		if result.flags&pyTPFlagsHeapType != 0 {
			if module := c.heapTypeModule(result); module != "" {
				result.name = module + "." + result.name
			} else {
				result.name = "unknown." + result.name
			}
		} else {
			result.name = "builtins." + result.name
		}
		c.types[address] = result
	}
	if len(result.name) > 512 {
		result.name = result.name[:512]
		c.types[address] = result
	}
	return result, nil
}

func (c *externalCensus) heapTypeModule(typeInfo pythonType) string {
	meta, err := c.typeInfo(typeInfo.meta)
	if err != nil || meta.basicsize <= pyTypeReadSize ||
		meta.basicsize > maxTypeAllocation {
		return ""
	}
	raw, err := c.memory.read(typeInfo.address, int(meta.basicsize))
	if err != nil {
		return ""
	}
	if len(raw) >= pyTypeDictionaryOffset+8 {
		dictAddress := c.image.order.Uint64(raw[pyTypeDictionaryOffset : pyTypeDictionaryOffset+8])
		for _, entry := range c.dictionaryFields(dictAddress) {
			if entry.name != "__module__" {
				continue
			}
			if module, moduleErr := c.readASCIIUnicode(entry.address, 256); moduleErr == nil {
				return module
			}
		}
	}
	// ht_module immediately follows ht_cached_keys throughout the supported
	// CPython range. Locate the keys structurally instead of hard-coding the
	// growing PyHeapTypeObject offset.
	for offset := pyTypeReadSize; offset+16 <= len(raw); offset += 8 {
		keys := c.image.order.Uint64(raw[offset : offset+8])
		if _, parseErr := c.parseDictKeys(keys); parseErr != nil {
			continue
		}
		moduleAddress := c.image.order.Uint64(raw[offset+8 : offset+16])
		module, moduleErr := c.readASCIIUnicode(moduleAddress, 256)
		if moduleErr == nil && module != "" && module != typeInfo.name {
			return module
		}
	}
	return ""
}

func (c *externalCensus) objectBaseSize(address uint64, typeInfo pythonType) uint64 {
	size := uint64(typeInfo.basicsize)
	if typeInfo.itemsize == 0 {
		return alignUp(size, 8)
	}
	raw, err := c.memory.read(address+pyObjectSizeOffset, 8)
	if err != nil {
		return alignUp(size, 8)
	}
	items := int64(c.image.order.Uint64(raw))
	if items < 0 {
		items = -items
	}
	if items > 1<<40 || uint64(items) > (math.MaxUint64-size)/uint64(typeInfo.itemsize) {
		return alignUp(size, 8)
	}
	return alignUp(size+uint64(items)*uint64(typeInfo.itemsize), 8)
}

func (c *externalCensus) objectShallowSize(address uint64, head []byte,
	typeInfo pythonType,
) uint64 {
	size := c.objectBaseSize(address, typeInfo)
	switch typeInfo.name {
	case "builtins.bytearray":
		if len(head) >= 32 {
			allocated := int64(c.image.order.Uint64(head[24:32]))
			if allocated > 0 && allocated < 1<<40 {
				size = saturatedAdd(size, uint64(allocated))
			}
		}
	case "builtins.list":
		if len(head) >= 40 {
			allocated := int64(c.image.order.Uint64(head[32:40]))
			if allocated > 0 && allocated < 1<<40 {
				size = saturatedAdd(size, uint64(allocated)*8)
			}
		}
	}
	// Every object reached here has a GC head. Managed dict/weakref pointers are
	// additional preheader words in CPython 3.11+.
	size = saturatedAdd(size, pyGCHeadSize)
	if typeInfo.flags&pyTPFlagsPreheader != 0 {
		size = saturatedAdd(size, 16)
	}
	return size
}

func (c *externalCensus) objectLength(address uint64, head []byte,
	typeInfo pythonType,
) (uint64, bool) {
	switch typeInfo.name {
	case "builtins.str":
		if len(head) < 24 {
			return 0, false
		}
		length := int64(c.image.order.Uint64(head[16:24]))
		return nonNegativeLength(length)
	case "builtins.bytes", "builtins.bytearray", "builtins.list",
		"builtins.tuple", "builtins.set", "builtins.frozenset", "builtins.dict":
		if len(head) < 24 {
			raw, err := c.memory.read(address+pyObjectSizeOffset, 8)
			if err != nil {
				return 0, false
			}
			head = append(make([]byte, 16), raw...)
		}
		length := int64(c.image.order.Uint64(head[16:24]))
		return nonNegativeLength(length)
	default:
		return 0, false
	}
}

func nonNegativeLength(length int64) (uint64, bool) {
	if length < 0 || length > 1<<50 {
		return 0, false
	}
	return uint64(length), true
}

func (c *externalCensus) readCString(address uint64, limit int) (string, error) {
	if !isPlausibleAddress(address) {
		return "", errors.New("invalid C string pointer")
	}
	valueRaw := make([]byte, 0, 64)
	for offset := 0; offset < limit; {
		chunkSize := 32
		if remaining := limit - offset; remaining < chunkSize {
			chunkSize = remaining
		}
		chunk, err := c.memory.read(address+uint64(offset), chunkSize)
		if err != nil {
			// A short type name can sit at the end of an ELF mapping. Avoid
			// rejecting it merely because a speculative chunk crossed the next
			// unmapped page.
			chunk, err = c.memory.read(address+uint64(offset), 1)
			if err != nil {
				return "", err
			}
			chunkSize = 1
		}
		if end := strings.IndexByte(string(chunk), 0); end >= 0 {
			valueRaw = append(valueRaw, chunk[:end]...)
			value := string(valueRaw)
			if !utf8.ValidString(value) {
				return "", errors.New("invalid UTF-8 C string")
			}
			for _, character := range value {
				if character < 0x20 || character == 0x7f {
					return "", errors.New("non-printable C string")
				}
			}
			return value, nil
		}
		valueRaw = append(valueRaw, chunk...)
		offset += chunkSize
	}
	return "", errors.New("unterminated C string")
}

func (c *externalCensus) readASCIIUnicode(address uint64, limit int) (string, error) {
	header, err := c.memory.read(address, 40)
	if err != nil {
		return "", err
	}
	length := int64(c.image.order.Uint64(header[16:24]))
	state := c.image.order.Uint32(header[32:36])
	compact := state&(1<<5) != 0
	ascii := state&(1<<6) != 0
	if !compact || !ascii || length <= 0 || length > int64(limit) {
		return "", errors.New("dictionary key is not compact ASCII")
	}
	dataOffset := uint64(48)
	if c.image.version.minor >= 12 {
		dataOffset = 40
	}
	raw, err := c.memory.read(address+dataOffset, int(length))
	if err != nil {
		return "", err
	}
	for _, character := range raw {
		if character < 0x20 || character > 0x7e {
			return "", errors.New("dictionary key is not printable ASCII")
		}
	}
	return string(raw), nil
}

func (c *externalCensus) finishAggregates() []memsnap.ObjectAggregate {
	result := make([]memsnap.ObjectAggregate, 0, len(c.aggregates))
	for _, aggregate := range c.aggregates {
		if aggregate.object.Count != 0 {
			aggregate.object.AverageBytes = float64(aggregate.object.ShallowBytes) /
				float64(aggregate.object.Count)
		}
		aggregate.object.LengthBuckets = finishBuckets(aggregate.lengthBuckets)
		for _, field := range aggregate.fields {
			if field.shape.UniqueReferencedObjects != 0 {
				field.shape.AverageReferencedBytes = float64(field.shape.ReferencedShallowBytes) /
					float64(field.shape.UniqueReferencedObjects)
				field.shape.AverageReferencedLength = float64(field.shape.TotalReferencedLength) /
					float64(field.shape.UniqueReferencedObjects)
			}
			field.shape.LengthBuckets = finishBuckets(field.lengthBuckets)
			aggregate.object.Fields = append(aggregate.object.Fields, field.shape)
		}
		sort.SliceStable(aggregate.object.Fields, func(i, j int) bool {
			return aggregate.object.Fields[i].ReferencedShallowBytes >
				aggregate.object.Fields[j].ReferencedShallowBytes
		})
		result = append(result, aggregate.object)
	}
	sort.SliceStable(result, func(i, j int) bool {
		return pythonDiagnosticBytes(&result[i]) > pythonDiagnosticBytes(&result[j])
	})
	return result
}

func finishBuckets(source map[string]uint64) []memsnap.ShapeBucket {
	result := make([]memsnap.ShapeBucket, 0, len(source))
	for name, count := range source {
		result = append(result, memsnap.ShapeBucket{Name: name, Count: count})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result
}

func lengthBucket(length uint64) string {
	if length <= 1 {
		return strconv.FormatUint(length, 10)
	}
	leading := uint64(1) << (63 - uint64(bitsLeadingZeros64(length)))
	return fmt.Sprintf("%d-%d", leading, leading*2-1)
}

func bitsLeadingZeros64(value uint64) int {
	if value == 0 {
		return 64
	}
	count := 0
	for mask := uint64(1) << 63; value&mask == 0; mask >>= 1 {
		count++
	}
	return count
}

func isPlausiblePointer(address uint64) bool {
	return isPlausibleAddress(address) && address&7 == 0
}

func isPlausibleAddress(address uint64) bool {
	return address >= 0x10000 && address < 1<<56
}

func alignUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) &^ (alignment - 1)
}

func saturatedAdd(left, right uint64) uint64 {
	if math.MaxUint64-left < right {
		return math.MaxUint64
	}
	return left + right
}
