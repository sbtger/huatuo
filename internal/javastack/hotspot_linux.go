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
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	maxHotspotCodeHeaps    = 8
	maxHotspotTableEntries = 4096
	maxHotspotStringLength = 256
	maxHotspotLayoutCache  = 16
)

var requiredHotspotELFSymbols = map[string]struct{}{
	"gHotSpotVMStructs": {}, "gHotSpotVMStructEntryArrayStride": {},
	"gHotSpotVMStructEntryTypeNameOffset": {}, "gHotSpotVMStructEntryFieldNameOffset": {},
	"gHotSpotVMStructEntryOffsetOffset": {}, "gHotSpotVMStructEntryAddressOffset": {},
	"gHotSpotVMTypes": {}, "gHotSpotVMTypeEntryArrayStride": {},
	"gHotSpotVMTypeEntryTypeNameOffset": {}, "gHotSpotVMTypeEntrySizeOffset": {},
}

var requiredHotspotFields = map[string]struct{}{
	"CodeHeap._memory": {}, "CodeHeap._segmap": {}, "CodeHeap._log2_segment_size": {},
	"VirtualSpace._low_boundary": {}, "VirtualSpace._high_boundary": {},
	"CodeCache._heaps": {}, "CodeCache._heap": {},
	"GenericGrowableArray._len": {}, "GrowableArrayBase._len": {},
	"GrowableArray<int>._data": {}, "CodeBlob._name": {},
	"nmethod._method": {}, "CompiledMethod._method": {},
	"nmethod._compile_id": {}, "CompiledMethod._compile_id": {},
	"Method._constMethod": {}, "methodOopDesc._constMethod": {},
	"ConstMethod._constants": {}, "constMethodOopDesc._constants": {},
	"ConstMethod._name_index": {}, "constMethodOopDesc._name_index": {},
	"ConstantPool._pool_holder": {}, "constantPoolOopDesc._pool_holder": {},
	"Klass._name": {}, "Symbol._length_and_refcount": {},
	"Symbol._length": {}, "Symbol._body": {},
}

var requiredHotspotTypes = map[string]struct{}{
	"HeapBlock": {}, "GrowableArray<int>": {},
	"ConstantPool": {}, "constantPoolOopDesc": {},
}

// HotspotCodeHeap contains the stable address ranges needed to map a JIT PC
// back to its CodeBlob while the target JVM is still alive.
type HotspotCodeHeap struct {
	CodeStart   uint64
	CodeEnd     uint64
	SegmapStart uint64
	SegmapEnd   uint64
}

// HotspotMetadata is the bounded per-JVM state required by the OOM BPF path.
// It contains addresses and layout offsets only; it does not cache JIT symbols.
type HotspotMetadata struct {
	Heaps [maxHotspotCodeHeaps]HotspotCodeHeap

	HeapCount            uint32
	SegmentShift         uint8
	HeapBlockSize        uint8
	CodeBlobName         uint8
	NmethodMethod        uint16
	NmethodCompileID     uint16
	MethodConstMethod    uint8
	ConstMethodConstants uint8
	ConstMethodNameIndex uint8
	ConstantPoolSize     uint16
	ConstantPoolHolder   uint8
	KlassName            uint16
	SymbolLength         uint8
	SymbolBody           uint8
}

type hotspotField struct {
	value    uint64
	isStatic bool
}

type hotspotTables struct {
	fields map[string]hotspotField
	sizes  map[string]uint64
}

type hotspotTableSymbols struct {
	base          string
	stride        string
	typeOffset    string
	fieldOffset   string
	valueOffset   string
	addressOffset string
}

type hotspotLayoutKey struct {
	device     uint64
	inode      uint64
	size       int64
	modifiedNS int64
}

// hotspotInspector shares only stable, reduced HotSpot layouts. Runtime
// addresses are relocated and CodeCache bounds are reread for every JVM.
type hotspotInspector struct {
	procRoot string
	mu       sync.Mutex
	layouts  map[hotspotLayoutKey]hotspotTables
	order    []hotspotLayoutKey
}

func newHotspotInspector(procRoot string) *hotspotInspector {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &hotspotInspector{
		procRoot: procRoot,
		layouts:  make(map[hotspotLayoutKey]hotspotTables),
	}
}

type remoteMemory struct {
	pid int
}

func (m remoteMemory) read(address uint64, output []byte) error {
	if address == 0 || len(output) == 0 {
		return errors.New("javastack: invalid remote memory read")
	}
	local := unix.Iovec{Base: &output[0]}
	local.SetLen(len(output))
	remote := unix.RemoteIovec{Base: uintptr(address), Len: len(output)}
	n, err := unix.ProcessVMReadv(m.pid, []unix.Iovec{local}, []unix.RemoteIovec{remote}, 0)
	if err != nil {
		return err
	}
	if n != len(output) {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (m remoteMemory) uint16(address uint64) (uint16, error) {
	var data [2]byte
	if err := m.read(address, data[:]); err != nil {
		return 0, err
	}
	return binary.NativeEndian.Uint16(data[:]), nil
}

func (m remoteMemory) uint32(address uint64) (uint32, error) {
	var data [4]byte
	if err := m.read(address, data[:]); err != nil {
		return 0, err
	}
	return binary.NativeEndian.Uint32(data[:]), nil
}

func (m remoteMemory) uint64(address uint64) (uint64, error) {
	var data [8]byte
	if err := m.read(address, data[:]); err != nil {
		return 0, err
	}
	return binary.NativeEndian.Uint64(data[:]), nil
}

func (m remoteMemory) cString(address uint64) (string, error) {
	var data [maxHotspotStringLength]byte
	if err := m.read(address, data[:]); err != nil {
		return "", err
	}
	end := 0
	for end < len(data) && data[end] != 0 {
		end++
	}
	if end == len(data) {
		return "", errors.New("javastack: unterminated HotSpot introspection string")
	}
	return string(data[:end]), nil
}

// InspectHotspot reads HotSpot's exported VMStructs/VMTypes tables and reduces
// them to the small configuration consumed synchronously by the OOM BPF hook.
func InspectHotspot(procRoot string, target Target) (HotspotMetadata, error) {
	return newHotspotInspector(procRoot).Inspect(target)
}

func (i *hotspotInspector) Inspect(target Target) (HotspotMetadata, error) {
	if target.PID == 0 {
		return HotspotMetadata{}, errors.New("javastack: invalid HotSpot pid")
	}
	libjvmPath, loadBias, err := findLibJVM(i.procRoot, target.PID)
	if err != nil {
		return HotspotMetadata{}, err
	}
	key, err := hotspotLayoutIdentity(libjvmPath)
	if err != nil {
		return HotspotMetadata{}, err
	}
	memory := remoteMemory{pid: int(target.PID)}
	layout, ok := i.cachedLayout(key)
	if !ok {
		layout, err = loadHotspotLayout(memory, libjvmPath, loadBias)
		if err != nil {
			return HotspotMetadata{}, err
		}
		layout = i.rememberLayout(key, layout)
	}
	tables, err := relocateHotspotLayout(layout, loadBias)
	if err != nil {
		return HotspotMetadata{}, err
	}
	return buildHotspotMetadata(memory, tables)
}

func hotspotLayoutIdentity(path string) (hotspotLayoutKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return hotspotLayoutKey{}, fmt.Errorf("javastack: stat libjvm: %w", err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return hotspotLayoutKey{}, errors.New("javastack: unsupported libjvm file identity")
	}
	return hotspotLayoutKey{
		device: uint64(stat.Dev), inode: uint64(stat.Ino), size: info.Size(),
		modifiedNS: info.ModTime().UnixNano(),
	}, nil
}

func (i *hotspotInspector) cachedLayout(key hotspotLayoutKey) (hotspotTables, bool) {
	i.mu.Lock()
	defer i.mu.Unlock()
	layout, ok := i.layouts[key]
	return layout, ok
}

func (i *hotspotInspector) rememberLayout(key hotspotLayoutKey, layout hotspotTables) hotspotTables {
	i.mu.Lock()
	defer i.mu.Unlock()
	if cached, ok := i.layouts[key]; ok {
		return cached
	}
	if len(i.order) == maxHotspotLayoutCache {
		delete(i.layouts, i.order[0])
		copy(i.order, i.order[1:])
		i.order = i.order[:len(i.order)-1]
	}
	i.layouts[key] = layout
	i.order = append(i.order, key)
	return layout
}

func loadHotspotLayout(memory remoteMemory, path string, loadBias uint64) (hotspotTables, error) {
	symbols, err := readELFSymbols(path)
	if err != nil {
		return hotspotTables{}, fmt.Errorf("javastack: read libjvm symbols: %w", err)
	}
	tables, err := readHotspotTables(memory, loadBias, symbols)
	if err != nil {
		return hotspotTables{}, err
	}
	return normalizeHotspotLayout(tables, loadBias)
}

func normalizeHotspotLayout(tables hotspotTables, loadBias uint64) (hotspotTables, error) {
	fields := make(map[string]hotspotField, len(tables.fields))
	for name, field := range tables.fields {
		if field.isStatic {
			if field.value < loadBias {
				return hotspotTables{}, fmt.Errorf("javastack: HotSpot static field %s is outside libjvm", name)
			}
			field.value -= loadBias
		}
		fields[name] = field
	}
	return hotspotTables{fields: fields, sizes: tables.sizes}, nil
}

func relocateHotspotLayout(layout hotspotTables, loadBias uint64) (hotspotTables, error) {
	fields := make(map[string]hotspotField, len(layout.fields))
	for name, field := range layout.fields {
		if field.isStatic {
			if ^uint64(0)-loadBias < field.value {
				return hotspotTables{}, fmt.Errorf("javastack: HotSpot static field %s relocation overflow", name)
			}
			field.value += loadBias
		}
		fields[name] = field
	}
	return hotspotTables{fields: fields, sizes: layout.sizes}, nil
}

func findLibJVM(procRoot string, pid uint32) (string, uint64, error) {
	mapsPath := filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), "maps")
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return "", 0, fmt.Errorf("javastack: read JVM maps: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || filepath.Base(strings.TrimSuffix(fields[len(fields)-1], " (deleted)")) != "libjvm.so" {
			continue
		}
		bounds := strings.SplitN(fields[0], "-", 2)
		if len(bounds) != 2 {
			continue
		}
		start, startErr := strconv.ParseUint(bounds[0], 16, 64)
		offset, offsetErr := strconv.ParseUint(fields[2], 16, 64)
		if startErr != nil || offsetErr != nil || start < offset {
			continue
		}
		mappedPath := strings.TrimSuffix(fields[len(fields)-1], " (deleted)")
		rootedPath := filepath.Join(procRoot, strconv.FormatUint(uint64(pid), 10), "root", strings.TrimPrefix(mappedPath, "/"))
		return rootedPath, start - offset, nil
	}
	return "", 0, errors.New("javastack: libjvm.so mapping not found")
}

func readELFSymbols(path string) (map[string]uint64, error) {
	file, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	result := make(map[string]uint64)
	for _, read := range []func() ([]elf.Symbol, error){file.DynamicSymbols, file.Symbols} {
		symbols, readErr := read()
		if readErr != nil && !errors.Is(readErr, elf.ErrNoSymbols) {
			return nil, readErr
		}
		for _, symbol := range symbols {
			if _, required := requiredHotspotELFSymbols[symbol.Name]; required && symbol.Value != 0 {
				result[symbol.Name] = symbol.Value
			}
		}
	}
	return result, nil
}

func readHotspotTables(memory remoteMemory, loadBias uint64, symbols map[string]uint64) (hotspotTables, error) {
	structSymbols := hotspotTableSymbols{
		base: "gHotSpotVMStructs", stride: "gHotSpotVMStructEntryArrayStride",
		typeOffset: "gHotSpotVMStructEntryTypeNameOffset", fieldOffset: "gHotSpotVMStructEntryFieldNameOffset",
		valueOffset: "gHotSpotVMStructEntryOffsetOffset", addressOffset: "gHotSpotVMStructEntryAddressOffset",
	}
	typeSymbols := hotspotTableSymbols{
		base: "gHotSpotVMTypes", stride: "gHotSpotVMTypeEntryArrayStride",
		typeOffset: "gHotSpotVMTypeEntryTypeNameOffset", valueOffset: "gHotSpotVMTypeEntrySizeOffset",
	}
	fields, err := readHotspotTable(memory, loadBias, symbols, structSymbols, true,
		func(name string) bool { _, ok := requiredHotspotFields[name]; return ok })
	if err != nil {
		return hotspotTables{}, fmt.Errorf("javastack: read VMStructs: %w", err)
	}
	types, err := readHotspotTable(memory, loadBias, symbols, typeSymbols, false,
		func(name string) bool { _, ok := requiredHotspotTypes[name]; return ok })
	if err != nil {
		return hotspotTables{}, fmt.Errorf("javastack: read VMTypes: %w", err)
	}
	sizes := make(map[string]uint64, len(types))
	for name, value := range types {
		sizes[name] = value.value
	}
	return hotspotTables{fields: fields, sizes: sizes}, nil
}

func readHotspotTable(memory remoteMemory, loadBias uint64, symbols map[string]uint64,
	description hotspotTableSymbols, hasFields bool, required func(string) bool,
) (map[string]hotspotField, error) {
	global := func(name string) (uint64, error) {
		value, ok := symbols[name]
		if !ok {
			return 0, fmt.Errorf("missing ELF symbol %s", name)
		}
		return memory.uint64(loadBias + value)
	}
	base, err := global(description.base)
	if err != nil {
		return nil, err
	}
	stride, err := global(description.stride)
	if err != nil {
		return nil, err
	}
	typeOffset, err := global(description.typeOffset)
	if err != nil {
		return nil, err
	}
	valueOffset, err := global(description.valueOffset)
	if err != nil {
		return nil, err
	}
	var fieldOffset, addressOffset uint64
	if hasFields {
		if fieldOffset, err = global(description.fieldOffset); err != nil {
			return nil, err
		}
		if addressOffset, err = global(description.addressOffset); err != nil {
			return nil, err
		}
	}
	if base == 0 || stride < 8 || stride > 128 || typeOffset+8 > stride || valueOffset+8 > stride ||
		(hasFields && (fieldOffset+8 > stride || addressOffset+8 > stride)) {
		return nil, errors.New("invalid introspection table geometry")
	}
	result := make(map[string]hotspotField)
	row := make([]byte, stride)
	for index := 0; index < maxHotspotTableEntries; index++ {
		if err := memory.read(base+uint64(index)*stride, row); err != nil {
			return nil, err
		}
		typePointer := binary.NativeEndian.Uint64(row[typeOffset : typeOffset+8])
		if typePointer == 0 {
			return result, nil
		}
		typeName, err := memory.cString(typePointer)
		if err != nil {
			return nil, err
		}
		key := typeName
		if hasFields {
			fieldPointer := binary.NativeEndian.Uint64(row[fieldOffset : fieldOffset+8])
			if fieldPointer == 0 {
				continue
			}
			fieldName, stringErr := memory.cString(fieldPointer)
			if stringErr != nil {
				return nil, stringErr
			}
			key += "." + fieldName
			if !required(key) {
				continue
			}
			address := binary.NativeEndian.Uint64(row[addressOffset : addressOffset+8])
			if address != 0 {
				result[key] = hotspotField{value: address, isStatic: true}
				continue
			}
		}
		if required(key) {
			result[key] = hotspotField{value: binary.NativeEndian.Uint64(row[valueOffset : valueOffset+8])}
		}
	}
	return nil, errors.New("HotSpot introspection table is not terminated")
}

func buildHotspotMetadata(memory remoteMemory, tables hotspotTables) (HotspotMetadata, error) {
	field := func(types []string, names ...string) (hotspotField, error) {
		for _, typeName := range types {
			for _, name := range names {
				if value, ok := tables.fields[typeName+"."+name]; ok {
					return value, nil
				}
			}
		}
		return hotspotField{}, fmt.Errorf("missing HotSpot field %s.%s", strings.Join(types, "/"), strings.Join(names, "/"))
	}
	size := func(types ...string) (uint64, error) {
		for _, name := range types {
			if value, ok := tables.sizes[name]; ok {
				return value, nil
			}
		}
		return 0, fmt.Errorf("missing HotSpot type size %s", strings.Join(types, "/"))
	}
	codeHeapMemory, err := field([]string{"CodeHeap"}, "_memory")
	if err != nil {
		return HotspotMetadata{}, err
	}
	codeHeapSegmap, err := field([]string{"CodeHeap"}, "_segmap")
	if err != nil {
		return HotspotMetadata{}, err
	}
	codeHeapShift, err := field([]string{"CodeHeap"}, "_log2_segment_size")
	if err != nil {
		return HotspotMetadata{}, err
	}
	virtualLow, err := field([]string{"VirtualSpace"}, "_low_boundary")
	if err != nil {
		return HotspotMetadata{}, err
	}
	virtualHigh, err := field([]string{"VirtualSpace"}, "_high_boundary")
	if err != nil {
		return HotspotMetadata{}, err
	}
	heapBlockSize, err := size("HeapBlock")
	if err != nil {
		return HotspotMetadata{}, err
	}

	heapPointers, err := hotspotHeapPointers(memory, tables, field, size)
	if err != nil {
		return HotspotMetadata{}, err
	}
	if len(heapPointers) > maxHotspotCodeHeaps {
		return HotspotMetadata{}, fmt.Errorf("HotSpot has %d code heaps, maximum is %d", len(heapPointers), maxHotspotCodeHeaps)
	}
	metadata := HotspotMetadata{HeapCount: uint32(len(heapPointers))}
	for index, heapPointer := range heapPointers {
		shift, readErr := memory.uint32(heapPointer + codeHeapShift.value)
		if readErr != nil {
			return HotspotMetadata{}, readErr
		}
		if shift > 31 || (index > 0 && uint8(shift) != metadata.SegmentShift) {
			return HotspotMetadata{}, errors.New("invalid HotSpot code heap segment shift")
		}
		metadata.SegmentShift = uint8(shift)
		readPointer := func(offset uint64) (uint64, error) { return memory.uint64(heapPointer + offset) }
		metadata.Heaps[index].CodeStart, err = readPointer(codeHeapMemory.value + virtualLow.value)
		if err != nil {
			return HotspotMetadata{}, err
		}
		metadata.Heaps[index].CodeEnd, err = readPointer(codeHeapMemory.value + virtualHigh.value)
		if err != nil {
			return HotspotMetadata{}, err
		}
		metadata.Heaps[index].SegmapStart, err = readPointer(codeHeapSegmap.value + virtualLow.value)
		if err != nil {
			return HotspotMetadata{}, err
		}
		metadata.Heaps[index].SegmapEnd, err = readPointer(codeHeapSegmap.value + virtualHigh.value)
		if err != nil {
			return HotspotMetadata{}, err
		}
		heap := metadata.Heaps[index]
		if heap.CodeStart == 0 || heap.CodeEnd <= heap.CodeStart || heap.SegmapStart == 0 || heap.SegmapEnd <= heap.SegmapStart {
			return HotspotMetadata{}, errors.New("invalid HotSpot code heap boundaries")
		}
	}

	assign := func(destination any, types []string, names ...string) error {
		value, lookupErr := field(types, names...)
		if lookupErr != nil {
			return lookupErr
		}
		if value.isStatic {
			return fmt.Errorf("unexpected static HotSpot field %s.%s", strings.Join(types, "/"), strings.Join(names, "/"))
		}
		switch output := destination.(type) {
		case *uint8:
			if value.value > 255 {
				return fmt.Errorf("HotSpot offset %d exceeds uint8", value.value)
			}
			*output = uint8(value.value)
		case *uint16:
			if value.value > 65535 {
				return fmt.Errorf("HotSpot offset %d exceeds uint16", value.value)
			}
			*output = uint16(value.value)
		}
		return nil
	}
	if heapBlockSize > 255 {
		return HotspotMetadata{}, errors.New("HotSpot HeapBlock size exceeds uint8")
	}
	metadata.HeapBlockSize = uint8(heapBlockSize)
	if err = assign(&metadata.CodeBlobName, []string{"CodeBlob"}, "_name"); err != nil {
		return HotspotMetadata{}, err
	}
	if err = assign(&metadata.NmethodMethod, []string{"nmethod", "CompiledMethod"}, "_method"); err != nil {
		return HotspotMetadata{}, err
	}
	if err = assign(&metadata.NmethodCompileID, []string{"nmethod", "CompiledMethod"}, "_compile_id"); err != nil {
		return HotspotMetadata{}, err
	}
	if err = assign(&metadata.MethodConstMethod, []string{"Method", "methodOopDesc"}, "_constMethod"); err != nil {
		return HotspotMetadata{}, err
	}
	if err = assign(&metadata.ConstMethodConstants, []string{"ConstMethod", "constMethodOopDesc"}, "_constants"); err != nil {
		return HotspotMetadata{}, err
	}
	if err = assign(&metadata.ConstMethodNameIndex, []string{"ConstMethod", "constMethodOopDesc"}, "_name_index"); err != nil {
		return HotspotMetadata{}, err
	}
	constantPoolSize, err := size("ConstantPool", "constantPoolOopDesc")
	if err != nil {
		return HotspotMetadata{}, err
	}
	if constantPoolSize > 65535 {
		return HotspotMetadata{}, errors.New("HotSpot ConstantPool size exceeds uint16")
	}
	metadata.ConstantPoolSize = uint16(constantPoolSize)
	if err = assign(&metadata.ConstantPoolHolder, []string{"ConstantPool", "constantPoolOopDesc"}, "_pool_holder"); err != nil {
		return HotspotMetadata{}, err
	}
	if err = assign(&metadata.KlassName, []string{"Klass"}, "_name"); err != nil {
		return HotspotMetadata{}, err
	}
	if symbolLengthAndRefcount, ok := tables.fields["Symbol._length_and_refcount"]; ok {
		if symbolLengthAndRefcount.value+2 > 255 {
			return HotspotMetadata{}, errors.New("HotSpot Symbol length offset exceeds uint8")
		}
		metadata.SymbolLength = uint8(symbolLengthAndRefcount.value + 2)
	} else if err = assign(&metadata.SymbolLength, []string{"Symbol"}, "_length"); err != nil {
		return HotspotMetadata{}, err
	}
	if err = assign(&metadata.SymbolBody, []string{"Symbol"}, "_body"); err != nil {
		return HotspotMetadata{}, err
	}
	return metadata, nil
}

func hotspotHeapPointers(memory remoteMemory, tables hotspotTables,
	field func([]string, ...string) (hotspotField, error), size func(...string) (uint64, error),
) ([]uint64, error) {
	if heaps, ok := tables.fields["CodeCache._heaps"]; ok && heaps.isStatic {
		arrayPointer, err := memory.uint64(heaps.value)
		if err != nil {
			return nil, err
		}
		if arrayPointer == 0 {
			return nil, errors.New("HotSpot CodeCache heaps are not initialized")
		}
		length, err := field([]string{"GenericGrowableArray", "GrowableArrayBase"}, "_len")
		if err != nil {
			return nil, err
		}
		data, err := field([]string{"GrowableArray<int>"}, "_data")
		if err != nil {
			return nil, err
		}
		arraySize, err := size("GrowableArray<int>")
		if err != nil {
			return nil, err
		}
		if length.value+4 > arraySize || data.value+8 > arraySize {
			return nil, errors.New("invalid HotSpot GrowableArray layout")
		}
		count, err := memory.uint32(arrayPointer + length.value)
		if err != nil {
			return nil, err
		}
		if count == 0 || count > 16 {
			return nil, fmt.Errorf("invalid HotSpot code heap count %d", count)
		}
		dataPointer, err := memory.uint64(arrayPointer + data.value)
		if err != nil {
			return nil, err
		}
		result := make([]uint64, count)
		for index := range result {
			result[index], err = memory.uint64(dataPointer + uint64(index)*8)
			if err != nil {
				return nil, err
			}
			if result[index] == 0 {
				return nil, errors.New("HotSpot CodeHeap pointer is nil")
			}
		}
		return result, nil
	}
	heap, ok := tables.fields["CodeCache._heap"]
	if !ok || !heap.isStatic {
		return nil, errors.New("HotSpot CodeCache heap pointer is unavailable")
	}
	heapPointer, err := memory.uint64(heap.value)
	if err != nil {
		return nil, err
	}
	if heapPointer == 0 {
		return nil, errors.New("HotSpot CodeCache heap is not initialized")
	}
	return []uint64{heapPointer}, nil
}
