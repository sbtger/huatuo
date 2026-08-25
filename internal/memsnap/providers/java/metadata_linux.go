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

package java

import (
	"bufio"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"huatuo-bamai/internal/memsnap"
)

const (
	maxHotSpotTableEntries  = 16384
	maxHotSpotStringBytes   = 4096
	hotSpotTableReadEntries = 128
)

type processMemory struct {
	pid         int
	ctx         context.Context
	deadline    time.Time
	hasDeadline bool
}

func (m processMemory) check() error {
	if m.ctx != nil {
		if err := m.ctx.Err(); err != nil {
			return err
		}
	}
	if memsnap.DeadlineReached(m.deadline, m.hasDeadline) {
		return context.DeadlineExceeded
	}
	return nil
}

func (m processMemory) read(address uint64, size int) ([]byte, error) {
	if err := m.check(); err != nil {
		return nil, err
	}
	if address == 0 || size <= 0 || size > maxReadBytes {
		return nil, errors.New("HotSpot memory read range is invalid")
	}
	if _, ok := checkedAdd(address, uint64(size)); !ok {
		return nil, errors.New("HotSpot memory read range overflows")
	}
	data := make([]byte, size)
	local := []unix.Iovec{{Base: &data[0], Len: uint64(size)}}
	remote := []unix.RemoteIovec{{Base: uintptr(address), Len: size}}
	read, err := unix.ProcessVMReadv(m.pid, local, remote, 0)
	if err != nil {
		return nil, err
	}
	if err := m.check(); err != nil {
		return nil, err
	}
	if read != size {
		return nil, fmt.Errorf("short HotSpot memory read: got %d, want %d", read, size)
	}
	return data, nil
}

type memoryRange struct {
	address uint64
	size    int
}

func (m processMemory) readv(ranges []memoryRange) ([][]byte, error) {
	if err := m.check(); err != nil {
		return nil, err
	}
	if len(ranges) == 0 {
		return nil, nil
	}
	if len(ranges) > maxReadIOVs {
		return nil, errors.New("HotSpot vector memory read has too many ranges")
	}
	data := make([][]byte, len(ranges))
	local := make([]unix.Iovec, len(ranges))
	remote := make([]unix.RemoteIovec, len(ranges))
	want := 0
	for index, item := range ranges {
		if item.address == 0 || item.size <= 0 {
			return nil, errors.New("HotSpot vector memory read range is invalid")
		}
		if item.size > maxReadBytes-want {
			return nil, errors.New("HotSpot vector memory read is too large")
		}
		if _, ok := checkedAdd(item.address, uint64(item.size)); !ok {
			return nil, errors.New("HotSpot vector memory read range overflows")
		}
		data[index] = make([]byte, item.size)
		local[index] = unix.Iovec{Base: &data[index][0], Len: uint64(item.size)}
		remote[index] = unix.RemoteIovec{Base: uintptr(item.address), Len: item.size}
		want += item.size
	}
	read, err := unix.ProcessVMReadv(m.pid, local, remote, 0)
	if err != nil {
		return nil, err
	}
	if err := m.check(); err != nil {
		return nil, err
	}
	if read != want {
		return nil, fmt.Errorf("short HotSpot vector memory read: got %d, want %d",
			read, want)
	}
	return data, nil
}

func (m processMemory) uint64(address uint64) (uint64, error) {
	raw, err := m.read(address, 8)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(raw), nil
}

func (m processMemory) uint32(address uint64) (uint32, error) {
	raw, err := m.read(address, 4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(raw), nil
}

func (m processMemory) cstring(address uint64) (string, error) {
	if address == 0 {
		return "", nil
	}
	result := make([]byte, 0, 64)
	for len(result) < maxHotSpotStringBytes {
		chunkSize := 64
		if remaining := maxHotSpotStringBytes - len(result); remaining < chunkSize {
			chunkSize = remaining
		}
		chunk, err := m.read(address+uint64(len(result)), chunkSize)
		if err != nil {
			return "", err
		}
		for _, value := range chunk {
			if value == 0 {
				return string(result), nil
			}
			result = append(result, value)
		}
	}
	return "", errors.New("HotSpot metadata string exceeds safety limit")
}

type vmImage struct {
	javaVersion string
	vmRelease   string
	symbols     map[string]uint64
	readable    []addressRange
}

func (image *vmImage) displayVersion() string {
	if image == nil {
		return ""
	}
	if image.javaVersion != "" {
		return image.javaVersion
	}
	return image.vmRelease
}

func (image *vmImage) contains(address, size uint64) bool {
	if image == nil || len(image.readable) == 0 {
		return true
	}
	end, ok := checkedAdd(address, size)
	if !ok {
		return false
	}
	index := sort.Search(len(image.readable), func(index int) bool {
		return image.readable[index].end > address
	})
	return index < len(image.readable) && image.readable[index].start <= address &&
		end <= image.readable[index].end
}

func discoverVM(ctx context.Context, procRoot string, pid int) (*vmImage, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	mapsPath := filepath.Join(procRoot, strconv.Itoa(pid), "maps")
	mappings, err := memsnap.ReadProcMapsContext(ctx, mapsPath, maxProcMapEntries)
	if err != nil {
		return nil, fmt.Errorf("read HotSpot maps: %w", err)
	}
	readable := make([]addressRange, 0, len(mappings))
	for _, mapping := range mappings {
		if !strings.HasPrefix(mapping.Perms, "r") {
			continue
		}
		if len(readable) >= maxProcMapEntries {
			return nil, unsupportedHotSpot(
				"readable mapping count exceeds safety limit")
		}
		readable = append(readable, addressRange{
			start: mapping.Start, end: mapping.End,
		})
	}
	var mappedPath string
	var mappedInode uint64
	for _, mapping := range mappings {
		path := strings.TrimSuffix(mapping.Path, " (deleted)")
		if !strings.HasSuffix(path, "/libjvm.so") {
			continue
		}
		mappedPath = path
		mappedInode = mapping.Inode
		break
	}
	if mappedPath == "" {
		return nil, fmt.Errorf("%w: target does not map libjvm.so",
			errHotSpotUnavailable)
	}
	imagePath := filepath.Join(procRoot, strconv.Itoa(pid), "root", mappedPath)
	file, err := elf.Open(imagePath)
	if err != nil {
		return nil, fmt.Errorf("open target libjvm.so: %w", err)
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.ByteOrder != binary.LittleEndian {
		return nil, fmt.Errorf("%w: unsupported ELF class or byte order",
			errHotSpotUnavailable)
	}
	pageSize := uint64(os.Getpagesize())
	var loadBias uint64
	biasFound := false
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD {
			continue
		}
		loadOffset := program.Off &^ (pageSize - 1)
		loadAddress := program.Vaddr &^ (pageSize - 1)
		loadBias, err = memsnap.FindLoadBias(mappings, mappedInode,
			loadOffset, loadAddress)
		if err == nil {
			biasFound = true
			break
		}
	}
	if !biasFound {
		return nil, fmt.Errorf("%w: cannot determine libjvm.so load bias",
			errHotSpotUnavailable)
	}
	if !javaELFSectionsWithinBudget(file, ".dynsym", ".dynstr") {
		return nil, unsupportedHotSpot(
			"libjvm.so dynamic symbols exceed safety limit")
	}
	dynamicSymbols, err := file.DynamicSymbols()
	if err != nil {
		return nil, unsupportedHotSpot(
			"libjvm.so dynamic symbols are unavailable")
	}
	symbols := make(map[string]uint64, len(dynamicSymbols))
	for _, symbol := range dynamicSymbols {
		name := strings.SplitN(symbol.Name, "@", 2)[0]
		if strings.HasPrefix(name, "gHotSpotVM") {
			address, valid := checkedAdd(loadBias, symbol.Value)
			if valid {
				symbols[name] = address
			}
		}
	}
	return &vmImage{
		javaVersion: readJavaVersion(procRoot, pid,
			mappedPath), symbols: symbols, readable: readable,
	}, nil
}

func javaELFSectionsWithinBudget(file *elf.File, names ...string) bool {
	var total uint64
	for _, name := range names {
		section := file.Section(name)
		if section == nil {
			continue
		}
		if section.Size > maxELFMetadataBytes-total ||
			section.Entsize != 0 && section.Size/section.Entsize > maxELFSymbols {
			return false
		}
		total += section.Size
	}
	return true
}

func readJavaVersion(procRoot string, pid int, libjvmPath string) string {
	root := filepath.Join(procRoot, strconv.Itoa(pid), "root")
	directory := filepath.Dir(libjvmPath)
	for depth := 0; depth < 6; depth++ {
		releasePath := filepath.Join(root,
			strings.TrimPrefix(directory, string(filepath.Separator)), "release")
		release, err := os.Open(releasePath)
		if err == nil {
			scanner := bufio.NewScanner(release)
			for scanner.Scan() {
				key, value, found := strings.Cut(scanner.Text(), "=")
				if found && key == "JAVA_VERSION" {
					_ = release.Close()
					return strings.Trim(value, "\"")
				}
			}
			_ = release.Close()
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	return ""
}

type vmStruct struct {
	typeString string
	isStatic   bool
	offset     uint64
	address    uint64
}

type vmType struct {
	superclass string
	size       uint64
}

type vmMeta struct {
	image           *vmImage
	structs         map[string]vmStruct
	types           map[string]vmType
	constants       map[string]int64
	stringCache     map[uint64]string
	cachedBytes     uint64
	objectAlignment uint64
	compressedKlass bool
}

func loadMetadata(procRoot string, memory processMemory) (*vmMeta, error) {
	if err := memory.check(); err != nil {
		return nil, err
	}
	image, err := discoverVM(memory.ctx, procRoot, memory.pid)
	if err != nil {
		return nil, err
	}
	metadata := &vmMeta{
		image: image, structs: make(map[string]vmStruct),
		types: make(map[string]vmType), constants: make(map[string]int64),
		stringCache: make(map[uint64]string),
	}
	if err := metadata.loadStructs(memory); err != nil {
		return nil, err
	}
	metadata.image.vmRelease = metadata.readVMRelease(memory)
	if err := metadata.loadTypes(memory); err != nil {
		return nil, err
	}
	if err := metadata.loadRuntimeConfig(memory); err != nil {
		return nil, err
	}
	if err := metadata.loadConstants(memory); err != nil {
		return nil, err
	}
	if err := metadata.validate(); err != nil {
		return nil, err
	}
	return metadata, nil
}

func (m *vmMeta) validate() error {
	required := []string{
		"Universe::_collectedHeap", "G1CollectedHeap::_hrm",
		"G1HeapRegionTable::_base", "G1HeapRegionTable::_length",
		"Klass::_layout_helper", "Klass::_name", "Symbol::_length",
	}
	for _, name := range required {
		if _, ok := m.structs[name]; !ok {
			return unsupportedHotSpot("required metadata " + name + " is unavailable")
		}
	}
	if firstStruct(m, "G1HeapRegionManager::_regions",
		"HeapRegionManager::_regions").typeString == "" {
		return unsupportedHotSpot("region manager layout is unavailable")
	}
	if _, ok := m.structs["Symbol::_body[0]"]; !ok {
		if _, ok = m.structs["Symbol::_body"]; !ok {
			return unsupportedHotSpot("required metadata Symbol::_body is unavailable")
		}
	}
	for _, name := range []string{
		"HeapWordSize", "Klass::_lh_instance_slow_path_bit",
		"Klass::_lh_header_size_shift", "Klass::_lh_header_size_mask",
		"Klass::_lh_log2_element_size_shift",
		"Klass::_lh_log2_element_size_mask",
	} {
		if _, ok := m.constants[name]; !ok {
			return unsupportedHotSpot("required constant " + name + " is unavailable")
		}
	}
	constantInRange := func(name string, minimum, maximum int64) error {
		value := m.constants[name]
		if value < minimum || value > maximum {
			return unsupportedHotSpot(fmt.Sprintf(
				"constant %s=%d is outside [%d,%d]",
				name, value, minimum, maximum))
		}
		return nil
	}
	if err := constantInRange("HeapWordSize", 8, 8); err != nil {
		return err
	}
	for _, name := range []string{
		"Klass::_lh_header_size_shift",
		"Klass::_lh_log2_element_size_shift",
	} {
		if err := constantInRange(name, 0, 31); err != nil {
			return err
		}
	}
	for _, name := range []string{
		"Klass::_lh_header_size_mask",
		"Klass::_lh_log2_element_size_mask",
	} {
		if err := constantInRange(name, 1, 0xffff); err != nil {
			return err
		}
	}
	slowBit := m.constants["Klass::_lh_instance_slow_path_bit"]
	if slowBit <= 0 || uint64(slowBit)&(uint64(slowBit)-1) != 0 {
		return unsupportedHotSpot(
			"Klass slow-path bit is not a positive power of two")
	}
	if value, ok := m.constants["arrayOopDesc_length_offset_in_bytes"]; ok &&
		(value < 8 || value > 256) {
		return unsupportedHotSpot(
			"array length offset is outside the supported range")
	}
	return nil
}

func (m *vmMeta) readCString(memory processMemory, address uint64) (string, error) {
	if address == 0 {
		return "", nil
	}
	if value, ok := m.stringCache[address]; ok {
		return value, nil
	}
	value, err := memory.cstring(address)
	if err == nil && uint64(len(value)) <= maxCachedMetadataBytes-m.cachedBytes {
		m.stringCache[address] = value
		m.cachedBytes += uint64(len(value))
	}
	return value, err
}

func readTableBatch(memory processMemory, baseAddress, stride uint64, start int) ([]byte, int, error) {
	entries := hotSpotTableReadEntries
	if remaining := maxHotSpotTableEntries - start; remaining < entries {
		entries = remaining
	}
	data, err := memory.read(baseAddress+uint64(start)*stride, entries*int(stride))
	if err == nil {
		return data, entries, nil
	}
	if entries == 1 {
		return nil, 0, err
	}
	data, err = memory.read(baseAddress+uint64(start)*stride, int(stride))
	if err != nil {
		return nil, 0, err
	}
	return data, 1, nil
}

func walkTable(memory processMemory, name string, baseAddress,
	stride uint64, visit func([]byte) (bool, error),
) error {
	strideBytes := int(stride)
	for index := 0; index < maxHotSpotTableEntries; {
		batch, entries, err := readTableBatch(memory, baseAddress, stride,
			index)
		if err != nil {
			return fmt.Errorf("read HotSpot %s entry %d: %w", name, index, err)
		}
		for batchIndex := 0; batchIndex < entries; batchIndex++ {
			entry := batch[batchIndex*strideBytes : (batchIndex+1)*strideBytes]
			index++
			done, err := visit(entry)
			if err != nil || done {
				return err
			}
		}
	}
	return unsupportedHotSpot(fmt.Sprintf("%s table exceeds safety limit", name))
}

func (m *vmMeta) readVMRelease(memory processMemory) string {
	field, ok := m.structs["Abstract_VM_Version::_s_vm_release"]
	if !ok || !field.isStatic || field.address == 0 {
		return ""
	}
	address, err := memory.uint64(field.address)
	if err != nil || address == 0 {
		return ""
	}
	version, err := m.readCString(memory, address)
	if err != nil {
		return ""
	}
	return version
}

func (m *vmMeta) symbol(name string) (uint64, error) {
	address, ok := m.image.symbols[name]
	if !ok {
		return 0, unsupportedHotSpot("metadata symbol " + name + " is unavailable")
	}
	return address, nil
}

func (m *vmMeta) value(memory processMemory, name string) (uint64, error) {
	address, err := m.symbol(name)
	if err != nil {
		return 0, err
	}
	return memory.uint64(address)
}

type offsetField struct {
	name  string
	width int
}

func validateOffsets(offsets map[string]uint64, stride int,
	fields []offsetField,
) error {
	for _, field := range fields {
		offset, ok := offsets[field.name]
		if !ok {
			return unsupportedHotSpot(
				"metadata offset " + field.name + " is unavailable")
		}
		if offset > uint64(stride) || offset+uint64(field.width) > uint64(stride) {
			return unsupportedHotSpot(fmt.Sprintf(
				"metadata offset %s=%d with width %d exceeds stride %d",
				field.name, offset, field.width, stride))
		}
	}
	return nil
}

func (m *vmMeta) loadStructs(memory processMemory) error {
	basePointer, err := m.value(memory, "gHotSpotVMStructs")
	if err != nil {
		return err
	}
	stride, err := m.value(memory, "gHotSpotVMStructEntryArrayStride")
	if err != nil {
		return err
	}
	if stride == 0 || stride > 256 {
		return unsupportedHotSpot("VMStruct stride is invalid")
	}
	offsets := make(map[string]uint64)
	for _, name := range []string{"TypeName", "FieldName", "TypeString", "IsStatic", "Offset", "Address"} {
		offset, offsetErr := m.value(memory, "gHotSpotVMStructEntry"+name+"Offset")
		if offsetErr != nil {
			return offsetErr
		}
		offsets[name] = offset
	}
	strideBytes := int(stride)
	if err := validateOffsets(offsets, strideBytes, []offsetField{
		{name: "TypeName", width: 8},
		{name: "FieldName", width: 8},
		{name: "TypeString", width: 8},
		{name: "IsStatic", width: 4},
		{name: "Offset", width: 8},
		{name: "Address", width: 8},
	}); err != nil {
		return err
	}
	return walkTable(memory, "VMStruct", basePointer, stride,
		func(entry []byte) (bool, error) {
			typePointer := binary.LittleEndian.Uint64(entry[offsets["TypeName"]:])
			if typePointer == 0 {
				return true, nil
			}
			fieldPointer := binary.LittleEndian.Uint64(entry[offsets["FieldName"]:])
			typeStringPointer := binary.LittleEndian.Uint64(entry[offsets["TypeString"]:])
			staticValue := binary.LittleEndian.Uint32(entry[offsets["IsStatic"]:])
			offset := binary.LittleEndian.Uint64(entry[offsets["Offset"]:])
			address := binary.LittleEndian.Uint64(entry[offsets["Address"]:])
			typeName, readErr := m.readCString(memory, typePointer)
			if readErr != nil {
				return false, readErr
			}
			fieldName, _ := m.readCString(memory, fieldPointer)
			typeString, _ := m.readCString(memory, typeStringPointer)
			m.structs[typeName+"::"+fieldName] = vmStruct{
				typeString: typeString,
				isStatic:   staticValue != 0, offset: offset, address: address,
			}
			return false, nil
		},
	)
}

func (m *vmMeta) loadTypes(memory processMemory) error {
	basePointer, err := m.value(memory, "gHotSpotVMTypes")
	if err != nil {
		return err
	}
	stride, err := m.value(memory, "gHotSpotVMTypeEntryArrayStride")
	if err != nil {
		return err
	}
	if stride == 0 || stride > 256 {
		return unsupportedHotSpot("VMType stride is invalid")
	}
	offsets := make(map[string]uint64)
	for _, name := range []string{"TypeName", "SuperclassName", "Size"} {
		offset, offsetErr := m.value(memory, "gHotSpotVMTypeEntry"+name+"Offset")
		if offsetErr != nil {
			return offsetErr
		}
		offsets[name] = offset
	}
	strideBytes := int(stride)
	if err := validateOffsets(offsets, strideBytes, []offsetField{
		{name: "TypeName", width: 8},
		{name: "SuperclassName", width: 8},
		{name: "Size", width: 8},
	}); err != nil {
		return err
	}
	return walkTable(memory, "VMType", basePointer, stride,
		func(entry []byte) (bool, error) {
			namePointer := binary.LittleEndian.Uint64(entry[offsets["TypeName"]:])
			if namePointer == 0 {
				return true, nil
			}
			superPointer := binary.LittleEndian.Uint64(entry[offsets["SuperclassName"]:])
			name, _ := m.readCString(memory, namePointer)
			superclass, _ := m.readCString(memory, superPointer)
			size := binary.LittleEndian.Uint64(entry[offsets["Size"]:])
			m.types[name] = vmType{superclass: superclass, size: size}
			return false, nil
		},
	)
}

func (m *vmMeta) loadConstants(memory processMemory) error {
	prefix := "gHotSpotVMIntConstantEntry"
	tableSymbol := "gHotSpotVMIntConstants"
	basePointer, err := m.value(memory, tableSymbol)
	if err != nil {
		return err
	}
	stride, err := m.value(memory, prefix+"ArrayStride")
	if err != nil {
		return err
	}
	if stride == 0 || stride > 128 {
		return unsupportedHotSpot("constant table stride is invalid")
	}
	nameOffset, err := m.value(memory, prefix+"NameOffset")
	if err != nil {
		return err
	}
	valueOffset, err := m.value(memory, prefix+"ValueOffset")
	if err != nil {
		return err
	}
	strideBytes := int(stride)
	if nameOffset > uint64(strideBytes) || nameOffset+8 > uint64(strideBytes) {
		return unsupportedHotSpot("constant name offset exceeds stride")
	}
	if valueOffset > uint64(strideBytes) ||
		valueOffset+4 > uint64(strideBytes) {
		return unsupportedHotSpot("constant value offset exceeds stride")
	}
	return walkTable(memory, "VMIntConstant", basePointer, stride,
		func(entry []byte) (bool, error) {
			namePointer := binary.LittleEndian.Uint64(entry[nameOffset:])
			if namePointer == 0 {
				return true, nil
			}
			name, _ := m.readCString(memory, namePointer)
			value := binary.LittleEndian.Uint32(entry[valueOffset:])
			m.constants[name] = int64(int32(value))
			return false, nil
		},
	)
}
