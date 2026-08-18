// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package java

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	maxHotSpotTableEntries  = 16384
	maxHotSpotStringBytes   = 4096
	hotSpotTableReadEntries = 128
)

type processMemory struct {
	pid int
}

func (m processMemory) read(address uint64, size int) ([]byte, error) {
	if address == 0 || size <= 0 {
		return nil, errors.New("HotSpot memory read range is invalid")
	}
	data := make([]byte, size)
	local := []unix.Iovec{{Base: &data[0], Len: uint64(size)}}
	remote := []unix.RemoteIovec{{Base: uintptr(address), Len: size}}
	read, err := unix.ProcessVMReadv(m.pid, local, remote, 0)
	if err != nil {
		return nil, err
	}
	if read != size {
		return nil, fmt.Errorf("short HotSpot memory read: got %d, want %d", read, size)
	}
	return data, nil
}

func (m processMemory) readInto(address uint64, data []byte) error {
	if address == 0 || len(data) == 0 {
		return errors.New("HotSpot memory read range is invalid")
	}
	local := []unix.Iovec{{Base: &data[0], Len: uint64(len(data))}}
	remote := []unix.RemoteIovec{{Base: uintptr(address), Len: len(data)}}
	read, err := unix.ProcessVMReadv(m.pid, local, remote, 0)
	if err != nil {
		return err
	}
	if read != len(data) {
		return fmt.Errorf("short HotSpot memory read: got %d, want %d", read, len(data))
	}
	return nil
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

type hotspotImage struct {
	path           string
	runtimeVersion string
	symbols        map[string]uint64
}

func discoverHotSpotImage(procRoot string, pid int) (*hotspotImage, error) {
	if procRoot == "" {
		procRoot = "/proc"
	}
	mapsPath := filepath.Join(procRoot, strconv.Itoa(pid), "maps")
	mapsFile, err := os.Open(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("open HotSpot maps: %w", err)
	}
	defer mapsFile.Close()
	var mappedPath string
	var loadBias uint64
	scanner := bufio.NewScanner(mapsFile)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || !strings.HasSuffix(fields[len(fields)-1], "/libjvm.so") {
			continue
		}
		offset, parseErr := strconv.ParseUint(fields[2], 16, 64)
		if parseErr != nil || offset != 0 {
			continue
		}
		startText, _, found := strings.Cut(fields[0], "-")
		if !found {
			continue
		}
		start, parseErr := strconv.ParseUint(startText, 16, 64)
		if parseErr != nil {
			continue
		}
		mappedPath = strings.TrimSuffix(fields[len(fields)-1], " (deleted)")
		loadBias = start
		break
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan HotSpot maps: %w", err)
	}
	if mappedPath == "" {
		return nil, errors.New("target does not map a HotSpot libjvm.so")
	}
	imagePath := filepath.Join(procRoot, strconv.Itoa(pid), "root", mappedPath)
	file, err := elf.Open(imagePath)
	if err != nil {
		return nil, fmt.Errorf("open target libjvm.so: %w", err)
	}
	defer file.Close()
	if file.Class != elf.ELFCLASS64 || file.ByteOrder != binary.LittleEndian {
		return nil, fmt.Errorf("unsupported HotSpot ELF class or byte order")
	}
	dynamicSymbols, err := file.DynamicSymbols()
	if err != nil {
		return nil, fmt.Errorf("read HotSpot dynamic symbols: %w", err)
	}
	symbols := make(map[string]uint64, len(dynamicSymbols))
	for _, symbol := range dynamicSymbols {
		name := strings.SplitN(symbol.Name, "@", 2)[0]
		if strings.HasPrefix(name, "gHotSpotVM") {
			symbols[name] = loadBias + symbol.Value
		}
	}
	return &hotspotImage{
		path: mappedPath, runtimeVersion: readJavaRuntimeVersion(procRoot, pid,
			mappedPath), symbols: symbols,
	}, nil
}

func readJavaRuntimeVersion(procRoot string, pid int, libjvmPath string) string {
	javaHome := filepath.Dir(filepath.Dir(filepath.Dir(libjvmPath)))
	releasePath := filepath.Join(procRoot, strconv.Itoa(pid), "root", javaHome,
		"release")
	release, err := os.Open(releasePath)
	if err != nil {
		return ""
	}
	defer release.Close()
	scanner := bufio.NewScanner(release)
	for scanner.Scan() {
		key, value, found := strings.Cut(scanner.Text(), "=")
		if found && key == "JAVA_VERSION" {
			return strings.Trim(value, "\"")
		}
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

type hotspotMetadata struct {
	image       *hotspotImage
	structs     map[string]vmStruct
	types       map[string]vmType
	constants   map[string]int64
	longConsts  map[string]int64
	stringCache map[uint64]string
}

func loadHotSpotMetadata(procRoot string, pid int) (*hotspotMetadata, error) {
	image, err := discoverHotSpotImage(procRoot, pid)
	if err != nil {
		return nil, err
	}
	memory := processMemory{pid: pid}
	metadata := &hotspotMetadata{
		image: image, structs: make(map[string]vmStruct),
		types: make(map[string]vmType), constants: make(map[string]int64),
		longConsts: make(map[string]int64), stringCache: make(map[uint64]string),
	}
	if err := metadata.loadStructs(memory); err != nil {
		return nil, err
	}
	if metadata.image.runtimeVersion == "" {
		metadata.image.runtimeVersion = metadata.runtimeVersion(memory)
	}
	if err := metadata.loadTypes(memory); err != nil {
		return nil, err
	}
	if err := metadata.loadConstants(memory, false); err != nil {
		return nil, err
	}
	if err := metadata.loadConstants(memory, true); err != nil {
		return nil, err
	}
	return metadata, nil
}

func (m *hotspotMetadata) readCString(memory processMemory, address uint64) (string, error) {
	if address == 0 {
		return "", nil
	}
	if value, ok := m.stringCache[address]; ok {
		return value, nil
	}
	value, err := memory.cstring(address)
	if err == nil {
		m.stringCache[address] = value
	}
	return value, err
}

func readHotSpotTableBatch(memory processMemory, baseAddress, stride uint64, start int) ([]byte, int, error) {
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

func (m *hotspotMetadata) runtimeVersion(memory processMemory) string {
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

func (m *hotspotMetadata) symbol(name string) (uint64, error) {
	address, ok := m.image.symbols[name]
	if !ok {
		return 0, fmt.Errorf("HotSpot metadata symbol %s is unavailable", name)
	}
	return address, nil
}

func (m *hotspotMetadata) value(memory processMemory, name string) (uint64, error) {
	address, err := m.symbol(name)
	if err != nil {
		return 0, err
	}
	return memory.uint64(address)
}

type metadataOffsetField struct {
	name  string
	width int
}

func validateHotSpotOffsets(offsets map[string]uint64, stride int,
	fields []metadataOffsetField,
) error {
	for _, field := range fields {
		offset, ok := offsets[field.name]
		if !ok {
			return fmt.Errorf("HotSpot metadata offset %s is unavailable", field.name)
		}
		if offset > uint64(stride) || offset+uint64(field.width) > uint64(stride) {
			return fmt.Errorf("HotSpot metadata offset %s=%d with width %d exceeds stride %d",
				field.name, offset, field.width, stride)
		}
	}
	return nil
}

func (m *hotspotMetadata) loadStructs(memory processMemory) error {
	basePointer, err := m.value(memory, "gHotSpotVMStructs")
	if err != nil {
		return err
	}
	stride, err := m.value(memory, "gHotSpotVMStructEntryArrayStride")
	if err != nil || stride == 0 || stride > 256 {
		return errors.New("HotSpot VMStruct stride is invalid")
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
	if err := validateHotSpotOffsets(offsets, strideBytes, []metadataOffsetField{
		{name: "TypeName", width: 8}, {name: "FieldName", width: 8},
		{name: "TypeString", width: 8}, {name: "IsStatic", width: 4},
		{name: "Offset", width: 8}, {name: "Address", width: 8},
	}); err != nil {
		return err
	}
	for index := 0; index < maxHotSpotTableEntries; {
		batch, entries, readErr := readHotSpotTableBatch(memory, basePointer, stride, index)
		if readErr != nil {
			return fmt.Errorf("read HotSpot VMStruct entry %d: %w", index, readErr)
		}
		for batchIndex := 0; batchIndex < entries; batchIndex++ {
			entry := batch[batchIndex*strideBytes : (batchIndex+1)*strideBytes]
			index++
			typePointer := binary.LittleEndian.Uint64(entry[offsets["TypeName"]:])
			if typePointer == 0 {
				return nil
			}
			fieldPointer := binary.LittleEndian.Uint64(entry[offsets["FieldName"]:])
			typeStringPointer := binary.LittleEndian.Uint64(entry[offsets["TypeString"]:])
			staticValue := binary.LittleEndian.Uint32(entry[offsets["IsStatic"]:])
			offset := binary.LittleEndian.Uint64(entry[offsets["Offset"]:])
			address := binary.LittleEndian.Uint64(entry[offsets["Address"]:])
			typeName, readErr := m.readCString(memory, typePointer)
			if readErr != nil {
				return readErr
			}
			fieldName, _ := m.readCString(memory, fieldPointer)
			typeString, _ := m.readCString(memory, typeStringPointer)
			m.structs[typeName+"::"+fieldName] = vmStruct{
				typeString: typeString,
				isStatic:   staticValue != 0, offset: offset, address: address,
			}
		}
	}
	return errors.New("HotSpot VMStruct table exceeds safety limit")
}

func (m *hotspotMetadata) loadTypes(memory processMemory) error {
	basePointer, err := m.value(memory, "gHotSpotVMTypes")
	if err != nil {
		return err
	}
	stride, err := m.value(memory, "gHotSpotVMTypeEntryArrayStride")
	if err != nil || stride == 0 || stride > 256 {
		return errors.New("HotSpot VMType stride is invalid")
	}
	offsets := make(map[string]uint64)
	for _, name := range []string{"TypeName", "SuperclassName", "Size", "IsOopType", "IsIntegerType", "IsUnsigned"} {
		offset, offsetErr := m.value(memory, "gHotSpotVMTypeEntry"+name+"Offset")
		if offsetErr != nil {
			return offsetErr
		}
		offsets[name] = offset
	}
	strideBytes := int(stride)
	if err := validateHotSpotOffsets(offsets, strideBytes, []metadataOffsetField{
		{name: "TypeName", width: 8}, {name: "SuperclassName", width: 8},
		{name: "Size", width: 8},
	}); err != nil {
		return err
	}
	for index := 0; index < maxHotSpotTableEntries; {
		batch, entries, readErr := readHotSpotTableBatch(memory, basePointer, stride, index)
		if readErr != nil {
			return readErr
		}
		for batchIndex := 0; batchIndex < entries; batchIndex++ {
			entry := batch[batchIndex*strideBytes : (batchIndex+1)*strideBytes]
			index++
			namePointer := binary.LittleEndian.Uint64(entry[offsets["TypeName"]:])
			if namePointer == 0 {
				return nil
			}
			superPointer := binary.LittleEndian.Uint64(entry[offsets["SuperclassName"]:])
			size := binary.LittleEndian.Uint64(entry[offsets["Size"]:])
			name, _ := m.readCString(memory, namePointer)
			superclass, _ := m.readCString(memory, superPointer)
			m.types[name] = vmType{
				superclass: superclass, size: size,
			}
		}
	}
	return errors.New("HotSpot VMType table exceeds safety limit")
}

func (m *hotspotMetadata) loadConstants(memory processMemory, longValues bool) error {
	prefix := "gHotSpotVMIntConstantEntry"
	tableSymbol := "gHotSpotVMIntConstants"
	destination := m.constants
	if longValues {
		prefix = "gHotSpotVMLongConstantEntry"
		tableSymbol = "gHotSpotVMLongConstants"
		destination = m.longConsts
	}
	basePointer, err := m.value(memory, tableSymbol)
	if err != nil {
		return err
	}
	stride, err := m.value(memory, prefix+"ArrayStride")
	if err != nil || stride == 0 || stride > 128 {
		return errors.New("HotSpot constant table stride is invalid")
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
	valueWidth := 4
	if longValues {
		valueWidth = 8
	}
	if nameOffset > uint64(strideBytes) || nameOffset+8 > uint64(strideBytes) {
		return errors.New("HotSpot constant name offset exceeds stride")
	}
	if valueOffset > uint64(strideBytes) ||
		valueOffset+uint64(valueWidth) > uint64(strideBytes) {
		return errors.New("HotSpot constant value offset exceeds stride")
	}
	for index := 0; index < maxHotSpotTableEntries; {
		batch, entries, readErr := readHotSpotTableBatch(memory, basePointer, stride, index)
		if readErr != nil {
			return readErr
		}
		for batchIndex := 0; batchIndex < entries; batchIndex++ {
			entry := batch[batchIndex*strideBytes : (batchIndex+1)*strideBytes]
			index++
			namePointer := binary.LittleEndian.Uint64(entry[nameOffset:])
			if namePointer == 0 {
				return nil
			}
			name, _ := m.readCString(memory, namePointer)
			if longValues {
				value := binary.LittleEndian.Uint64(entry[valueOffset:])
				destination[name] = int64(value)
			} else {
				value := binary.LittleEndian.Uint32(entry[valueOffset:])
				destination[name] = int64(int32(value))
			}
		}
	}
	return errors.New("HotSpot constant table exceeds safety limit")
}
