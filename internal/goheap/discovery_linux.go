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
	"bytes"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const defaultProcRoot = "/proc"

var errMBucketsSymbolNotFound = errors.New("runtime.mbuckets symbol not found")

type executableKey struct {
	device     uint64
	inode      uint64
	size       int64
	modifiedNS int64
}

func (k executableKey) String() string {
	return fmt.Sprintf("%x:%x:%x:%x", k.device, k.inode, k.size, k.modifiedNS)
}

type binaryInfo struct {
	goVersion     string
	buildID       string
	symbolAddress uint64
	elfType       elf.Type
	loadOffset    uint64
	loadVaddr     uint64
	err           error
}

// ProcDiscoverer scans a procfs mount and caches executable-level ELF results.
// Cache entries disappear when no process from the corresponding executable is
// present in the next complete scan.
type ProcDiscoverer struct {
	procRoot string

	mu    sync.Mutex
	cache map[executableKey]binaryInfo
}

// NewProcDiscoverer creates a procfs-backed Go process discoverer.
func NewProcDiscoverer(procRoot string) *ProcDiscoverer {
	if procRoot == "" {
		procRoot = defaultProcRoot
	}
	return &ProcDiscoverer{
		procRoot: procRoot,
		cache:    make(map[executableKey]binaryInfo),
	}
}

// Discover returns every process whose runtime.mbuckets address can be found.
func (d *ProcDiscoverer) Discover(ctx context.Context) ([]Target, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	entries, err := os.ReadDir(d.procRoot)
	if err != nil {
		return nil, fmt.Errorf("read procfs %q: %w", d.procRoot, err)
	}

	pids := make([]int, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, parseErr := strconv.Atoi(entry.Name())
		if parseErr == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)

	seenExecutables := make(map[executableKey]struct{})
	targets := make([]Target, 0)
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		target, key, inspectErr := d.inspectPID(pid)
		if key != (executableKey{}) {
			seenExecutables[key] = struct{}{}
		}
		if inspectErr == nil {
			targets = append(targets, target)
		}
	}

	for key := range d.cache {
		if _, ok := seenExecutables[key]; !ok {
			delete(d.cache, key)
		}
	}
	return targets, nil
}

func (d *ProcDiscoverer) inspectPID(pid int) (Target, executableKey, error) {
	startTimeTicks, err := readStartTimeTicks(filepath.Join(d.procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return Target{}, executableKey{}, err
	}

	exePath := filepath.Join(d.procRoot, strconv.Itoa(pid), "exe")
	executable, err := os.Open(exePath)
	if err != nil {
		return Target{}, executableKey{}, err
	}
	defer executable.Close()

	key, inode, err := executableIdentity(executable)
	if err != nil {
		return Target{}, executableKey{}, err
	}
	info, ok := d.cache[key]
	if !ok {
		info = inspectExecutable(executable)
		d.cache[key] = info
	}
	if info.err != nil {
		return Target{}, key, info.err
	}

	loadBias := uint64(0)
	if info.elfType == elf.ET_DYN {
		loadBias, err = readLoadBias(
			filepath.Join(d.procRoot, strconv.Itoa(pid), "maps"),
			inode,
			info.loadOffset,
			info.loadVaddr,
		)
		if err != nil {
			return Target{}, key, err
		}
	}

	resolvedPath, _ := os.Readlink(exePath)
	return Target{
		Identity: Identity{
			PID:            uint32(pid),
			StartTimeTicks: startTimeTicks,
		},
		GoVersion:     info.goVersion,
		Executable:    resolvedPath,
		BuildID:       info.buildID,
		ExecutableKey: key.String(),
		SymbolAddress: info.symbolAddress,
		LoadBias:      loadBias,
	}, key, nil
}

func executableIdentity(file *os.File) (executableKey, uint64, error) {
	stat, err := file.Stat()
	if err != nil {
		return executableKey{}, 0, err
	}
	sys, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		return executableKey{}, 0, errors.New("executable stat has no Stat_t")
	}
	return executableKey{
		device:     uint64(sys.Dev),
		inode:      sys.Ino,
		size:       stat.Size(),
		modifiedNS: stat.ModTime().UnixNano(),
	}, sys.Ino, nil
}

func inspectExecutable(file *os.File) binaryInfo {
	elfFile, err := elf.NewFile(file)
	if err != nil {
		return binaryInfo{err: fmt.Errorf("open ELF: %w", err)}
	}
	defer elfFile.Close()

	symbolAddress, err := lookupSymbol(elfFile, "runtime.mbuckets")
	if err != nil {
		return binaryInfo{err: err}
	}
	loadOffset, loadVaddr, err := firstLoadSegment(elfFile)
	if err != nil {
		return binaryInfo{err: err}
	}
	buildID := readELFBuildID(elfFile)

	// Read build info last: debug/buildinfo may close an ELF wrapper around the
	// supplied file, so no later operation should depend on the descriptor.
	build, err := buildinfo.Read(file)
	if err != nil {
		return binaryInfo{err: fmt.Errorf("read Go build info: %w", err)}
	}
	if build.GoVersion == "" {
		return binaryInfo{err: errors.New("Go build version is empty")}
	}

	return binaryInfo{
		goVersion:     build.GoVersion,
		buildID:       buildID,
		symbolAddress: symbolAddress,
		elfType:       elfFile.Type,
		loadOffset:    loadOffset,
		loadVaddr:     loadVaddr,
	}
}

func lookupSymbol(file *elf.File, name string) (uint64, error) {
	if symbols, err := file.Symbols(); err == nil {
		for _, symbol := range symbols {
			if symbol.Name == name {
				return symbol.Value, nil
			}
		}
	}
	if symbols, err := file.DynamicSymbols(); err == nil {
		for _, symbol := range symbols {
			if symbol.Name == name {
				return symbol.Value, nil
			}
		}
	}
	return 0, errMBucketsSymbolNotFound
}

func firstLoadSegment(file *elf.File) (uint64, uint64, error) {
	pageSize := uint64(os.Getpagesize())
	for _, program := range file.Progs {
		if program.Type == elf.PT_LOAD {
			return alignDown(program.Off, pageSize), alignDown(program.Vaddr, pageSize), nil
		}
	}
	return 0, 0, errors.New("ELF has no PT_LOAD segment")
}

func readStartTimeTicks(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	closingParen := bytes.LastIndex(data, []byte(") "))
	if closingParen < 0 {
		return 0, errors.New("malformed proc stat command")
	}
	// The suffix starts at field 3 (state); starttime is field 22.
	fields := bytes.Fields(data[closingParen+2:])
	if len(fields) <= 19 {
		return 0, errors.New("proc stat does not contain starttime")
	}
	startTime, err := strconv.ParseUint(string(fields[19]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse proc stat starttime: %w", err)
	}
	return startTime, nil
}

func readLoadBias(mapsPath string, inode, loadOffset, loadVaddr uint64) (uint64, error) {
	data, err := os.ReadFile(mapsPath)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		mappingInode, parseErr := strconv.ParseUint(fields[4], 10, 64)
		if parseErr != nil || mappingInode != inode {
			continue
		}
		offset, parseErr := strconv.ParseUint(fields[2], 16, 64)
		if parseErr != nil || offset != loadOffset {
			continue
		}
		startText, _, found := strings.Cut(fields[0], "-")
		if !found {
			continue
		}
		start, parseErr := strconv.ParseUint(startText, 16, 64)
		if parseErr == nil && start >= loadVaddr {
			return start - loadVaddr, nil
		}
	}
	return 0, errors.New("executable load bias not found")
}

func readELFBuildID(file *elf.File) string {
	for _, name := range []string{".note.go.buildid", ".note.gnu.build-id"} {
		section := file.Section(name)
		if section == nil {
			continue
		}
		data, err := section.Data()
		if err != nil {
			continue
		}
		value, ok := parseELFNote(data, file.ByteOrder)
		if !ok {
			continue
		}
		if name == ".note.gnu.build-id" {
			return hex.EncodeToString(value)
		}
		return strings.TrimRight(string(value), "\x00")
	}
	return ""
}

func parseELFNote(data []byte, byteOrder binary.ByteOrder) ([]byte, bool) {
	if len(data) < 12 {
		return nil, false
	}
	nameSize := int(byteOrder.Uint32(data[0:4]))
	descSize := int(byteOrder.Uint32(data[4:8]))
	descStart := 12 + int(alignUp(uint64(nameSize), 4))
	if nameSize < 0 || descSize < 0 || descStart > len(data) || descSize > len(data)-descStart {
		return nil, false
	}
	return data[descStart : descStart+descSize], true
}

func alignDown(value, alignment uint64) uint64 {
	return value &^ (alignment - 1)
}

func alignUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) &^ (alignment - 1)
}
