// Copyright 2022-2025 The Parca Authors
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
//
// This file contains work derived from github.com/parca-dev/oomprof.
// It was modified by The HuaTuo Authors for integration with HuaTuo.

package golang

import (
	"context"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	versionpkg "go/version"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"huatuo-bamai/internal/memsnap"
)

const (
	defaultProcRoot         = "/proc"
	firstSupportedGoVersion = "go1.18"
	lastSupportedGoVersion  = "go1.26"
	maxELFMetadataBytes     = 64 << 20
	maxELFSymbols           = 1 << 20
)

var errMBucketsSymbolNotFound = errors.New("runtime.mbuckets symbol not found")

type imageInfo struct {
	goVersion   string
	mbucketsSym uint64
	rateSym     uint64
	elfType     elf.Type
	loadOffset  uint64
	loadVaddr   uint64
	byteOrder   binary.ByteOrder
	symbolTable *gosym.Table
	err         error
}

// target contains the addresses needed to inspect one Go OOM victim.
type target struct {
	startTime   uint64
	version     string
	mbucketsSym uint64
	rateSym     uint64
	loadBias    uint64
	byteOrder   binary.ByteOrder
	symbolTable *gosym.Table
}

func (t *target) mbuckets() uint64 {
	return t.mbucketsSym + t.loadBias
}

func (t *target) rateAddress() uint64 {
	if t.rateSym == 0 {
		return 0
	}
	return t.rateSym + t.loadBias
}

// discoverPID resolves a target from its thread-group leader PID.
func discoverPID(ctx context.Context, procRoot string, pid int) (target, error) {
	if err := ctx.Err(); err != nil {
		return target{}, err
	}
	if pid <= 0 {
		return target{}, errors.New("Go heap target PID must be positive")
	}
	if procRoot == "" {
		procRoot = defaultProcRoot
	}
	return inspectPID(ctx, procRoot, pid)
}

func inspectPID(ctx context.Context, procRoot string, pid int) (target, error) {
	startTimeTicks, err := readStartTimeTicks(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		return target{}, err
	}

	exePath := filepath.Join(procRoot, strconv.Itoa(pid), "exe")
	executable, err := os.Open(exePath)
	if err != nil {
		return target{}, err
	}
	defer executable.Close()

	inode, err := executableInode(executable)
	if err != nil {
		return target{}, err
	}
	info := inspectExecutable(ctx, executable)
	if err := ctx.Err(); err != nil {
		return target{}, err
	}
	if info.err != nil {
		return target{}, info.err
	}

	loadBias := uint64(0)
	if info.elfType == elf.ET_DYN {
		mappings, mapsErr := memsnap.ReadProcMapsContext(ctx,
			filepath.Join(procRoot, strconv.Itoa(pid), "maps"), 1<<18)
		if mapsErr != nil {
			return target{}, mapsErr
		}
		loadBias, err = memsnap.FindLoadBias(mappings, inode, info.loadOffset,
			info.loadVaddr)
		if err != nil {
			return target{}, err
		}
	}

	return target{
		startTime:   startTimeTicks,
		version:     info.goVersion,
		mbucketsSym: info.mbucketsSym,
		rateSym:     info.rateSym,
		loadBias:    loadBias,
		byteOrder:   info.byteOrder,
		symbolTable: info.symbolTable,
	}, nil
}

func executableInode(file *os.File) (uint64, error) {
	stat, err := file.Stat()
	if err != nil {
		return 0, err
	}
	sys, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("executable stat has no Stat_t")
	}
	return sys.Ino, nil
}

func inspectExecutable(ctx context.Context, file *os.File) imageInfo {
	if err := ctx.Err(); err != nil {
		return imageInfo{err: err}
	}
	elfFile, err := elf.NewFile(file)
	if err != nil {
		return imageInfo{err: fmt.Errorf("%w: open ELF: %w",
			errUnsupportedRuntime, err)}
	}
	defer elfFile.Close()
	if elfFile.Class != elf.ELFCLASS64 {
		return imageInfo{err: fmt.Errorf("%w: unsupported Go victim ELF class %s",
			errUnsupportedRuntime, elfFile.Class)}
	}

	var symbolTable *gosym.Table
	loadSymbolTable := func() (*gosym.Table, error) {
		if symbolTable != nil {
			return symbolTable, nil
		}
		table, tableErr := newGoSymbolTable(ctx, elfFile)
		if tableErr == nil {
			symbolTable = table
		}
		return table, tableErr
	}
	runtimeSymbols := lookupRuntimeSymbols(elfFile)
	if err := ctx.Err(); err != nil {
		return imageInfo{err: err}
	}
	mbucketsSym := runtimeSymbols.mbuckets
	if !runtimeSymbols.mbucketsFound {
		table, tableErr := loadSymbolTable()
		if tableErr != nil {
			err = fmt.Errorf("%w: %w", errMBucketsSymbolNotFound, tableErr)
		} else {
			mbucketsSym, err = lookupStrippedMBuckets(elfFile, table)
		}
	}
	if err != nil {
		return imageInfo{err: err}
	}
	rateSym := runtimeSymbols.memProfileRate
	if !runtimeSymbols.memProfileRateFound {
		// The provider can still return raw samples if scaling metadata is not
		// recoverable from a stripped executable.
		if table, tableErr := loadSymbolTable(); tableErr == nil {
			rateSym, _ = lookupStrippedRate(elfFile, table)
		}
	}
	loadOffset, loadVaddr, err := firstLoadSegment(elfFile)
	if err != nil {
		return imageInfo{err: fmt.Errorf("%w: %w", errUnsupportedRuntime, err)}
	}
	// Read build info last: debug/buildinfo may close an ELF wrapper around the
	// supplied file, so no later operation should depend on the descriptor.
	build, err := buildinfo.Read(file)
	if err != nil {
		return imageInfo{err: fmt.Errorf("%w: read Go build info: %w",
			errUnsupportedRuntime, err)}
	}
	if err := ctx.Err(); err != nil {
		return imageInfo{err: err}
	}
	if build.GoVersion == "" {
		return imageInfo{err: fmt.Errorf("%w: Go build version is empty",
			errUnsupportedRuntime)}
	}
	if err := validateGoVersion(build.GoVersion); err != nil {
		return imageInfo{err: err}
	}

	return imageInfo{
		goVersion:   build.GoVersion,
		mbucketsSym: mbucketsSym,
		rateSym:     rateSym,
		elfType:     elfFile.Type,
		loadOffset:  loadOffset,
		loadVaddr:   loadVaddr,
		byteOrder:   elfFile.ByteOrder,
		symbolTable: symbolTable,
	}
}

type runtimeSymbolAddresses struct {
	mbuckets            uint64
	memProfileRate      uint64
	mbucketsFound       bool
	memProfileRateFound bool
}

func lookupRuntimeSymbols(file *elf.File) runtimeSymbolAddresses {
	addresses := runtimeSymbolAddresses{}
	collect := func(symbols []elf.Symbol) {
		for _, symbol := range symbols {
			switch symbol.Name {
			case "runtime.mbuckets":
				if !addresses.mbucketsFound {
					addresses.mbuckets = symbol.Value
					addresses.mbucketsFound = true
				}
			case "runtime.MemProfileRate":
				if !addresses.memProfileRateFound {
					addresses.memProfileRate = symbol.Value
					addresses.memProfileRateFound = true
				}
			}
			if addresses.mbucketsFound && addresses.memProfileRateFound {
				return
			}
		}
	}
	if sectionBudgetOK(file, ".symtab", ".strtab") {
		if symbols, symbolErr := file.Symbols(); symbolErr == nil {
			collect(symbols)
		}
	}
	if !addresses.mbucketsFound || !addresses.memProfileRateFound {
		if sectionBudgetOK(file, ".dynsym", ".dynstr") {
			if symbols, symbolErr := file.DynamicSymbols(); symbolErr == nil {
				collect(symbols)
			}
		}
	}
	return addresses
}

func sectionBudgetOK(file *elf.File, names ...string) bool {
	var total uint64
	for _, name := range names {
		section := file.Section(name)
		if section == nil {
			continue
		}
		if section.Size > maxELFMetadataBytes-total {
			return false
		}
		if section.Entsize != 0 && section.Size/section.Entsize > maxELFSymbols {
			return false
		}
		total += section.Size
	}
	return true
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
	return memsnap.ParseProcStatStartTime(data)
}

func alignDown(value, alignment uint64) uint64 {
	return value &^ (alignment - 1)
}

// validateGoVersion makes an unknown runtime fail closed instead of silently
// interpreting incompatible heap-profile structures.
func validateGoVersion(version string) error {
	runtimeVersion := version
	start := strings.Index(version, "go")
	if start >= 0 {
		version = strings.Fields(version[start:])[0]
	}
	languageVersion := versionpkg.Lang(version)
	if languageVersion == "" ||
		versionpkg.Compare(languageVersion, firstSupportedGoVersion) < 0 ||
		versionpkg.Compare(languageVersion, lastSupportedGoVersion) > 0 {
		return fmt.Errorf("%w: unsupported Go runtime version %q: supported range is %s-%s",
			errUnsupportedRuntime, runtimeVersion, firstSupportedGoVersion,
			lastSupportedGoVersion)
	}
	return nil
}
