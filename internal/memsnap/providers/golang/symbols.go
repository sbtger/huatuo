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

package golang

import (
	"context"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"fmt"
	"io"
)

// symbolizer resolves Go PCs from pclntab and remains usable after the
// profiled process exits.
type symbolizer struct {
	table    *gosym.Table
	loadBias uint64
}

// newSymbolizer loads Go symbol metadata from an executable. loadBias is
// subtracted from runtime PCs for PIE binaries.
func newSymbolizer(ctx context.Context, executable string, loadBias uint64,
	table *gosym.Table,
) (*symbolizer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if table != nil {
		return &symbolizer{table: table, loadBias: loadBias}, nil
	}
	file, err := elf.Open(executable)
	if err != nil {
		return nil, fmt.Errorf("open executable %q: %w", executable, err)
	}
	defer file.Close()

	table, err = newGoSymbolTable(ctx, file)
	if err != nil {
		return nil, fmt.Errorf("parse Go symbol table from %q: %w", executable, err)
	}
	return &symbolizer{table: table, loadBias: loadBias}, nil
}

func newGoSymbolTable(ctx context.Context, file *elf.File) (*gosym.Table, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pcln, err := readPCLN(ctx, file)
	if err != nil {
		return nil, err
	}
	textStart, err := goTextStart(file, pcln)
	if err != nil {
		return nil, err
	}
	var symtab []byte
	section := file.Section(".gosymtab")
	if section == nil {
		section = file.Section(".data.rel.ro.gosymtab")
	}
	if section != nil {
		if !sectionBudgetOK(file, section.Name) {
			return nil, fmt.Errorf("Go symtab exceeds ELF metadata safety limit")
		}
		symtab, err = section.Data()
		if err != nil {
			return nil, fmt.Errorf("read Go symtab: %w", err)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	table, err := gosym.NewTable(symtab, gosym.NewLineTable(pcln, textStart))
	if err != nil {
		return nil, fmt.Errorf("parse Go symbol table: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return table, nil
}

// goTextStart returns the link-time start of the Go text section, which the
// pclntab functab offsets are relative to. Go 1.26 removed the textStart field
// from the pcHeader (it requires a relocation and is now a placeholder), so the
// ELF .text section address is used instead; it equals the pcHeader value for
// every supported release.
func goTextStart(file *elf.File, pcln []byte) (uint64, error) {
	if section := file.Section(".text"); section != nil {
		return section.Addr, nil
	}
	return pclnTextStart(pcln, file.ByteOrder)
}

func pclnTextStart(pcln []byte, byteOrder binary.ByteOrder) (uint64, error) {
	if len(pcln) < 8 {
		return 0, fmt.Errorf("Go pclntab header is truncated")
	}
	switch magic := byteOrder.Uint32(pcln[:4]); magic {
	case 0xfffffff0, 0xfffffff1:
		// Go 1.18-1.19 emit 0xfffffff0 and Go 1.20+ emit 0xfffffff1; the
		// pcHeader fields used below are identical for both.
	default:
		return 0, fmt.Errorf("unsupported Go pclntab magic %#x", magic)
	}
	pointerSize := int(pcln[7])
	if pointerSize != 4 && pointerSize != 8 {
		return 0, fmt.Errorf("unsupported Go pclntab pointer size %d", pointerSize)
	}
	// pcHeader contains nfunc and nfiles before textStart.
	offset := 8 + 2*pointerSize
	if len(pcln) < offset+pointerSize {
		return 0, fmt.Errorf("Go pclntab pcHeader is truncated")
	}
	if pointerSize == 4 {
		return uint64(byteOrder.Uint32(pcln[offset : offset+pointerSize])), nil
	}
	return byteOrder.Uint64(pcln[offset : offset+pointerSize]), nil
}

func readPCLN(ctx context.Context, file *elf.File) ([]byte, error) {
	section := file.Section(".gopclntab")
	if section == nil {
		section = file.Section(".data.rel.ro.gopclntab")
	}
	if section != nil {
		if !sectionBudgetOK(file, section.Name) {
			return nil, fmt.Errorf("Go pclntab exceeds ELF metadata safety limit")
		}
		data, err := section.Data()
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return data, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !sectionBudgetOK(file, ".symtab", ".strtab") {
		return nil, fmt.Errorf("ELF symbol table exceeds metadata safety limit")
	}
	symbols, err := file.Symbols()
	if err != nil {
		return nil, fmt.Errorf("read ELF symbols: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var start, end uint64
	var startFound, endFound bool
	for _, symbol := range symbols {
		switch symbol.Name {
		case "runtime.pclntab":
			start, startFound = symbol.Value, true
		case "runtime.epclntab":
			end, endFound = symbol.Value, true
		}
	}
	if !startFound || !endFound {
		return nil, fmt.Errorf("Go pclntab section and runtime symbol range not found")
	}
	if end <= start {
		return nil, fmt.Errorf("invalid pclntab range %#x-%#x", start, end)
	}
	data, err := readVirtualRange(file, start, end-start)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func readVirtualRange(file *elf.File, address, size uint64) ([]byte, error) {
	if size > maxELFMetadataBytes {
		return nil, fmt.Errorf("ELF virtual range exceeds metadata safety limit")
	}
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || address < program.Vaddr || size > program.Filesz ||
			address-program.Vaddr > program.Filesz-size {
			continue
		}
		reader := program.Open()
		if _, err := reader.Seek(int64(address-program.Vaddr), io.SeekStart); err != nil {
			return nil, fmt.Errorf("seek ELF segment: %w", err)
		}
		data := make([]byte, size)
		if _, err := io.ReadFull(reader, data); err != nil {
			return nil, fmt.Errorf("read ELF segment: %w", err)
		}
		return data, nil
	}
	return nil, fmt.Errorf("virtual range %#x-%#x is not file-backed", address, address+size)
}

// resolve resolves one runtime PC to a Go function name.
func (s *symbolizer) resolve(runtimePC uint64) string {
	if s == nil || s.table == nil || runtimePC <= s.loadBias {
		return ""
	}
	// runtime.MemProfile stacks contain return PCs. Move into the call
	// instruction so boundary PCs are attributed to the allocating function.
	function := s.table.PCToFunc(runtimePC - s.loadBias - 1)
	if function == nil {
		return ""
	}
	return function.Name
}
