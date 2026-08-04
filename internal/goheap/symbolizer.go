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
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"fmt"
	"io"
)

// ELFSymbolizer resolves Go PCs from pclntab and remains usable after the
// profiled process exits.
type ELFSymbolizer struct {
	table    *gosym.Table
	loadBias uint64
}

// NewELFSymbolizer loads Go symbol metadata from an executable. loadBias is
// subtracted from runtime PCs for PIE binaries.
func NewELFSymbolizer(executable string, loadBias uint64) (*ELFSymbolizer, error) {
	file, err := elf.Open(executable)
	if err != nil {
		return nil, fmt.Errorf("open executable %q: %w", executable, err)
	}
	defer file.Close()

	table, err := newGoSymbolTable(file)
	if err != nil {
		return nil, fmt.Errorf("parse Go symbol table from %q: %w", executable, err)
	}
	return &ELFSymbolizer{table: table, loadBias: loadBias}, nil
}

func newGoSymbolTable(file *elf.File) (*gosym.Table, error) {
	pcln, err := readPCLN(file)
	if err != nil {
		return nil, err
	}
	textStart, err := pclnTextStart(pcln, file.ByteOrder)
	if err != nil {
		return nil, err
	}
	var symtab []byte
	if section := file.Section(".gosymtab"); section != nil {
		symtab, err = section.Data()
		if err != nil {
			return nil, fmt.Errorf("read Go symtab: %w", err)
		}
	}
	table, err := gosym.NewTable(symtab, gosym.NewLineTable(pcln, textStart))
	if err != nil {
		return nil, fmt.Errorf("parse Go symbol table: %w", err)
	}
	return table, nil
}

func pclnTextStart(pcln []byte, byteOrder binary.ByteOrder) (uint64, error) {
	if len(pcln) < 8 {
		return 0, fmt.Errorf("Go pclntab header is truncated")
	}
	if byteOrder.Uint32(pcln[:4]) != 0xfffffff1 {
		return 0, fmt.Errorf("unsupported Go pclntab magic %#x", byteOrder.Uint32(pcln[:4]))
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

func readPCLN(file *elf.File) ([]byte, error) {
	if section := file.Section(".gopclntab"); section != nil {
		return section.Data()
	}
	start, err := lookupELFSymbol(file, "runtime.pclntab")
	if err != nil {
		return scanPCLN(file)
	}
	end, err := lookupELFSymbol(file, "runtime.epclntab")
	if err != nil {
		return scanPCLN(file)
	}
	if end <= start {
		return nil, fmt.Errorf("invalid pclntab range %#x-%#x", start, end)
	}
	return readVirtualRange(file, start, end-start)
}

func scanPCLN(file *elf.File) ([]byte, error) {
	for _, program := range file.Progs {
		if program.Type != elf.PT_LOAD || program.Filesz < 8 {
			continue
		}
		data, err := io.ReadAll(program.Open())
		if err != nil {
			return nil, fmt.Errorf("scan ELF segment: %w", err)
		}
		for offset := 0; offset+8 <= len(data); offset++ {
			// Go 1.20 and newer use 0xfffffff1 followed by two zero
			// padding bytes, the PC quantum, and the pointer size.
			if file.ByteOrder.Uint32(data[offset:offset+4]) == 0xfffffff1 &&
				data[offset+4] == 0 && data[offset+5] == 0 && data[offset+6] != 0 &&
				(data[offset+7] == 4 || data[offset+7] == 8) {
				return data[offset:], nil
			}
		}
	}
	return nil, fmt.Errorf("Go pclntab not found")
}

func lookupELFSymbol(file *elf.File, name string) (uint64, error) {
	symbols, err := file.Symbols()
	if err != nil {
		return 0, fmt.Errorf("read ELF symbols: %w", err)
	}
	for _, symbol := range symbols {
		if symbol.Name == name {
			return symbol.Value, nil
		}
	}
	return 0, fmt.Errorf("ELF symbol %q not found", name)
}

func readVirtualRange(file *elf.File, address, size uint64) ([]byte, error) {
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

// Resolve resolves one runtime PC to a Go function name.
func (s *ELFSymbolizer) Resolve(runtimePC uint64) string {
	if s == nil || s.table == nil || runtimePC < s.loadBias {
		return ""
	}
	fn := s.table.PCToFunc(runtimePC - s.loadBias)
	if fn == nil {
		return ""
	}
	return fn.Name
}
