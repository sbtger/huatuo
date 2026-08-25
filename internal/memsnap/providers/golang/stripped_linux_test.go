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

//go:build linux

package golang

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"testing"
)

func TestDecodeAMD64Rate(t *testing.T) {
	const (
		entry   = uint64(0x1000)
		address = uint64(0x3000)
	)
	code := []byte{
		0x48, 0x8b, 0x05, 0, 0, 0, 0, // MOV address(%RIP), RAX
		0x66, 0x90, // NOP
		0x48, 0x83, 0xf8, 0x01, // CMP RAX, 1
	}
	binary.LittleEndian.PutUint32(code[3:7], uint32(address-(entry+7)))
	file := testRateELF(code, nil, 0x100)

	got, err := decodeAMD64Rate(file, entry, code)
	if err != nil {
		t.Fatal(err)
	}
	if got != address {
		t.Fatalf("address=%#x, want %#x", got, address)
	}
}

func TestDecodeAMD64RateRejectsUnconfirmedLoad(t *testing.T) {
	const (
		entry   = uint64(0x1000)
		address = uint64(0x3000)
	)
	code := []byte{0x48, 0x8b, 0x05, 0, 0, 0, 0}
	binary.LittleEndian.PutUint32(code[3:7], uint32(address-(entry+7)))
	file := testRateELF(code, nil, 0x100)

	if _, err := decodeAMD64Rate(file, entry, code); err == nil {
		t.Fatal("unconfirmed zero-valued global was accepted")
	}
}

func testRateELF(code, data []byte, dataMemSize uint64) *elf.File {
	return &elf.File{
		FileHeader: elf.FileHeader{
			Class: elf.ELFCLASS64, Data: elf.ELFDATA2LSB,
			ByteOrder: binary.LittleEndian, Machine: elf.EM_X86_64,
		},
		Progs: []*elf.Prog{
			{
				ProgHeader: elf.ProgHeader{
					Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_X,
					Vaddr: 0x1000, Filesz: uint64(len(code)), Memsz: uint64(len(code)),
				},
				ReaderAt: bytes.NewReader(code),
			},
			{
				ProgHeader: elf.ProgHeader{
					Type: elf.PT_LOAD, Flags: elf.PF_R | elf.PF_W,
					Vaddr: 0x3000, Filesz: uint64(len(data)), Memsz: dataMemSize,
				},
				ReaderAt: bytes.NewReader(data),
			},
		},
	}
}
