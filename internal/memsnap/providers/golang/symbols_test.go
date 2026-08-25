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
	"encoding/binary"
	"errors"
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"huatuo-bamai/internal/memsnap"
)

func TestPCLNTextStart(t *testing.T) {
	for _, magic := range []uint32{0xfffffff0, 0xfffffff1} {
		header := make([]byte, 32)
		binary.LittleEndian.PutUint32(header[:4], magic)
		header[7] = 8
		binary.LittleEndian.PutUint64(header[24:32], 0x12345678)

		got, err := pclnTextStart(header, binary.LittleEndian)
		if err != nil {
			t.Fatal(err)
		}
		if got != 0x12345678 {
			t.Fatalf("magic=%#x textStart = %#x, want %#x", magic, got,
				uint64(0x12345678))
		}
	}
}

//go:noinline
func symbolizerFixture() {}

func TestELFSymbolizer(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	loadBias := selfLoadBias(t, executable)
	pc := uint64(reflect.ValueOf(symbolizerFixture).Pointer())
	for _, addedBias := range []uint64{0, 0x10000000} {
		symbolizer, err := newSymbolizer(context.Background(), executable,
			loadBias+addedBias, nil)
		if err != nil {
			t.Fatal(err)
		}
		runtimePC := pc + addedBias + 1
		if got := symbolizer.resolve(runtimePC); !strings.HasSuffix(got,
			".symbolizerFixture") {
			t.Fatalf("added bias %#x: resolve(%#x) = %q", addedBias, runtimePC, got)
		}
	}
}

func TestSymbolTableReuse(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := elf.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	table, err := newGoSymbolTable(context.Background(), file)
	if err != nil {
		t.Fatal(err)
	}
	symbolizer, err := newSymbolizer(context.Background(),
		"/does/not/need/to/exist", 0, table)
	if err != nil {
		t.Fatal(err)
	}
	if symbolizer.table != table {
		t.Fatal("symbolizer did not reuse the parsed Go symbol table")
	}
}

func TestSymbolizerCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := newSymbolizer(ctx, "/does/not/need/to/exist", 0, nil); !errors.Is(
		err, context.Canceled) {
		t.Fatalf("newSymbolizer error = %v, want context canceled", err)
	}
}

func selfLoadBias(t *testing.T, executable string) uint64 {
	t.Helper()
	file, err := elf.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if file.Type != elf.ET_DYN {
		return 0
	}
	stat, err := os.Stat(executable)
	if err != nil {
		t.Fatal(err)
	}
	sys, ok := stat.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("executable stat has no Stat_t")
	}
	offset, vaddr, err := firstLoadSegment(file)
	if err != nil {
		t.Fatal(err)
	}
	mappings, err := memsnap.ReadProcMaps("/proc/self/maps")
	if err != nil {
		t.Fatal(err)
	}
	bias, err := memsnap.FindLoadBias(mappings, sys.Ino, offset, vaddr)
	if err != nil {
		t.Fatal(err)
	}
	return bias
}
