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
	"os"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

//go:noinline
func symbolizerFixture() {}

func TestELFSymbolizerResolvesGoPclntab(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	loadBias := selfLoadBias(t, executable)
	symbolizer, err := NewELFSymbolizer(executable, loadBias)
	if err != nil {
		t.Fatal(err)
	}
	pc := reflect.ValueOf(symbolizerFixture).Pointer()
	if got := symbolizer.Resolve(uint64(pc)); !strings.HasSuffix(got, ".symbolizerFixture") {
		t.Fatalf("Resolve(%#x) = %q", pc, got)
	}
}

func TestELFSymbolizerAppliesLoadBias(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	const addedBias = uint64(0x10000000)
	loadBias := selfLoadBias(t, executable)
	symbolizer, err := NewELFSymbolizer(executable, loadBias+addedBias)
	if err != nil {
		t.Fatal(err)
	}
	pc := uint64(reflect.ValueOf(symbolizerFixture).Pointer())
	if got := symbolizer.Resolve(pc + addedBias); !strings.HasSuffix(got, ".symbolizerFixture") {
		t.Fatalf("Resolve(%#x) = %q", pc+addedBias, got)
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
	bias, err := readLoadBias("/proc/self/maps", sys.Ino, offset, vaddr)
	if err != nil {
		t.Fatal(err)
	}
	return bias
}
