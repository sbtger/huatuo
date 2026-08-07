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
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

func TestReadStartTimeTicksHandlesSpacesAndParentheses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stat")
	fields := "S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20"
	if err := os.WriteFile(path, []byte("99 (worker ) name) "+fields+"\n"), 0o600); err != nil {
		t.Fatalf("write stat: %v", err)
	}

	got, err := readStartTimeTicks(path)
	if err != nil {
		t.Fatalf("readStartTimeTicks: %v", err)
	}
	if got != 424242 {
		t.Fatalf("start time = %d, want 424242", got)
	}
}

func TestReadLoadBiasUsesExecutableInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maps")
	maps := "400000-401000 r--p 00000000 00:00 111 /not/the/executable\n" +
		"7f001000-7f002000 r--p 00001000 00:00 222 /target\n"
	if err := os.WriteFile(path, []byte(maps), 0o600); err != nil {
		t.Fatalf("write maps: %v", err)
	}

	got, err := readLoadBias(path, 222, 0x1000, 0)
	if err != nil {
		t.Fatalf("readLoadBias: %v", err)
	}
	if got != 0x7f001000 {
		t.Fatalf("load bias = %#x, want %#x", got, uint64(0x7f001000))
	}
}

func TestParseELFNote(t *testing.T) {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint32(data[0:4], 4)
	binary.LittleEndian.PutUint32(data[4:8], 7)
	copy(data[12:16], "Go\x00\x00")
	copy(data[16:23], "buildid")

	got, ok := parseELFNote(data, binary.LittleEndian)
	if !ok || string(got) != "buildid" {
		t.Fatalf("parseELFNote = %q, %v", got, ok)
	}
}

func TestInspectCurrentGoProcess(t *testing.T) {
	discoverer := NewProcDiscoverer("/proc")
	target, _, err := discoverer.inspectPID(os.Getpid())
	if errors.Is(err, errMBucketsSymbolNotFound) {
		t.Skip("go test runner omitted runtime.mbuckets; direct test binaries are supported")
	}
	if err != nil {
		t.Fatalf("inspect current process: %v", err)
	}
	if target.GoVersion == "" || target.MBucketsAddress() == 0 || target.StartTimeTicks == 0 {
		t.Fatalf("incomplete target: %+v", target)
	}
}

func TestLookupStrippedMBucketsMatchesELFSymbol(t *testing.T) {
	// Keep the memory profiler linked into this test binary.
	runtime.MemProfile(nil, false)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	file, err := elf.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	want, err := lookupSymbol(file, "runtime.mbuckets")
	if errors.Is(err, errMBucketsSymbolNotFound) {
		t.Skip("test executable has no ELF symbols")
	}
	if err != nil {
		t.Fatal(err)
	}
	got, err := lookupStrippedMBuckets(file)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("stripped runtime.mbuckets = %#x, want %#x", got, want)
	}
}

func TestDiscoverIncludesTargetProcess(t *testing.T) {
	pidText := os.Getenv("TEST_GOHEAP_PID")
	if pidText == "" {
		t.Skip("TEST_GOHEAP_PID is not set")
	}
	pid, err := strconv.Atoi(pidText)
	if err != nil {
		t.Fatalf("parse TEST_GOHEAP_PID: %v", err)
	}

	targets, err := NewProcDiscoverer("/proc").Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	for _, target := range targets {
		if target.PID == uint32(pid) {
			if target.StartTimeTicks == 0 || target.MBucketsAddress() == 0 {
				t.Fatalf("incomplete target: %+v", target)
			}
			return
		}
	}
	t.Fatalf("PID %d was not discovered among %d targets", pid, len(targets))
}
