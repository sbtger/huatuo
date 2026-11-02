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

//go:build integration && linux

package autotracing

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"testing"

	"golang.org/x/sys/unix"
)

// Real procfs catches constructors that leave process handles awaiting GC.
func TestTopMemoryProcessesDoesNotAccumulatePidfds(t *testing.T) {
	fd, err := unix.PidfdOpen(os.Getpid(), 0)
	if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EPERM) {
		t.Skipf("pidfd unavailable: %v", err)
	}
	if err != nil {
		t.Fatalf("probe pidfd support: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	previous := debug.SetGCPercent(-1)
	t.Cleanup(func() { debug.SetGCPercent(previous); runtime.GC() })

	count := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, entry := range entries {
			target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if err != nil {
				t.Fatal(err)
			}
			if target == "anon_inode:[pidfd]" {
				n++
			}
		}
		return n
	}
	baseline := count()
	for _, metric := range []memoryType{memoryRSS, memoryShared} {
		for round := 0; round < 3; round++ {
			ranked, err := topMemoryProcesses(1<<20, metric)
			if err != nil {
				t.Fatal(err)
			}
			if len(ranked) == 0 {
				t.Fatal("real procfs returned no ranked processes")
			}
			foundSelf := false
			for i, process := range ranked {
				if i > 0 && ranked[i-1].MemSize < process.MemSize {
					t.Fatal("process ranking is not descending")
				}
				if process.identity.TGID != int(process.PID) || process.identity.StartTimeTicks == 0 {
					t.Fatalf("ranked process lacks start-time identity: %+v", process)
				}
				if process.PID == int32(os.Getpid()) {
					foundSelf = true
				}
			}
			if !foundSelf {
				t.Fatal("process ranking omitted the live test process")
			}
			if after := count(); after > baseline {
				t.Fatalf("metric %d round %d: pidfds grew from %d to %d with GC disabled", metric, round, baseline, after)
			}
		}
	}
}

func BenchmarkTopMemoryProcesses(b *testing.B) {
	for b.Loop() {
		if _, err := topMemoryProcesses(10, memoryRSS); err != nil {
			b.Fatal(err)
		}
	}
}
