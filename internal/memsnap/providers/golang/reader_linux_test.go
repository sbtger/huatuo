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
	"encoding/binary"
	"errors"
	"os"
	"runtime"
	"testing"
	"time"

	"huatuo-bamai/internal/memsnap"
)

func TestCaptureCurrentProcess(t *testing.T) {
	payloads := make([][]byte, 8)
	for index := range payloads {
		payloads[index] = make([]byte, 2<<20)
		payloads[index][0] = byte(index)
	}
	runtime.GC()
	identity, err := memsnap.ReadProcessIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snapshot, err := newReader("/proc").capture(ctx, identity, 4096)
	runtime.KeepAlive(payloads)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RuntimeVersion == "" || len(snapshot.Allocations) == 0 {
		t.Fatalf("incomplete external snapshot: %+v", snapshot)
	}
}

func TestProcessMemoryChecksCanceledContextBeforeRead(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	memory := processMemory{pid: os.Getpid(), ctx: ctx}
	if err := memory.readInto(0x10000, make([]byte, 8)); !errors.Is(err, context.Canceled) {
		t.Fatalf("read error = %v, want context.Canceled", err)
	}
}

func TestHexStackFallback(t *testing.T) {
	raw := make([]byte, 16)
	binary.LittleEndian.PutUint64(raw, 0x1234)
	binary.LittleEndian.PutUint64(raw[8:], 0x5678)
	stack := resolveStack(raw, binary.LittleEndian, nil)
	if len(stack) != 2 || stack[0] != "0x1234" || stack[1] != "0x5678" {
		t.Fatalf("hex stack = %v", stack)
	}
	snapshot := &snapshot{PartialReason: "mbucket scan was partial"}
	appendPartialReason(snapshot, "symbolization unavailable: test failure")
	if snapshot.PartialReason != "mbucket scan was partial; symbolization unavailable: test failure" {
		t.Fatalf("partial reason = %q", snapshot.PartialReason)
	}
}

func TestAggregateKeyBudget(t *testing.T) {
	aggregates := make(map[string]int)
	var totals []allocationTotals
	keyBytes := 0
	if !aggregateAllocation(aggregates, &totals, []byte("1234"), 1, 10,
		&keyBytes, 4) {
		t.Fatal("first aggregate was rejected")
	}
	if !aggregateAllocation(aggregates, &totals, []byte("1234"), 2, 20,
		&keyBytes, 4) {
		t.Fatal("existing aggregate was rejected at the key budget")
	}
	if aggregateAllocation(aggregates, &totals, []byte("5"), 1, 100,
		&keyBytes, 4) {
		t.Fatal("new aggregate exceeded the key budget")
	}
	aggregate := totals[aggregates["1234"]]
	if keyBytes != 4 || len(aggregates) != 1 || aggregate.inuseObjects != 3 ||
		aggregate.inuseBytes != 30 {
		t.Fatalf("keyBytes=%d aggregates=%+v", keyBytes, aggregates)
	}
}

func TestValidateGoVersion(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"go1.18.10", "go1.19.13", "go1.20.14", "go1.21", "go1.22.2", "go1.23.6 X:boringcrypto", "devel go1.24-deadbeef", "go1.25rc1", "go1.26rc1"} {
		if err := validateGoVersion(version); err != nil {
			t.Fatalf("validateGoVersion(%q): %v", version, err)
		}
	}
	for _, version := range []string{"", "1.24", "go1.17.13", "go1.27rc1", "not-go"} {
		if err := validateGoVersion(version); err == nil {
			t.Fatalf("validateGoVersion(%q) unexpectedly succeeded", version)
		}
	}
}
