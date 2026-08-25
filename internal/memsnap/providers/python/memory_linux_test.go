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

package python

import (
	"context"
	"errors"
	"math"
	"os"
	"runtime"
	"testing"
	"unsafe"
)

func TestMemoryRange(t *testing.T) {
	tests := []struct {
		name    string
		address uint64
		size    int
	}{
		{name: "null address", size: 8},
		{name: "zero size", address: 0x10000},
		{name: "negative size", address: 0x10000, size: -1},
		{name: "oversized read", address: 0x10000, size: maxReadBytes + 1},
		{name: "address overflow", address: math.MaxUint64 - 3, size: 8},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateRead(test.address, test.size); err == nil {
				t.Fatal("expected invalid range to be rejected")
			}
		})
	}
	if err := validateRead(0x10000, maxReadBytes); err != nil {
		t.Fatalf("validate bounded read: %v", err)
	}
}

func TestMemoryChecksCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	memory := newMemory(os.Getpid(), ctx)
	_, err := memory.read(0x10000, 8)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("read after close error=%v, want context.Canceled", err)
	}
}

func TestMemoryReadReuse(t *testing.T) {
	source := []byte("python-census")
	destination := make([]byte, len(source))
	address := uint64(uintptr(unsafe.Pointer(&source[0])))
	memory := newMemory(os.Getpid(), context.Background())
	if err := memory.readInto(address, destination); err != nil {
		t.Fatal(err)
	}
	var readErr error
	allocations := testing.AllocsPerRun(100, func() {
		readErr = memory.readInto(address, destination)
	})
	runtime.KeepAlive(source)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if allocations != 0 {
		t.Fatalf("readInto allocations=%v, want 0", allocations)
	}
}
