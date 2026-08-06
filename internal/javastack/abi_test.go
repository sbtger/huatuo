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

package javastack

import (
	"testing"
	"unsafe"

	"huatuo-bamai/internal/bpf/abi"
)

func TestJavaStackABILimits(t *testing.T) {
	var event abi.JavaStackEvent
	if got := len(event.Ips); got != 64 {
		t.Fatalf("Java stack depth = %d, want 64", got)
	}
	if got := unsafe.Sizeof(event); got != abi.JavaStackEventSize {
		t.Fatalf("Java stack event size = %d, want %d", got, abi.JavaStackEventSize)
	}
	if got := unsafe.Offsetof(event.Ips); got != 56 {
		t.Fatalf("Java stack PC offset = %d, want 56", got)
	}
}
