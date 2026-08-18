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

import "testing"

func TestLayoutForVersion(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"go1.20.14", "go1.21", "go1.22.2", "go1.23.6 X:boringcrypto", "devel go1.24-deadbeef", "go1.25rc1"} {
		layout, err := LayoutForVersion(version)
		if err != nil {
			t.Fatalf("LayoutForVersion(%q): %v", version, err)
		}
		if layout.BucketHeaderSize != 48 || layout.RecordCycles != 4 || layout.MaxStackDepth != 64 {
			t.Fatalf("LayoutForVersion(%q) = %+v", version, layout)
		}
	}
}

func TestLayoutForVersionRejectsUnknownLayouts(t *testing.T) {
	t.Parallel()
	for _, version := range []string{"", "1.24", "go1.19.13", "go1.26rc1", "not-go"} {
		if _, err := LayoutForVersion(version); err == nil {
			t.Fatalf("LayoutForVersion(%q) unexpectedly succeeded", version)
		}
	}
}
