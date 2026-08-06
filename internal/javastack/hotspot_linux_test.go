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

import "testing"

func TestHotspotLayoutRelocatesStaticFieldsPerJVM(t *testing.T) {
	tables := hotspotTables{
		fields: map[string]hotspotField{
			"CodeCache._heaps": {value: 0x1200, isStatic: true},
			"CodeBlob._name":   {value: 24},
		},
		sizes: map[string]uint64{"HeapBlock": 16},
	}
	layout, err := normalizeHotspotLayout(tables, 0x1000)
	if err != nil {
		t.Fatalf("normalizeHotspotLayout: %v", err)
	}
	if got := layout.fields["CodeCache._heaps"].value; got != 0x200 {
		t.Fatalf("normalized static offset = %#x, want %#x", got, 0x200)
	}
	relocated, err := relocateHotspotLayout(layout, 0x4000)
	if err != nil {
		t.Fatalf("relocateHotspotLayout: %v", err)
	}
	if got := relocated.fields["CodeCache._heaps"].value; got != 0x4200 {
		t.Fatalf("relocated static address = %#x, want %#x", got, 0x4200)
	}
	if got := relocated.fields["CodeBlob._name"].value; got != 24 {
		t.Fatalf("instance offset = %d, want 24", got)
	}
}

func TestHotspotLayoutCacheIsBounded(t *testing.T) {
	inspector := newHotspotInspector("/proc")
	for index := 0; index <= maxHotspotLayoutCache; index++ {
		key := hotspotLayoutKey{inode: uint64(index + 1)}
		inspector.rememberLayout(key, hotspotTables{})
	}
	if got := len(inspector.layouts); got != maxHotspotLayoutCache {
		t.Fatalf("cached layouts = %d, want %d", got, maxHotspotLayoutCache)
	}
	if _, ok := inspector.layouts[hotspotLayoutKey{inode: 1}]; ok {
		t.Fatal("oldest HotSpot layout was not evicted")
	}
}
