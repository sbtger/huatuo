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

package java

import "testing"

func TestValidateHotSpotOffsets(t *testing.T) {
	fields := []offsetField{{name: "TypeName", width: 8}}

	if err := validateOffsets(map[string]uint64{"TypeName": 248}, 256,
		fields); err != nil {
		t.Fatalf("in-bounds offset rejected: %v", err)
	}
	if err := validateOffsets(map[string]uint64{"TypeName": 249}, 256,
		fields); err == nil {
		t.Fatal("offset whose trailing bytes exceed the stride was accepted")
	}
	if err := validateOffsets(map[string]uint64{"TypeName": 256}, 256,
		fields); err == nil {
		t.Fatal("offset equal to stride was accepted")
	}
	if err := validateOffsets(map[string]uint64{}, 256, fields); err == nil {
		t.Fatal("missing offset was accepted")
	}
}

func TestMissingHotSpotOffset(t *testing.T) {
	metadata := &vmMeta{
		structs:   make(map[string]vmStruct),
		constants: make(map[string]int64),
	}
	if err := metadata.validate(); err == nil {
		t.Fatal("incomplete HotSpot metadata was accepted")
	}
}
