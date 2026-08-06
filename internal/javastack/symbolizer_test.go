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

func TestResolvePrefersHotspotDirectMethod(t *testing.T) {
	manager := NewSymbolManager()
	snapshot := &Snapshot{
		PCs: []uint64{0x1000}, DirectFrames: []DirectFrame{{
			PC: 0x1000, CompileID: 42, Flags: DirectFrameResolved,
			ClassName: "demo/App", MethodName: "run",
		}},
	}
	resolution := manager.Resolve(snapshot)
	if len(resolution.Frames) != 1 || resolution.Frames[0].Name != "demo.App.run" ||
		resolution.Frames[0].Kind != "java" || resolution.Frames[0].CompileID != 42 {
		t.Fatalf("resolution = %+v", resolution)
	}
	if !resolution.DirectAvailable || resolution.ResolvedFrames != 1 {
		t.Fatalf("resolution metadata = %+v", resolution)
	}
}

func TestResolvePublishesOnlyJavaFrames(t *testing.T) {
	manager := NewSymbolManager()
	snapshot := &Snapshot{
		PCs: []uint64{0x1000, 0x2000, 0x3000},
		DirectFrames: []DirectFrame{
			{PC: 0x1000, Flags: DirectFrameNotNmethod},
			{PC: 0x2000, Flags: DirectFrameResolved, ClassName: "demo/App", MethodName: "run"},
		},
	}
	resolution := manager.Resolve(snapshot)
	if len(resolution.Frames) != 1 || resolution.Frames[0].Name != "demo.App.run" ||
		resolution.Frames[0].Kind != "java" {
		t.Fatalf("resolution = %+v", resolution)
	}
	if resolution.ResolvedFrames != 1 || resolution.UnresolvedFrames != 2 {
		t.Fatalf("resolution metadata = %+v", resolution)
	}
}
