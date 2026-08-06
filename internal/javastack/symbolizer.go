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

import "strings"

// Frame is one resolved Java frame and its original machine address.
type Frame struct {
	PC          uint64 `json:"pc"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	CompileID   uint32 `json:"compile_id,omitempty"`
	DirectFlags uint32 `json:"hotspot_direct_flags,omitempty"`
}

// Resolution describes one root-to-leaf Java stack and its quality. Native,
// VM stub, interpreter, and unreadable frames are counted but not published.
type Resolution struct {
	Frames           []Frame
	ResolvedFrames   int
	UnresolvedFrames int
	DirectAvailable  bool
	DirectErrors     uint32
}

// SymbolManager resolves only names copied directly from HotSpot while the
// victim still exists. It intentionally owns no per-process native symbol
// cache, so tracking more JVMs does not preload libjvm or shared-library ELF
// symbol tables into Huatuo.
type SymbolManager struct{}

func NewSymbolManager() *SymbolManager {
	return &SymbolManager{}
}

// Resolve converts inner-to-outer PCs to root-to-leaf Java frames.
func (*SymbolManager) Resolve(snapshot *Snapshot) Resolution {
	if snapshot == nil {
		return Resolution{}
	}
	resolution := Resolution{
		Frames:          make([]Frame, 0, len(snapshot.DirectFrames)),
		DirectAvailable: len(snapshot.DirectFrames) != 0,
		DirectErrors:    snapshot.DirectErrorCount,
	}
	for index := len(snapshot.PCs) - 1; index >= 0; index-- {
		if index >= len(snapshot.DirectFrames) {
			resolution.UnresolvedFrames++
			continue
		}
		direct := snapshot.DirectFrames[index]
		if direct.Flags&DirectFrameResolved == 0 ||
			direct.ClassName == "" || direct.MethodName == "" {
			resolution.UnresolvedFrames++
			continue
		}
		resolution.Frames = append(resolution.Frames, Frame{
			PC: snapshot.PCs[index],
			Name: strings.ReplaceAll(direct.ClassName, "/", ".") +
				"." + direct.MethodName,
			Kind: "java", CompileID: direct.CompileID,
			DirectFlags: direct.Flags,
		})
		resolution.ResolvedFrames++
	}
	return resolution
}
