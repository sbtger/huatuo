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

// Package goheap resolves Go Runtime heap-profile metadata on demand.
package goheap

// Identity distinguishes a process from a later process that reuses its TGID.
type Identity struct {
	TGID           uint32
	StartTimeTicks uint64
}

// Target contains the addresses needed to inspect one Go OOM victim.
type Target struct {
	Identity
	GoVersion                   string
	BuildID                     string
	ExecutableKey               string
	SymbolAddress               uint64
	MemProfileRateSymbolAddress uint64
	LoadBias                    uint64
}

func (t *Target) MBucketsAddress() uint64 {
	return t.SymbolAddress + t.LoadBias
}

func (t *Target) MemProfileRateAddress() uint64 {
	if t.MemProfileRateSymbolAddress == 0 {
		return 0
	}
	return t.MemProfileRateSymbolAddress + t.LoadBias
}

// MemRecordCycle mirrors one generation of runtime.memRecordCycle.
type MemRecordCycle struct {
	Allocs     uint64
	Frees      uint64
	AllocBytes uint64
	FreeBytes  uint64
}

// MemRecord mirrors the active and future generations of runtime.memRecord.
type MemRecord struct {
	Active MemRecordCycle
	Future [3]MemRecordCycle
}
