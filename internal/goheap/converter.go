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

import (
	"fmt"
	"math"
	"slices"
	"time"

	"huatuo-bamai/internal/profiler"
)

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

// Bucket is the architecture-independent representation copied from one
// runtime.memProfile bucket by BPF.
type Bucket struct {
	StackDepth uint64
	Stack      [MaxStackDepth]uint64
	Record     MemRecord
}

// Symbolizer resolves a runtime program counter to a function name.
type Symbolizer interface {
	Resolve(uint64) string
}

// ConversionStats reports partial or inconsistent captured data.
type ConversionStats struct {
	InputBuckets       int
	EmittedBuckets     int
	EmptyBuckets       int
	InvalidStackDepths int
	CounterUnderflows  int
	CounterOverflows   int
	ProfileValueClamps int
}

// Profiles contains the two independent Huatuo views of one heap snapshot.
type Profiles struct {
	InuseSpace   *profiler.ProfileData
	InuseObjects *profiler.ProfileData
	Stats        ConversionStats
}

// Convert converts captured Go runtime buckets into Huatuo profiles.
func Convert(target Target, buckets []Bucket, capturedAt time.Time, symbolizer Symbolizer) (*Profiles, error) {
	layout, err := LayoutForVersion(target.GoVersion)
	if err != nil {
		return nil, err
	}

	stats := ConversionStats{InputBuckets: len(buckets)}
	spaceItems := make([]*profiler.TreeItem, 0, len(buckets))
	objectItems := make([]*profiler.TreeItem, 0, len(buckets))
	for i := range buckets {
		bucket := &buckets[i]
		if bucket.StackDepth == 0 {
			stats.EmptyBuckets++
			continue
		}
		if bucket.StackDepth > uint64(layout.MaxStackDepth) {
			stats.InvalidStackDepths++
			continue
		}

		stack := symbolizeStack(bucket.Stack[:bucket.StackDepth], symbolizer)
		if len(stack) == 0 {
			stats.EmptyBuckets++
			continue
		}
		objects, bytes := inuse(bucket.Record, &stats)
		if objects == 0 && bytes == 0 {
			stats.EmptyBuckets++
			continue
		}
		if bytes != 0 {
			spaceItems = append(spaceItems, &profiler.TreeItem{Stack: cloneStack(stack), Value: profileValue(bytes, &stats)})
		}
		if objects != 0 {
			objectItems = append(objectItems, &profiler.TreeItem{Stack: cloneStack(stack), Value: profileValue(objects, &stats)})
		}
		stats.EmittedBuckets++
	}

	space, err := profiler.ParseTree(capturedAt, profiler.ProfileTypeMemInuseSpace, spaceItems, nil)
	if err != nil {
		return nil, fmt.Errorf("build inuse-space profile: %w", err)
	}
	objects, err := profiler.ParseTree(capturedAt, profiler.ProfileTypeMemInuseObjects, objectItems, nil)
	if err != nil {
		return nil, fmt.Errorf("build inuse-objects profile: %w", err)
	}
	return &Profiles{InuseSpace: space, InuseObjects: objects, Stats: stats}, nil
}

func symbolizeStack(pcs []uint64, symbolizer Symbolizer) [][]byte {
	frames := make([][]byte, 0, len(pcs))
	for _, pc := range pcs {
		if pc == 0 {
			break
		}
		name := ""
		if symbolizer != nil {
			name = symbolizer.Resolve(pc)
		}
		if name == "" {
			name = fmt.Sprintf("0x%x", pc)
		}
		frames = append(frames, []byte(name))
	}
	// runtime.memProfile stores leaf first; pyroscope trees expect root first.
	slices.Reverse(frames)
	return frames
}

func cloneStack(stack [][]byte) [][]byte {
	cloned := make([][]byte, len(stack))
	for i := range stack {
		cloned[i] = slices.Clone(stack[i])
	}
	return cloned
}

func inuse(record MemRecord, stats *ConversionStats) (uint64, uint64) {
	allocs, frees := uint64(0), uint64(0)
	allocBytes, freeBytes := uint64(0), uint64(0)
	cycles := [4]MemRecordCycle{record.Active, record.Future[0], record.Future[1], record.Future[2]}
	for _, cycle := range cycles {
		allocs = saturatedAdd(allocs, cycle.Allocs, stats)
		frees = saturatedAdd(frees, cycle.Frees, stats)
		allocBytes = saturatedAdd(allocBytes, cycle.AllocBytes, stats)
		freeBytes = saturatedAdd(freeBytes, cycle.FreeBytes, stats)
	}
	return nonNegativeDelta(allocs, frees, stats), nonNegativeDelta(allocBytes, freeBytes, stats)
}

func saturatedAdd(left, right uint64, stats *ConversionStats) uint64 {
	if math.MaxUint64-left < right {
		stats.CounterOverflows++
		return math.MaxUint64
	}
	return left + right
}

func nonNegativeDelta(alloc, free uint64, stats *ConversionStats) uint64 {
	if free > alloc {
		stats.CounterUnderflows++
		return 0
	}
	return alloc - free
}

func profileValue(value uint64, stats *ConversionStats) uint64 {
	if value > math.MaxInt64 {
		stats.ProfileValueClamps++
		return math.MaxInt64
	}
	return value
}
