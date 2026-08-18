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
	"math"
	"sort"
	"strings"

	"huatuo-bamai/internal/memsnap"
)

// scaleHeapSample follows runtime/pprof's Poisson sampling correction.
func scaleHeapSample(count, size, rate int64) (int64, int64) {
	if count == 0 || size == 0 {
		return 0, 0
	}
	if rate <= 1 {
		return count, size
	}
	averageSize := float64(size) / float64(count)
	scale := 1 / (1 - math.Exp(-averageSize/float64(rate)))
	return clampScaleToInt64(float64(count) * scale),
		clampScaleToInt64(float64(size) * scale)
}

// clampScaleToInt64 saturates the scaled sample to int64. A victim configured
// with an extreme runtime.MemProfileRate could otherwise overflow the float64
// -> int64 conversion, which is implementation-defined and yields a negative
// in-use value downstream.
func clampScaleToInt64(value float64) int64 {
	if value >= math.MaxInt64 {
		return math.MaxInt64
	}
	if value <= 0 {
		return 0
	}
	return int64(value)
}

func stackKey(stack []string) string { return strings.Join(stack, "\x00") }

func sortAllocations(allocations []memsnap.AllocationSample) {
	sort.Slice(allocations, func(i, j int) bool {
		if allocations[i].InuseBytes == allocations[j].InuseBytes {
			return stackKey(allocations[i].Stack) < stackKey(allocations[j].Stack)
		}
		return allocations[i].InuseBytes > allocations[j].InuseBytes
	})
}
