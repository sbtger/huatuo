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
	"errors"
	"fmt"
	"testing"

	"huatuo-bamai/internal/memsnap"
)

func TestCaptureResultStatus(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want memsnap.Status
	}{
		{
			"unsupported runtime", fmt.Errorf("%w: go1.17", errUnsupportedRuntime),
			memsnap.StatusUnavailable,
		},
		{
			"missing runtime metadata", errMBucketsSymbolNotFound,
			memsnap.StatusUnavailable,
		},
		{"read failure", errors.New("permission denied"), memsnap.StatusFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := captureResult(nil, test.err)
			if result.Status != test.want || result.Reason == "" {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestSnapshotEntries(t *testing.T) {
	result, err := resultFromSnapshot(&snapshot{
		RuntimeVersion: "go1.24.1", SampleRate: 1, RateKnown: true,
		Allocations: []sample{{
			Stack: []string{"example/cache.allocate", "example/main.run"},
			Bytes: 4096, Objects: 2,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != memsnap.StatusComplete || len(result.Entries) != 1 {
		t.Fatalf("result=%+v", result)
	}
	allocation := result.Entries[0]
	if allocation.Bytes != 4096 || allocation.Objects != 2 ||
		allocation.Name != "example/cache.allocate" ||
		len(allocation.Stack) != 2 || allocation.Stack[0] != "example/cache.allocate" {
		t.Fatalf("allocation=%+v", allocation)
	}
}

func TestAllocationSiteName(t *testing.T) {
	for _, test := range []struct {
		name, want string
		stack      []string
	}{
		{
			name: "first non-runtime frame",
			stack: []string{
				"runtime.mallocgc", "runtime.makeslice",
				"example/cache.allocate", "example/main.run", "runtime.main",
			},
			want: "example/cache.allocate",
		},
		{
			name:  "runtime-only stack",
			stack: []string{"runtime.malg", "runtime.newproc1"}, want: "runtime.malg",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := allocationSiteName(test.stack); got != test.want {
				t.Fatalf("name=%q, want %q", got, test.want)
			}
		})
	}
}

func TestProfileRateStatus(t *testing.T) {
	for _, test := range []struct {
		name      string
		in        snapshot
		want      memsnap.Status
		wantBytes uint64
	}{
		{"unknown", snapshot{Allocations: []sample{{
			Stack: []string{"example/cache.allocate"}, Bytes: 4096, Objects: 2,
		}}}, memsnap.StatusPartial, 4096},
		{"disabled", snapshot{RateKnown: true}, memsnap.StatusUnavailable, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			result, err := resultFromSnapshot(&test.in)
			if err != nil {
				t.Fatal(err)
			}
			if result.Status != test.want || result.Reason == "" ||
				test.wantBytes != 0 && (len(result.Entries) != 1 ||
					result.Entries[0].Bytes != test.wantBytes) {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestAggregateBeforeTopK(t *testing.T) {
	aggregates := make(map[string]int)
	var totals []allocationTotals
	keyBytes := 0
	aggregateAllocation(aggregates, &totals, []byte("same-stack"), 1, 60,
		&keyBytes, maxAggregateKeyBytes)
	aggregateAllocation(aggregates, &totals, []byte("same-stack"), 1, 60,
		&keyBytes, maxAggregateKeyBytes)
	aggregateAllocation(aggregates, &totals, []byte("single-stack"), 1, 100,
		&keyBytes, maxAggregateKeyBytes)
	aggregate := totals[aggregates["same-stack"]]
	if aggregate.inuseBytes != 120 ||
		aggregate.inuseBytes <= totals[aggregates["single-stack"]].inuseBytes {
		t.Fatalf("aggregate=%+v totals=%+v", aggregate, totals)
	}
}

func TestTopKUsesScaledBytes(t *testing.T) {
	aggregates := make(map[string]int)
	var totals []allocationTotals
	keyBytes := 0
	objects, bytes := scaleHeapSample(100, 100, initialMemProfileRate)
	aggregateAllocation(aggregates, &totals, []byte("many-small"), objects, bytes,
		&keyBytes, maxAggregateKeyBytes)
	objects, bytes = scaleHeapSample(1, 1000, initialMemProfileRate)
	aggregateAllocation(aggregates, &totals, []byte("one-large"), objects, bytes,
		&keyBytes, maxAggregateKeyBytes)

	candidates := make(minHeap, 0, 1)
	for key, index := range aggregates {
		total := totals[index]
		keepTop(&candidates, 1, allocation{
			key: key, inuseBytes: total.inuseBytes,
			inuseObjects: total.inuseObjects,
		})
	}
	if candidate := candidates[0]; candidate.key != "many-small" {
		t.Fatalf("candidate=%+v", candidate)
	}
}
