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
	"context"
	"testing"

	"huatuo-bamai/internal/memsnap"
)

type stubReader struct {
	snapshot *RawSnapshot
	err      error
}

func (r stubReader) Capture(context.Context, memsnap.ProcessIdentity,
	int, int, int,
) (*RawSnapshot, error) {
	return r.snapshot, r.err
}

func TestProviderConvertsExternalMBuckets(t *testing.T) {
	provider, err := NewProvider(stubReader{snapshot: &RawSnapshot{
		RuntimeVersion: "go1.24.1", SampleRate: 1, RateKnown: true,
		Complete: true, VisitedBuckets: 9000,
		Allocations: []RawAllocation{{
			Stack:        []string{"example/cache.allocate", "example/main.run"},
			SampledBytes: 4096, SampledCount: 2,
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Capture(context.Background(), memsnap.Request{
		MaxStacks: 4096, MaxStackDepth: 64,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Status != memsnap.StatusComplete ||
		len(result.Allocations) != 1 {
		t.Fatalf("result=%+v", result)
	}
	allocation := result.Allocations[0]
	if allocation.InuseBytes != 4096 || allocation.InuseObjects != 2 ||
		len(allocation.Stack) != 2 {
		t.Fatalf("allocation=%+v", allocation)
	}
}

func TestProviderReportsDisabledMemProfile(t *testing.T) {
	provider, err := NewProvider(stubReader{snapshot: &RawSnapshot{
		RuntimeVersion: "go1.24", RateKnown: true, SampleRate: 0,
		Complete: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Capture(context.Background(), memsnap.Request{
		MaxStacks: 10, MaxStackDepth: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Status != memsnap.StatusProviderUnavailable {
		t.Fatalf("status=%s", result.Manifest.Status)
	}
}

func TestTopCandidateSelectionDoesNotStopAtLimit(t *testing.T) {
	candidates := make(candidateHeap, 0, 2)
	pushTopCandidate(&candidates, 2, bucketCandidate{bytes: 1})
	pushTopCandidate(&candidates, 2, bucketCandidate{bytes: 2})
	pushTopCandidate(&candidates, 2, bucketCandidate{bytes: 100})
	if len(candidates) != 2 {
		t.Fatalf("candidate count=%d", len(candidates))
	}
	for _, candidate := range candidates {
		if candidate.bytes == 1 {
			t.Fatal("early small bucket survived Top-K replacement")
		}
	}
}
