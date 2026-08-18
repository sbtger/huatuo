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

package python

import (
	"context"
	"testing"
	"time"

	"huatuo-bamai/internal/memsnap"
)

type stubExecutor struct {
	response *CaptureResponse
	err      error
}

type requestRecordingExecutor struct {
	request memsnap.Request
}

//nolint:gocritic // The stub records the production value-oriented request contract.
func (e *requestRecordingExecutor) Execute(_ context.Context,
	request memsnap.Request,
) (*CaptureResponse, error) {
	e.request = request
	return &CaptureResponse{Status: memsnap.StatusComplete}, nil
}

func (e stubExecutor) Execute(context.Context,
	memsnap.Request,
) (*CaptureResponse, error) {
	return e.response, e.err
}

func TestProviderReturnsBusinessClassAndFieldShapes(t *testing.T) {
	provider, err := NewProvider(stubExecutor{response: &CaptureResponse{
		RuntimeVersion: "3.14.1", Status: memsnap.StatusComplete,
		Coverage: memsnap.Coverage{
			Consistency:   "cpython_gc_tracked_object_census",
			SizeSemantics: "shallow_bytes", KnownGaps: []string{"native excluded"},
		},
		Objects: []memsnap.ObjectAggregate{{
			TypeName: "service.cache.CacheEntry", Count: 20, ShallowBytes: 960,
			AverageBytes: 48,
			Fields: []memsnap.FieldShape{{
				Name: "payload", ReferencedType: "builtins.bytearray",
				ReferenceCount: 20, UniqueReferencedObjects: 20,
				ReferencedShallowBytes: 81920,
			}},
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Capture(context.Background(), memsnap.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if err := result.FinalizeLocal(); err != nil {
		t.Fatal(err)
	}
	if len(result.Objects) != 1 || result.Objects[0].Fields[0].Name != "payload" {
		t.Fatalf("objects=%+v", result.Objects)
	}
}

func TestProviderMarksUnsupportedRuntimeUnavailable(t *testing.T) {
	provider, err := NewProvider(stubExecutor{err: ErrUnsupportedRuntime})
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Capture(context.Background(), memsnap.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Status != memsnap.StatusProviderUnavailable {
		t.Fatalf("manifest=%+v", result.Manifest)
	}
}

func TestProviderPreservesGateDeadlineForExecutor(t *testing.T) {
	hardDeadline := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), hardDeadline)
	defer cancel()
	executor := &requestRecordingExecutor{}
	provider, err := NewProvider(executor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Capture(ctx, memsnap.Request{
		GateDeadline: hardDeadline,
	}); err != nil {
		t.Fatal(err)
	}
	if got := executor.request.GateDeadline; !got.Equal(hardDeadline) {
		t.Fatalf("gate deadline=%s, want %s", got, hardDeadline)
	}
}

func TestProviderAcceptsPartialRecordLimit(t *testing.T) {
	provider, err := NewProvider(stubExecutor{response: &CaptureResponse{
		Status:    memsnap.StatusPartialRecordLimit,
		Truncated: true,
		Coverage: memsnap.Coverage{
			Consistency:   "cpython_pymalloc_stratified_sample",
			SizeSemantics: "estimated_pymalloc_block_bytes",
			KnownGaps:     []string{"pool changed"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Capture(context.Background(), memsnap.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Status != memsnap.StatusPartialRecordLimit ||
		!result.Manifest.Truncated {
		t.Fatalf("manifest=%+v", result.Manifest)
	}
}
