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
	"errors"
	"fmt"
	"math"

	"huatuo-bamai/internal/memsnap"
)

// RawAllocation is one selected runtime.memProfile bucket. Stack order is
// allocation site first, matching runtime.MemProfileRecord.Stack.
type RawAllocation struct {
	Stack        []string
	SampledBytes uint64
	SampledCount uint64
}

// RawSnapshot is copied entirely out of the victim before the kill gate ACK.
type RawSnapshot struct {
	RuntimeVersion string
	SampleRate     int64
	RateKnown      bool
	Allocations    []RawAllocation
	VisitedBuckets int
	Complete       bool
	PartialReason  string
}

type Reader interface {
	Capture(ctx context.Context, identity memsnap.ProcessIdentity,
		accessTID, maxStacks, maxStackDepth int,
	) (*RawSnapshot, error)
}

type Provider struct {
	reader Reader
}

func NewProvider(reader Reader) (*Provider, error) {
	if reader == nil {
		return nil, errors.New("Go external heap reader is required")
	}
	return &Provider{reader: reader}, nil
}

func (p *Provider) Language() memsnap.Language { return memsnap.LanguageGo }

//nolint:gocritic // Providers receive an isolated request value from the coordinator.
func (p *Provider) Capture(ctx context.Context,
	request memsnap.Request,
) (*memsnap.Result, error) {
	snapshot, err := p.reader.Capture(ctx, request.Identity, request.AccessTID,
		request.MaxStacks, request.MaxStackDepth)
	if err != nil {
		return unavailableResult(fmt.Sprintf("read Go runtime mbuckets: %v", err)), nil
	}
	if snapshot == nil {
		return nil, errors.New("Go external heap reader returned a nil snapshot")
	}
	if snapshot.RateKnown && snapshot.SampleRate <= 0 {
		return unavailableResult("Go heap profiling is disabled by MemProfileRate=0"), nil
	}
	status := memsnap.StatusComplete
	truncated := false
	var reasons []string
	if !snapshot.Complete {
		status = memsnap.OOMSnapshotPartialCaptureStatus(snapshot.PartialReason,
			ctx.Err() != nil)
		truncated = true
		reason := snapshot.PartialReason
		if reason == "" {
			reason = "mbucket scan did not reach the end of the chain"
		}
		reasons = []string{reason}
	}
	rateAssumption := "runtime_value_read_at_capture"
	gaps := []string{
		"native memory is excluded",
		"object type and retaining paths are unavailable",
		"counters may change while the external reader walks mbuckets",
	}
	if !snapshot.RateKnown {
		rateAssumption = "unscaled_rate_symbol_unavailable"
		gaps = append(gaps, "MemProfileRate was not recoverable; values are unscaled samples")
	}
	result := &memsnap.Result{Manifest: memsnap.Manifest{
		RuntimeVersion: snapshot.RuntimeVersion, Status: status,
		Truncated: truncated, TruncationReasons: reasons,
		Coverage: memsnap.Coverage{
			Consistency:          "external_runtime_mbuckets_non_atomic",
			SizeSemantics:        "sampled_allocation_profile_estimate",
			ObjectType:           "unavailable",
			SampleRateAssumption: rateAssumption,
			Impact:               "two_phase_top_k_external_read",
			KnownGaps:            gaps,
		},
	}}
	aggregates := make(map[string]*memsnap.AllocationSample,
		len(snapshot.Allocations))
	for _, raw := range snapshot.Allocations {
		if len(raw.Stack) == 0 || len(raw.Stack) > request.MaxStackDepth {
			continue
		}
		sampledCount := clampUint64(raw.SampledCount)
		sampledBytes := clampUint64(raw.SampledBytes)
		objects, bytes := scaleHeapSample(sampledCount, sampledBytes,
			snapshot.SampleRate)
		key := stackKey(raw.Stack)
		aggregate := aggregates[key]
		if aggregate == nil {
			aggregate = &memsnap.AllocationSample{
				Stack: append([]string(nil), raw.Stack...),
			}
			aggregates[key] = aggregate
		}
		aggregate.SampledBytes = saturatedInt64Add(aggregate.SampledBytes,
			sampledBytes)
		aggregate.SampledCount = saturatedInt64Add(aggregate.SampledCount,
			sampledCount)
		aggregate.InuseBytes = saturatedInt64Add(aggregate.InuseBytes, bytes)
		aggregate.InuseObjects = saturatedInt64Add(aggregate.InuseObjects, objects)
	}
	result.Allocations = make([]memsnap.AllocationSample, 0, len(aggregates))
	for _, allocation := range aggregates {
		result.Allocations = append(result.Allocations, *allocation)
	}
	sortAllocations(result.Allocations)
	return result, nil
}

func clampUint64(value uint64) int64 {
	if value > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(value)
}

func saturatedInt64Add(left, right int64) int64 {
	if right > 0 && left > math.MaxInt64-right {
		return math.MaxInt64
	}
	return left + right
}

func unavailableResult(reason string) *memsnap.Result {
	return &memsnap.Result{Manifest: memsnap.Manifest{
		Status: memsnap.StatusProviderUnavailable,
		Coverage: memsnap.Coverage{
			Consistency: "not_captured", SizeSemantics: "unavailable",
			KnownGaps: []string{reason},
		},
	}}
}
