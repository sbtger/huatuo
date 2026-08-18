// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package java

import (
	"context"
	"errors"

	"huatuo-bamai/internal/memsnap"
)

type Provider struct {
	reader SnapshotReader
}

func NewProvider(reader SnapshotReader) (*Provider, error) {
	if reader == nil {
		return nil, errors.New("Java external heap reader is required")
	}
	return &Provider{reader: reader}, nil
}

func (p *Provider) Language() memsnap.Language { return memsnap.LanguageJava }

//nolint:gocritic // Providers receive an isolated request value from the coordinator.
func (p *Provider) Capture(ctx context.Context,
	request memsnap.Request,
) (*memsnap.Result, error) {
	snapshot, err := p.reader.Capture(ctx, request.Identity, request.AccessTID,
		request.MaxObjects)
	if err != nil {
		return &memsnap.Result{Manifest: memsnap.Manifest{
			Status: memsnap.StatusProviderUnavailable,
			Coverage: javaCoverage([]string{
				"external HotSpot heap scan is unavailable: " + err.Error(),
			}),
		}}, nil
	}
	status := memsnap.StatusComplete
	truncated := false
	var reasons []string
	if !snapshot.Complete {
		status = memsnap.OOMSnapshotPartialCaptureStatus(snapshot.PartialReason,
			ctx.Err() != nil)
		truncated = true
		reasons = append(reasons, snapshot.PartialReason)
	}
	coverage := javaCoverage([]string{
		"objects in regions changed concurrently with the external scan may be skipped",
		"retained size, GC roots, allocation stacks, and native memory are unavailable",
		"classloader identity is unavailable; field ownership is a bounded sample of direct array references",
	})
	if snapshot.Estimated {
		coverage.SampleRateAssumption =
			"class in-use totals are region-stratified used-byte estimates; sampled fields preserve complete-region observations; field ownership uses at most 64 sampled objects per business class"
	} else {
		coverage.SampleRateAssumption =
			"class counts and shallow bytes are observed scan totals; field ownership uses at most 64 sampled objects per business class"
	}
	result := &memsnap.Result{
		Manifest: memsnap.Manifest{
			RuntimeVersion: snapshot.RuntimeVersion, Status: status,
			Truncated: truncated, TruncationReasons: reasons, Coverage: coverage,
		},
	}
	result.FinalizeLocal = func() error {
		if err := snapshot.FinalizeLocal(); err != nil {
			return err
		}
		coverage := &result.Manifest.Coverage
		coverage.ScannedBytes = snapshot.ScannedBytes
		coverage.HeapUsedBytes = snapshot.HeapUsedBytes
		coverage.ScannedRegions = snapshot.ScannedRegions
		coverage.TotalRegions = snapshot.TotalRegions
		coverage.ClassifiedBytes = snapshot.ClassifiedBytes
		if snapshot.HeapUsedBytes != 0 {
			coverage.RawCoverage = float64(snapshot.ScannedBytes) /
				float64(snapshot.HeapUsedBytes)
		}
		coverage.Estimated = snapshot.Estimated
		coverage.EstimationMethod = snapshot.EstimationMethod
		coverage.SamplingSeed = snapshot.SamplingSeed
		coverage.PlannedRegions = snapshot.PlannedRegions
		coverage.CompletedRegions = snapshot.ScannedRegions
		coverage.SamplingStrata = append(
			[]memsnap.SamplingStratumCoverage(nil), snapshot.SamplingStrata...)
		result.Objects = snapshot.Objects
		return nil
	}
	return result, nil
}

func javaCoverage(gaps []string) memsnap.Coverage {
	return memsnap.Coverage{
		Consistency:   "best_effort_external_hotspot_heap_scan",
		SizeSemantics: "shallow_bytes",
		Impact:        "on_demand_process_vm_readv_heap_dependent",
		KnownGaps:     gaps,
	}
}
