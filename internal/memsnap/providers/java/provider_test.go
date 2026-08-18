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

package java

import (
	"context"
	"testing"

	"huatuo-bamai/internal/memsnap"
)

type fixtureReader struct {
	result *ExternalSnapshot
	err    error
}

func (f fixtureReader) Capture(context.Context, memsnap.ProcessIdentity,
	int, int,
) (*ExternalSnapshot, error) {
	return f.result, f.err
}

func TestProviderCapture(t *testing.T) {
	provider, err := NewProvider(fixtureReader{result: &ExternalSnapshot{
		Complete: true, Estimated: true,
		EstimationMethod: "g1_region_stratified_v1", SamplingSeed: 42,
		ScannedBytes: 96, ClassifiedBytes: 80, HeapUsedBytes: 384,
		ScannedRegions: 2, TotalRegions: 8, PlannedRegions: 2,
		Objects: []memsnap.ObjectAggregate{{
			TypeName: "service.Payload", Count: 12, ShallowBytes: 384,
			SampledCount: 3, SampledBytes: 96, Estimated: true,
		}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := provider.Capture(context.Background(), memsnap.Request{
		Identity:       memsnap.ProcessIdentity{TGID: 42},
		MaxOutputBytes: 1 << 20, MaxObjects: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := result.FinalizeLocal(); err != nil {
		t.Fatal(err)
	}
	if result.Manifest.Status != memsnap.StatusComplete || len(result.Objects) != 1 {
		t.Fatalf("status=%s objects=%d", result.Manifest.Status, len(result.Objects))
	}
	coverage := result.Manifest.Coverage
	if !coverage.Estimated || coverage.EstimationMethod !=
		"g1_region_stratified_v1" || coverage.RawCoverage != 0.25 ||
		coverage.CompletedRegions != 2 {
		t.Fatalf("coverage=%+v", coverage)
	}
	payload := memsnap.RuntimePayloadFromResult(result)
	if len(payload.Entries) != 1 || payload.Entries[0].InuseBytes != 384 ||
		payload.Entries[0].SampledBytes != 96 || !payload.Entries[0].Estimated {
		t.Fatalf("entry=%+v", payload.Entries)
	}
}
