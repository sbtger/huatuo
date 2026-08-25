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
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"unicode/utf8"

	"huatuo-bamai/internal/memsnap"
)

func TestCaptureResultStatus(t *testing.T) {
	unsupported := captureResult(nil, errors.Join(errUnsupportedRuntime,
		errors.New("free-threaded build")))
	if unsupported.Status != memsnap.StatusUnavailable {
		t.Fatalf("unsupported status=%q", unsupported.Status)
	}
	failed := captureResult(nil, errors.New("process memory read failed"))
	if failed.Status != memsnap.StatusFailed {
		t.Fatalf("failed status=%q", failed.Status)
	}
	nilResult := captureResult(nil, nil)
	if nilResult.Status != memsnap.StatusFailed {
		t.Fatalf("nil result status=%q", nilResult.Status)
	}
}

func TestReasonBound(t *testing.T) {
	reason := strings.Repeat("\x01", maxReasonBytes*2)
	results := []*memsnap.Snapshot{
		captureResult(nil, errors.New(reason)),
		captureResult(&memsnap.Snapshot{
			Status: memsnap.StatusPartial, Reason: reason,
		}, nil),
	}
	for _, result := range results {
		if len(result.Reason) > maxReasonBytes {
			t.Fatalf("reason bytes=%d, want at most %d",
				len(result.Reason), maxReasonBytes)
		}
		if !utf8.ValidString(result.Reason) {
			t.Fatal("bounded reason is not valid UTF-8")
		}
		result.DurationMS = math.MaxUint64
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw) > 4096 {
			t.Fatalf("output bytes=%d, want at most 4096", len(raw))
		}
	}
}
