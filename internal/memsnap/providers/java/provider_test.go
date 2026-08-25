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

func TestReadDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := (processMemory{ctx: ctx}).check(); err == nil {
		t.Fatal("canceled capture allowed a remote read")
	}
}

func TestFinishStatus(t *testing.T) {
	tests := []struct {
		name                  string
		partialReason         string
		failedHumongousGroups int
	}{
		{name: "concurrent scan"},
		{name: "deadline", partialReason: "deadline reached during sampling"},
		{name: "failed humongous groups", failedHumongousGroups: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			snapshot := &memsnap.Snapshot{Reason: test.partialReason}
			finishStatus(snapshot, test.failedHumongousGroups, 1, 1)
			if snapshot.Status != memsnap.StatusPartial {
				t.Fatalf("status=%+v", snapshot)
			}
			if snapshot.Reason == "" {
				t.Fatalf("missing partial reason: %+v", snapshot)
			}
		})
	}
}
