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

package memsnap

import (
	"context"
	"testing"
	"time"
)

func TestOOMSnapshotDeadlineWithReserve(t *testing.T) {
	deadline := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()
	got, ok := OOMSnapshotDeadlineWithReserve(ctx, 150*time.Millisecond)
	if !ok {
		t.Fatal("deadline reserve should be available")
	}
	if got != deadline.Add(-150*time.Millisecond) {
		t.Fatalf("got deadline=%s want=%s", got, deadline.Add(-150*time.Millisecond))
	}
}

func TestOOMSnapshotDeadlineWithReserveWithoutDeadline(t *testing.T) {
	got, ok := OOMSnapshotDeadlineWithReserve(context.Background(),
		150*time.Millisecond)
	if ok {
		t.Fatalf("deadline reserve enabled for background context: %s", got)
	}
}

func TestOOMSnapshotPartialCaptureStatus(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		timedOut bool
		want     CompletionStatus
	}{
		{name: "deadline", reason: "deadline reached during external object scan", want: StatusPartialDeadline},
		{name: "sample limit", reason: "object work limit reached", want: StatusPartialObjectLimit},
		{name: "object scan limit", reason: "object scan limit reached", want: StatusPartialObjectLimit},
		{name: "sampled limits", reason: "sample limit reached", want: StatusPartialObjectLimit},
		{name: "safety limit", reason: "safety limit reached", want: StatusPartialRecordLimit},
		{name: "timed out", reason: "", timedOut: true, want: StatusPartialDeadline},
		{name: "unknown", reason: "unexpected partial", want: StatusPartialRecordLimit},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := OOMSnapshotPartialCaptureStatus(test.reason, test.timedOut); got != test.want {
				t.Fatalf("got=%s want=%s", got, test.want)
			}
		})
	}
}

func TestOOMSnapshotStatusToAck(t *testing.T) {
	tests := []struct {
		name string
		got  CompletionStatus
		want uint32
	}{
		{name: "complete", got: StatusComplete, want: OOMSnapshotAckCaptured},
		{name: "partial", got: StatusPartialDeadline, want: OOMSnapshotAckPartial},
		{name: "provider unavailable", got: StatusProviderUnavailable, want: OOMSnapshotAckUnavailable},
		{name: "identity unavailable", got: StatusIdentityUnavailable, want: OOMSnapshotAckUnavailable},
		{name: "filtered", got: StatusFiltered, want: OOMSnapshotAckFiltered},
		{name: "failed", got: StatusCaptureFailed, want: OOMSnapshotAckFailed},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := OOMSnapshotStatusToAck(test.got); got != test.want {
				t.Fatalf("got=%d want=%d", got, test.want)
			}
		})
	}
}
