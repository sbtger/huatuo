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
	"strings"
	"time"
)

// Gate states must match the oom_snapshot_gate_state enum in bpf/abi/oom_types.h.
const (
	OOMSnapshotGateDisabled uint8 = 0
	OOMSnapshotGateAdmitted uint8 = 1
	OOMSnapshotGateBusy     uint8 = 2
	OOMSnapshotGateCooldown uint8 = 3
)

const (
	OOMSnapshotAckCaptured uint32 = iota
	OOMSnapshotAckPartial
	OOMSnapshotAckUnavailable
	OOMSnapshotAckFailed
	OOMSnapshotAckFiltered
)

// Release reasons must match the oom_snapshot_release_reason enum in
// bpf/abi/oom_types.h.
const (
	OOMSnapshotReleaseACK              uint32 = 1
	OOMSnapshotReleaseDeadline         uint32 = 2
	OOMSnapshotReleaseWorkLimit        uint32 = 3
	OOMSnapshotReleasePerfOutputFailed uint32 = 4
)

func OOMSnapshotReleaseReasonName(reason uint32) string {
	switch reason {
	case OOMSnapshotReleaseACK:
		return "ack"
	case OOMSnapshotReleaseDeadline:
		return "deadline"
	case OOMSnapshotReleaseWorkLimit:
		return "work_limit"
	case OOMSnapshotReleasePerfOutputFailed:
		return "perf_output_failed"
	default:
		return "unknown"
	}
}

func OOMSnapshotStatusToAck(status CompletionStatus) uint32 {
	switch {
	case status == StatusComplete:
		return OOMSnapshotAckCaptured
	case status.IsPartial():
		return OOMSnapshotAckPartial
	case status == StatusProviderUnavailable ||
		status == StatusIdentityUnavailable:
		return OOMSnapshotAckUnavailable
	case status == StatusFiltered:
		return OOMSnapshotAckFiltered
	default:
		return OOMSnapshotAckFailed
	}
}

func OOMSnapshotDeadlineWithReserve(ctx context.Context,
	reserve time.Duration,
) (time.Time, bool) {
	deadline, _ := ctx.Deadline()
	if deadline.IsZero() {
		return time.Time{}, false
	}
	return deadline.Add(-reserve), true
}

func OOMSnapshotDeadlineReached(deadline time.Time, enabled bool) bool {
	return enabled && !time.Now().Before(deadline)
}

func OOMSnapshotPartialCaptureStatus(partialReason string, timedOut bool) CompletionStatus {
	if timedOut {
		return StatusPartialDeadline
	}
	return classifyPartialCaptureReason(partialReason)
}

func classifyPartialCaptureReason(partialReason string) CompletionStatus {
	if partialReason == "" {
		return StatusPartialRecordLimit
	}
	reason := strings.ToLower(partialReason)
	switch {
	case strings.Contains(reason, "deadline"):
		return StatusPartialDeadline
	case strings.Contains(reason, "object work limit"):
		return StatusPartialObjectLimit
	case strings.Contains(reason, "object scan limit"):
		return StatusPartialObjectLimit
	case strings.Contains(reason, "sample limit"):
		return StatusPartialObjectLimit
	case strings.Contains(reason, "safety limit"):
		return StatusPartialRecordLimit
	default:
		return StatusPartialRecordLimit
	}
}
