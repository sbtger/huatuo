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

// Package collector orchestrates runtime snapshots independently of their trigger.

package collector

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/ccfos/huatuo/internal/memsnapshot"
)

// ErrCaptureBusy lets triggers retain their event without concurrent external scans.
var (
	ErrCaptureBusy = errors.New("another memory snapshot is in progress")
	captureSlot    = make(chan struct{}, 1)
)

// Options uses the before-OOM budgets as defaults for zero-valued fields.
// Inline collection is cooperative; a configured worker enforces the caller budget.
type Options struct {
	MaxMemoryObjectEntries int
	SnapshotTimeout        time.Duration
	// WaitForCapture queues threshold captures behind the current scan.
	WaitForCapture bool
}

// Result carries runtime data without event or container metadata.
type Result struct {
	Process           memsnapshot.ProcessInstanceID `json:"Process"`
	Language          memsnapshot.Language          `json:"Language"`
	SnapshotStartedAt time.Time                     `json:"SnapshotStartedAt"`
	Snapshot          *memsnapshot.Snapshot         `json:"Snapshot"`
	ProcessMemory     *memsnapshot.ProcessMemory    `json:"ProcessMemory"`
}

// Snapshot binds memory collection to an already selected process instance.
// Callers must validate the process instance before calling Snapshot.
// Detection and provider failures become failed snapshots, retaining process memory.
// Output-processing failures, cancellation and invalid options return no result.
func Snapshot(ctx context.Context, process memsnapshot.ProcessInstanceID,
	options Options,
) (*Result, error) {
	options.setDefaults()
	if err := options.validate(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if worker := configuredWorker.Load(); worker != nil {
		if worker.err != nil {
			return failedWorkerResult(process, time.Now().UTC(), worker.err), nil
		}
		return worker.manager.Snapshot(ctx, process, options)
	}
	if err := acquireCapture(ctx, options); err != nil {
		return nil, err
	}
	defer func() { <-captureSlot }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return snapshotLocal(ctx, process, options, uint64(time.Now().UnixNano()))
}

func snapshotLocal(ctx context.Context, process memsnapshot.ProcessInstanceID, options Options, seed uint64) (*Result, error) {
	pid := process.TGID
	snapshotStartedAt := time.Now().UTC()

	language, detectionErr := memsnapshot.DetectLanguage(pid)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var snapshot *memsnapshot.Snapshot
	if detectionErr != nil {
		if err := memsnapshot.ValidateProcessInstanceID(process); err != nil {
			return nil, fmt.Errorf("detect process runtime: %w; validate process: %w", detectionErr, err)
		}
		language = memsnapshot.LanguageUnknown
		snapshot = memsnapshot.Failed("detect process runtime: " + detectionErr.Error())
	} else {
		snapshotCtx, cancelSnapshot := context.WithTimeout(ctx, options.SnapshotTimeout)
		snapshot = snapshotProviderSeed(snapshotCtx, newProvider(language), process, options.MaxMemoryObjectEntries, seed)
		cancelSnapshot()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := memsnapshot.LimitOutput(snapshot, options.MaxMemoryObjectEntries); err != nil {
		return nil, fmt.Errorf("limit runtime snapshot output: %w", err)
	}
	if err := memsnapshot.ValidateProcessInstanceID(process); err != nil {
		return nil, err
	}
	return &Result{
		Process:           process,
		Language:          language,
		SnapshotStartedAt: snapshotStartedAt,
		Snapshot:          snapshot,
		ProcessMemory:     readProcessMemory(pid),
	}, nil
}

func acquireCapture(ctx context.Context, options Options) error {
	if !options.WaitForCapture {
		select {
		case captureSlot <- struct{}{}:
			return nil
		default:
			return ErrCaptureBusy
		}
	}
	waitCtx, cancel := context.WithTimeout(ctx, options.SnapshotTimeout)
	defer cancel()
	select {
	case captureSlot <- struct{}{}:
		return nil
	case <-waitCtx.Done():
		if err := ctx.Err(); err != nil {
			return err
		}
		return fmt.Errorf("%w: wait budget exceeded", ErrCaptureBusy)
	}
}
