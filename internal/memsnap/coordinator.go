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

package memsnap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

type Coordinator struct {
	registry   *Registry
	identities IdentityReader
	clock      Clock
	semaphore  chan struct{}
	mu         sync.Mutex
	inFlight   map[ProcessIdentity]struct{}
}

// PreparedCapture contains only data already copied out of the victim. Finalize
// performs local normalization, sorting/limits and JSON sizing and must never
// access the victim process. This boundary lets the OOM gate ACK immediately
// after the final identity check.
type PreparedCapture struct {
	result                     *Result
	request                    Request
	language                   Language
	startedWall, completedWall time.Time
	startedMono, completedMono uint64
	finalized                  bool
}

func (p *PreparedCapture) Status() CompletionStatus {
	if p == nil || p.result == nil {
		return StatusCaptureFailed
	}
	return p.result.Manifest.Status
}

func NewCoordinator(registry *Registry, identities IdentityReader, clock Clock,
	maxConcurrent int,
) (*Coordinator, error) {
	if registry == nil || identities == nil || clock == nil {
		return nil, errors.New("registry, identity reader, and clock are required")
	}
	if maxConcurrent <= 0 {
		return nil, errors.New("maximum concurrency must be greater than zero")
	}
	return &Coordinator{
		registry: registry, identities: identities, clock: clock,
		semaphore: make(chan struct{}, maxConcurrent),
		inFlight:  make(map[ProcessIdentity]struct{}),
	}, nil
}

// PrepareVerified is the OOM fast path for a request whose identity was read
// immediately before this call. It omits only the redundant pre-capture check;
// the final check after the provider has copied victim memory is unchanged.
//
//nolint:gocritic // Requests are immutable value snapshots across capture stages.
func (c *Coordinator) PrepareVerified(ctx context.Context,
	language Language, request Request,
) *PreparedCapture {
	return c.prepare(ctx, language, request, false)
}

// Prepare performs every operation that can access the victim, including the
// final PID/start-time identity check. The returned value is safe to finalize
// after the OOM gate has released the victim.
//
//nolint:gocritic // Requests are immutable value snapshots across capture stages.
func (c *Coordinator) Prepare(ctx context.Context, language Language,
	request Request,
) *PreparedCapture {
	return c.prepare(ctx, language, request, true)
}

//nolint:gocritic // Requests are immutable value snapshots across capture stages.
func (c *Coordinator) prepare(ctx context.Context, language Language,
	request Request, checkBeforeCapture bool,
) *PreparedCapture {
	if err := request.Validate(c.clock.Now()); err != nil {
		return c.preparedFailure(request, language, StatusIdentityUnavailable, err.Error())
	}
	provider, ok := c.registry.Provider(language)
	if !ok {
		return c.preparedFailure(request, language, StatusProviderUnavailable,
			"no provider registered for victim runtime")
	}
	if !c.claim(request.Identity) {
		return c.preparedFailure(request, language, StatusRuntimeBusy,
			"snapshot already in flight for victim")
	}
	defer c.release(request.Identity)

	select {
	case c.semaphore <- struct{}{}:
		defer func() { <-c.semaphore }()
	default:
		return c.preparedFailure(request, language, StatusRuntimeBusy,
			"global snapshot concurrency limit reached")
	}

	if checkBeforeCapture {
		actual, err := c.identities.Read(request.Identity.TGID)
		if err != nil || actual != request.Identity {
			return c.preparedFailure(request, language, StatusIdentityUnavailable,
				"victim identity changed before capture")
		}
	}

	captureCtx, cancel := context.WithDeadline(ctx, request.GateDeadline)
	defer cancel()
	startedWall := c.clock.Now()
	startedMono := c.clock.MonotonicNS()
	result, captureErr := callProvider(captureCtx, provider, request)
	completedMono := c.clock.MonotonicNS()
	completedWall := c.clock.Now()
	if result != nil && errors.Is(captureErr, context.DeadlineExceeded) {
		// A provider may reach its final deadline check after it has copied a
		// useful prefix out of the victim. Preserve that owned data and describe
		// it as partial instead of replacing it with a terminal gate failure.
		markPartial(&result.Manifest, StatusPartialDeadline,
			"gate deadline reached after a useful capture prefix was copied")
		captureErr = nil
	}
	if captureErr != nil || result == nil {
		status := StatusCaptureFailed
		if errors.Is(captureErr, context.DeadlineExceeded) || captureCtx.Err() != nil {
			status = StatusGateTimeout
		}
		return c.preparedFailureAt(request, language, status,
			fmt.Sprintf("runtime capture failed: %v", captureErr),
			startedWall, completedWall, startedMono, completedMono)
	}

	actual, err := c.identities.Read(request.Identity.TGID)
	if err != nil || actual != request.Identity {
		return c.preparedFailureAt(request, language, StatusProcessExited,
			"victim identity changed during capture", startedWall,
			completedWall, startedMono, completedMono)
	}
	return &PreparedCapture{result: result, request: request, language: language,
		startedWall: startedWall, completedWall: completedWall,
		startedMono: startedMono, completedMono: completedMono}
}

// Finalize only consumes memory owned by Huatuo. It is safe to call after ACK.
func (c *Coordinator) Finalize(prepared *PreparedCapture) (ret *Result) {
	if prepared == nil || prepared.result == nil {
		return nil
	}
	// Capture panics are recovered by callProvider; finalize panics run outside
	// that boundary and must not crash the daemon on a single bad snapshot.
	defer func() {
		if recovered := recover(); recovered != nil {
			prepared.result = TerminalResult(prepared.request, prepared.language,
				StatusCaptureFailed,
				fmt.Sprintf("snapshot finalize panic: %v", recovered),
				prepared.startedWall, prepared.completedWall,
				prepared.startedMono, prepared.completedMono)
			prepared.finalized = true
			ret = prepared.result
		}
	}()
	if prepared.finalized {
		return prepared.result
	}
	result := prepared.result
	if result.FinalizeLocal != nil {
		finalize := result.FinalizeLocal
		result.FinalizeLocal = nil
		if err := finalize(); err != nil {
			prepared.result = TerminalResult(prepared.request, prepared.language,
				StatusCaptureFailed, fmt.Sprintf("provider local finalize failed: %v", err),
				prepared.startedWall, prepared.completedWall,
				prepared.startedMono, prepared.completedMono)
			prepared.finalized = true
			return prepared.result
		}
	}
	c.normalize(result, prepared.request, prepared.language, prepared.startedWall,
		prepared.completedWall, prepared.startedMono, prepared.completedMono)
	c.applyLimits(result, prepared.request)
	if err := result.Manifest.Validate(); err != nil {
		prepared.result = TerminalResult(prepared.request, prepared.language,
			StatusCaptureFailed,
			fmt.Sprintf("provider returned invalid manifest: %v", err),
			prepared.startedWall, prepared.completedWall,
			prepared.startedMono, prepared.completedMono)
		prepared.finalized = true
		return prepared.result
	}
	prepared.finalized = true
	return result
}

func (c *Coordinator) preparedFailure(request Request, language Language,
	status CompletionStatus, reason string,
) *PreparedCapture {
	now := c.clock.Now()
	mono := c.clock.MonotonicNS()
	return c.preparedFailureAt(request, language, status, reason,
		now, now, mono, mono)
}

func (c *Coordinator) preparedFailureAt(request Request,
	language Language, status CompletionStatus, reason string,
	startedWall, completedWall time.Time, startedMono, completedMono uint64,
) *PreparedCapture {
	return &PreparedCapture{result: TerminalResult(request, language, status, reason,
		startedWall, completedWall, startedMono, completedMono), request: request,
		language: language, startedWall: startedWall, completedWall: completedWall,
		startedMono: startedMono, completedMono: completedMono, finalized: true}
}

//nolint:gocritic // Passing a request copy prevents providers from mutating coordinator state.
func callProvider(ctx context.Context, provider Provider,
	request Request,
) (result *Result, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("provider panic: %v", recovered)
		}
	}()
	return provider.Capture(ctx, request)
}

//nolint:gocritic // Normalization consumes an immutable request snapshot.
func (c *Coordinator) normalize(result *Result, request Request,
	language Language, startedWall,
	completedWall time.Time, startedMono, completedMono uint64,
) {
	manifest := &result.Manifest
	manifest.SchemaVersion = SchemaVersion
	manifest.SnapshotID = request.SnapshotID
	manifest.OOMRequestCookie = request.OOMRequestCookie
	manifest.OOMMonotonicNS = request.OOMMonotonicNS
	manifest.GateDeadlineMonotonicNS = request.GateDeadlineMonotonicNS
	manifest.Identity = request.Identity
	manifest.Language = language
	manifest.Scope = ScopeRuntimeManagedHeap
	manifest.Mode = ModeFast
	manifest.Trigger = TriggerOOMVictim
	manifest.CaptureStartedWallTime = startedWall
	manifest.CaptureCompletedWallTime = completedWall
	manifest.CaptureStartedMonotonicNS = startedMono
	manifest.CaptureCompletedMonotonicNS = completedMono
	c.updatePayloadCounts(result)
}

//nolint:gocritic // Limit enforcement consumes an immutable request snapshot.
func (c *Coordinator) applyLimits(result *Result, request Request) {
	if len(result.Objects) > request.MaxObjects {
		result.Objects = result.Objects[:request.MaxObjects]
		markPartial(&result.Manifest, StatusPartialObjectLimit,
			"object aggregate limit reached")
	}
	if len(result.Allocations) > request.MaxStacks {
		result.Allocations = result.Allocations[:request.MaxStacks]
		markPartial(&result.Manifest, StatusPartialRecordLimit,
			"allocation stack limit reached")
	}
	c.updatePayloadCounts(result)
	if result.Manifest.PayloadBytes <= request.MaxOutputBytes {
		return
	}
	markPartial(&result.Manifest, StatusPartialOutputLimit,
		"payload exceeded output byte limit")
	c.retainStructuredPrefix(result, request.MaxOutputBytes)
}

// retainStructuredPrefix keeps the largest prefix that fits. Providers sort
// their aggregates by importance, so this preserves the most useful classes
// or allocation stacks instead of dropping the entire result at the limit.
func (c *Coordinator) retainStructuredPrefix(result *Result, maxBytes int64) {
	objects := result.Objects
	allocations := result.Allocations
	total := len(objects) + len(allocations)
	best := 0
	for low, high := 0, total; low <= high; {
		keep := low + (high-low)/2
		objectCount := min(keep, len(objects))
		allocationCount := min(max(keep-len(objects), 0), len(allocations))
		result.Objects = objects[:objectCount]
		result.Allocations = allocations[:allocationCount]
		c.updatePayloadCounts(result)
		if result.Manifest.PayloadBytes <= maxBytes {
			best = keep
			low = keep + 1
		} else {
			high = keep - 1
		}
	}
	objectCount := min(best, len(objects))
	allocationCount := min(max(best-len(objects), 0), len(allocations))
	result.Objects = objects[:objectCount]
	result.Allocations = allocations[:allocationCount]
	c.updatePayloadCounts(result)
}

func (c *Coordinator) updatePayloadCounts(result *Result) {
	result.Manifest.ObjectCount = len(result.Objects)
	result.Manifest.StackCount = len(result.Allocations)
	result.Manifest.EntryCount = result.Manifest.ObjectCount +
		result.Manifest.StackCount
	// PayloadBytes is itself encoded inside the payload, so its own string
	// length feeds back into the encoded size. Iterate to the fixed point; four
	// passes cover any realistic digit-count change and bound the work.
	for attempt := 0; attempt < 4; attempt++ {
		raw, err := json.Marshal(RuntimePayloadFromResult(result))
		if err != nil {
			return
		}
		payloadBytes := int64(len(raw))
		if payloadBytes == result.Manifest.PayloadBytes {
			return
		}
		result.Manifest.PayloadBytes = payloadBytes
	}
}

func markPartial(manifest *Manifest, status CompletionStatus, reason string) {
	if !manifest.Status.IsPartial() {
		manifest.Status = status
	}
	manifest.Truncated = true
	for _, existing := range manifest.TruncationReasons {
		if existing == reason {
			return
		}
	}
	manifest.TruncationReasons = append(manifest.TruncationReasons, reason)
}

func (c *Coordinator) claim(identity ProcessIdentity) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.inFlight[identity]; exists {
		return false
	}
	c.inFlight[identity] = struct{}{}
	return true
}

func (c *Coordinator) release(identity ProcessIdentity) {
	c.mu.Lock()
	delete(c.inFlight, identity)
	c.mu.Unlock()
}

// TerminalResult builds the result for a snapshot that never captured victim
// memory (filtered, busy, cooldown, identity unavailable, or gate timeout). The
// language fallback keeps the manifest valid when the victim runtime is unknown.
//
//nolint:gocritic // Failure results retain the request values captured at admission.
func TerminalResult(request Request, language Language,
	status CompletionStatus, reason string, startedWall, completedWall time.Time,
	startedMono, completedMono uint64,
) *Result {
	if language == LanguageUnknown {
		language = Language("unavailable")
	}
	return &Result{Manifest: Manifest{
		SchemaVersion: SchemaVersion, SnapshotID: request.SnapshotID,
		OOMRequestCookie:        request.OOMRequestCookie,
		OOMMonotonicNS:          request.OOMMonotonicNS,
		GateDeadlineMonotonicNS: request.GateDeadlineMonotonicNS,
		Identity:                request.Identity,
		Language:                language, Scope: ScopeRuntimeManagedHeap, Mode: ModeFast,
		Trigger: TriggerOOMVictim, Status: status,
		Coverage: Coverage{
			Consistency: "not_captured", SizeSemantics: "unavailable",
			KnownGaps: []string{reason},
		},
		CaptureStartedWallTime:      startedWall,
		CaptureCompletedWallTime:    completedWall,
		CaptureStartedMonotonicNS:   startedMono,
		CaptureCompletedMonotonicNS: completedMono,
	}}
}
