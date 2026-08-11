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
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeIdentityReader struct {
	identity ProcessIdentity
	reads    int
}

func (f *fakeIdentityReader) Read(int) (ProcessIdentity, error) {
	f.reads++
	return f.identity, nil
}

type fakeClock struct {
	mu   sync.Mutex
	now  time.Time
	mono uint64
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) MonotonicNS() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mono++
	return f.mono
}

type fakeProvider struct {
	block      chan struct{}
	panicValue any
	result     *Result
	err        error
	captures   int
}

func (*fakeProvider) Language() Language { return LanguageGo }

//nolint:gocritic // The fake implements the production value-oriented Provider contract.
func (p *fakeProvider) Capture(ctx context.Context, _ Request) (*Result, error) {
	p.captures++
	if p.panicValue != nil {
		panic(p.panicValue)
	}
	if p.block != nil {
		select {
		case <-p.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if p.result != nil || p.err != nil {
		return p.result, p.err
	}
	return &Result{Manifest: Manifest{
		Status: StatusComplete,
		Coverage: Coverage{
			Consistency: "runtime", SizeSemantics: "sampled",
			KnownGaps: []string{"native"},
		},
	}}, nil
}

func newCoordinatorForTest(t *testing.T, provider Provider) (*Coordinator, Request) {
	t.Helper()
	identity := ProcessIdentity{TGID: 42, StartTimeTicks: 7, BootID: "boot"}
	registry := NewRegistry()
	if err := registry.Register(provider); err != nil {
		t.Fatal(err)
	}
	clock := &fakeClock{now: time.Now().UTC()}
	coordinator, err := NewCoordinator(registry,
		&fakeIdentityReader{identity: identity}, clock, 1)
	if err != nil {
		t.Fatal(err)
	}
	request := Request{
		SnapshotID: "snapshot", OOMRequestCookie: 1,
		Identity: identity, Trigger: TriggerOOMVictim,
		GateDeadline: clock.now.Add(time.Second), MaxOutputBytes: 1024,
		MaxObjects: 10, MaxStacks: 10, MaxStackDepth: 10,
	}
	return coordinator, request
}

func captureForTest(coordinator *Coordinator, request Request) *Result {
	return coordinator.Finalize(coordinator.Prepare(context.Background(),
		LanguageGo, request))
}

func TestCoordinatorCapture(t *testing.T) {
	coordinator, request := newCoordinatorForTest(t, &fakeProvider{})
	result := captureForTest(coordinator, request)
	if result.Manifest.Status != StatusComplete {
		t.Fatalf("status=%s", result.Manifest.Status)
	}
	if result.Manifest.Identity != request.Identity {
		t.Fatal("identity was not normalized")
	}
}

func TestCoordinatorPrepareVerifiedSkipsOnlyInitialIdentityRead(t *testing.T) {
	provider := &fakeProvider{}
	coordinator, request := newCoordinatorForTest(t, provider)
	reader := coordinator.identities.(*fakeIdentityReader)
	prepared := coordinator.PrepareVerified(context.Background(),
		LanguageGo, request)
	if prepared.Status() != StatusComplete {
		t.Fatalf("status=%s", prepared.Status())
	}
	if reader.reads != 1 {
		t.Fatalf("identity reads=%d, want final check only", reader.reads)
	}
	result := coordinator.Finalize(prepared)
	if result == nil || reader.reads != 1 || provider.captures != 1 {
		t.Fatalf("finalize accessed victim: result=%p identity_reads=%d captures=%d",
			result, reader.reads, provider.captures)
	}
}

func TestCoordinatorPreservesPrefixReturnedAtDeadline(t *testing.T) {
	provider := &fakeProvider{
		result: &Result{
			Manifest: Manifest{Status: StatusComplete, Coverage: Coverage{
				Consistency: "bounded", SizeSemantics: "sampled",
				KnownGaps: []string{"deadline"},
			}},
			Objects: []ObjectAggregate{{
				TypeName: "service.Payload", Count: 7, ShallowBytes: 896,
			}},
		},
		err: context.DeadlineExceeded,
	}
	coordinator, request := newCoordinatorForTest(t, provider)
	result := captureForTest(coordinator, request)
	if result.Manifest.Status != StatusPartialDeadline ||
		!result.Manifest.Truncated || len(result.Objects) != 1 {
		t.Fatalf("status=%s truncated=%v objects=%d",
			result.Manifest.Status, result.Manifest.Truncated, len(result.Objects))
	}
}

func TestCoordinatorRejectsSameVictimConcurrentCapture(t *testing.T) {
	block := make(chan struct{})
	coordinator, request := newCoordinatorForTest(t, &fakeProvider{block: block})
	done := make(chan *Result, 1)
	go func() { done <- captureForTest(coordinator, request) }()
	for i := 0; i < 100; i++ {
		coordinator.mu.Lock()
		claimed := len(coordinator.inFlight) == 1
		coordinator.mu.Unlock()
		if claimed {
			break
		}
		time.Sleep(time.Millisecond)
	}
	second := request
	second.SnapshotID = "second"
	second.OOMRequestCookie = 2
	result := captureForTest(coordinator, second)
	if result.Manifest.Status != StatusRuntimeBusy {
		t.Fatalf("status=%s", result.Manifest.Status)
	}
	close(block)
	<-done
}

func TestCoordinatorConvertsProviderPanic(t *testing.T) {
	coordinator, request := newCoordinatorForTest(t, &fakeProvider{panicValue: "boom"})
	result := captureForTest(coordinator, request)
	if result.Manifest.Status != StatusCaptureFailed {
		t.Fatalf("status=%s", result.Manifest.Status)
	}
}

func TestCoordinatorRecoversFinalizePanic(t *testing.T) {
	provider := &resultProvider{result: &Result{
		Manifest: Manifest{Status: StatusComplete, Coverage: Coverage{
			Consistency: "runtime", SizeSemantics: "shallow",
			KnownGaps: []string{"native"},
		}},
		FinalizeLocal: func() error { panic("finalize boom") },
	}}
	coordinator, request := newCoordinatorForTest(t, provider)
	result := captureForTest(coordinator, request)
	if result.Manifest.Status != StatusCaptureFailed {
		t.Fatalf("status=%s, want %s", result.Manifest.Status, StatusCaptureFailed)
	}
}

func TestCoordinatorEnforcesResultLimits(t *testing.T) {
	provider := &resultProvider{result: &Result{
		Manifest: Manifest{Status: StatusComplete, Coverage: Coverage{
			Consistency: "runtime", SizeSemantics: "shallow",
			KnownGaps: []string{"native"},
		}},
		Objects: []ObjectAggregate{{TypeName: "a"}, {TypeName: "b"}},
	}}
	coordinator, request := newCoordinatorForTest(t, provider)
	request.MaxObjects = 1
	result := captureForTest(coordinator, request)
	if result.Manifest.Status != StatusPartialObjectLimit || len(result.Objects) != 1 {
		t.Fatalf("status=%s objects=%d", result.Manifest.Status, len(result.Objects))
	}
}

func TestCoordinatorCurrentSchemaCannotBypassLimits(t *testing.T) {
	provider := &resultProvider{result: &Result{
		Manifest: Manifest{SchemaVersion: SchemaVersion, Status: StatusComplete,
			Coverage: Coverage{Consistency: "runtime", SizeSemantics: "shallow",
				KnownGaps: []string{"native"}}},
		Objects: []ObjectAggregate{{TypeName: "a"}, {TypeName: "b"}},
	}}
	coordinator, request := newCoordinatorForTest(t, provider)
	request.MaxObjects = 1
	result := captureForTest(coordinator, request)
	if result.Manifest.Status != StatusPartialObjectLimit || len(result.Objects) != 1 {
		t.Fatalf("status=%s objects=%d", result.Manifest.Status, len(result.Objects))
	}
}

func TestCoordinatorLocalFinalizeRunsOnce(t *testing.T) {
	finalizes := 0
	provider := &resultProvider{result: &Result{
		Manifest: Manifest{Status: StatusComplete, Coverage: Coverage{
			Consistency: "runtime", SizeSemantics: "shallow",
			KnownGaps: []string{"native"},
		}},
		FinalizeLocal: func() error {
			finalizes++
			return nil
		},
	}}
	coordinator, request := newCoordinatorForTest(t, provider)
	prepared := coordinator.Prepare(context.Background(), LanguageGo,
		request)
	first := coordinator.Finalize(prepared)
	second := coordinator.Finalize(prepared)
	if finalizes != 1 || first != second {
		t.Fatalf("finalizes=%d first=%p second=%p", finalizes, first, second)
	}
}

func TestCoordinatorInvalidResultFinalizationIsIdempotent(t *testing.T) {
	provider := &resultProvider{result: &Result{Manifest: Manifest{
		Status: StatusComplete, Coverage: Coverage{},
	}}}
	coordinator, request := newCoordinatorForTest(t, provider)
	prepared := coordinator.Prepare(context.Background(), LanguageGo,
		request)
	first := coordinator.Finalize(prepared)
	second := coordinator.Finalize(prepared)
	if first != second || first.Manifest.Status != StatusCaptureFailed {
		t.Fatalf("first=%p second=%p status=%s", first, second,
			first.Manifest.Status)
	}
}

func TestCoordinatorOutputLimitRetainsUsefulPrefix(t *testing.T) {
	objects := make([]ObjectAggregate, 20)
	for i := range objects {
		objects[i] = ObjectAggregate{
			TypeName: strings.Repeat("class", 32),
			Count:    uint64(20 - i), ShallowBytes: uint64((20 - i) * 1024),
		}
	}
	provider := &resultProvider{result: &Result{
		Manifest: Manifest{Status: StatusComplete, Coverage: Coverage{
			Consistency: "runtime", SizeSemantics: "shallow",
			KnownGaps: []string{"native"},
		}},
		Objects: objects,
	}}
	coordinator, request := newCoordinatorForTest(t, provider)
	request.MaxOutputBytes = 1800
	request.MaxObjects = len(objects)
	result := captureForTest(coordinator, request)
	if result.Manifest.Status != StatusPartialOutputLimit ||
		len(result.Objects) == 0 || len(result.Objects) >= len(objects) {
		t.Fatalf("status=%s objects=%d", result.Manifest.Status,
			len(result.Objects))
	}
	if result.Manifest.PayloadBytes > request.MaxOutputBytes {
		t.Fatalf("payload=%d limit=%d", result.Manifest.PayloadBytes,
			request.MaxOutputBytes)
	}
	raw, err := json.Marshal(RuntimePayloadFromResult(result))
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(raw)) != result.Manifest.PayloadBytes {
		t.Fatalf("encoded payload=%d manifest payload=%d", len(raw),
			result.Manifest.PayloadBytes)
	}
	if strings.Contains(string(raw), `"objects":`) ||
		strings.Contains(string(raw), `"allocations":`) {
		t.Fatalf("payload uses legacy arrays: %s", raw)
	}
}

type resultProvider struct{ result *Result }

func (*resultProvider) Language() Language { return LanguageGo }
func (p *resultProvider) Capture(context.Context, Request) (*Result, error) {
	return p.result, nil
}
