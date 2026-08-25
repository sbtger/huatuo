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

package capturehelper

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"huatuo-bamai/internal/memsnap"
)

type providerFunc func(context.Context, memsnap.Request) (*memsnap.Snapshot, error)

func (f providerFunc) Capture(ctx context.Context,
	request memsnap.Request,
) (*memsnap.Snapshot, error) {
	return f(ctx, request)
}

func replaceProvider(t *testing.T, language memsnap.Language,
	factory ProviderFactory,
) {
	t.Helper()
	previous, hadPrevious := providerFactories.Load(language)
	providerFactories.Store(language, factory)
	t.Cleanup(func() {
		if hadPrevious {
			providerFactories.Store(language, previous)
		} else {
			providerFactories.Delete(language)
		}
	})
}

func TestCaptureCallsProviderDirectly(t *testing.T) {
	request := memsnap.Request{TopK: 2, SamplingSeed: 7}
	replaceProvider(t, memsnap.LanguageGo, func() memsnap.Provider {
		return providerFunc(func(ctx context.Context,
			got memsnap.Request,
		) (*memsnap.Snapshot, error) {
			if got != request {
				t.Fatalf("request = %+v, want %+v", got, request)
			}
			if _, ok := ctx.Deadline(); !ok {
				t.Fatal("provider context has no deadline")
			}
			return &memsnap.Snapshot{
				Status: memsnap.StatusComplete,
				Entries: []memsnap.Entry{
					{Name: "first"}, {Name: "second"}, {Name: "third"},
				},
			}, nil
		})
	})

	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	snapshot, err := Capture(ctx, memsnap.LanguageGo, request)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Entries) != 3 || snapshot.OutputTruncated ||
		snapshot.Entries[2].Name != "third" {
		t.Fatalf("snapshot = %+v", snapshot)
	}
}

func TestCaptureReturnsCooperativeTimeout(t *testing.T) {
	replaceProvider(t, memsnap.LanguageGo, func() memsnap.Provider {
		return providerFunc(func(ctx context.Context,
			_ memsnap.Request,
		) (*memsnap.Snapshot, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		})
	})

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	_, err := Capture(ctx, memsnap.LanguageGo, memsnap.Request{TopK: 1})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Capture() error = %v, want deadline exceeded", err)
	}
}

func TestCaptureRejectsResultReturnedAfterDeadline(t *testing.T) {
	replaceProvider(t, memsnap.LanguageGo, func() memsnap.Provider {
		return providerFunc(func(ctx context.Context,
			_ memsnap.Request,
		) (*memsnap.Snapshot, error) {
			<-ctx.Done()
			return &memsnap.Snapshot{Status: memsnap.StatusComplete}, nil
		})
	})

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	_, err := Capture(ctx, memsnap.LanguageGo, memsnap.Request{TopK: 1})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Capture() error = %v, want deadline exceeded", err)
	}
}

func TestCaptureRecoversProviderPanic(t *testing.T) {
	replaceProvider(t, memsnap.LanguageGo, func() memsnap.Provider {
		return providerFunc(func(context.Context,
			memsnap.Request,
		) (*memsnap.Snapshot, error) {
			panic("broken reader")
		})
	})

	_, err := Capture(t.Context(), memsnap.LanguageGo, memsnap.Request{TopK: 1})
	if err == nil || !strings.Contains(err.Error(), "broken reader") {
		t.Fatalf("Capture() error = %v, want recovered panic", err)
	}
}

func TestCaptureBuildsFreshProvider(t *testing.T) {
	var builds atomic.Int32
	replaceProvider(t, memsnap.LanguageGo, func() memsnap.Provider {
		builds.Add(1)
		return providerFunc(func(context.Context,
			memsnap.Request,
		) (*memsnap.Snapshot, error) {
			return &memsnap.Snapshot{Status: memsnap.StatusComplete}, nil
		})
	})

	for range 2 {
		if _, err := Capture(t.Context(), memsnap.LanguageGo,
			memsnap.Request{TopK: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if got := builds.Load(); got != 2 {
		t.Fatalf("provider builds = %d, want 2", got)
	}
}

func TestCaptureRejectsNilSnapshot(t *testing.T) {
	replaceProvider(t, memsnap.LanguageGo, func() memsnap.Provider {
		return providerFunc(func(context.Context,
			memsnap.Request,
		) (*memsnap.Snapshot, error) {
			return nil, nil
		})
	})

	if _, err := Capture(t.Context(), memsnap.LanguageGo,
		memsnap.Request{TopK: 1}); err == nil {
		t.Fatal("Capture() error = nil, want nil snapshot error")
	}
}

func TestCaptureSkipsUnsupportedRuntime(t *testing.T) {
	snapshot, err := Capture(t.Context(), memsnap.LanguageUnknown,
		memsnap.Request{})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != memsnap.StatusUnavailable {
		t.Fatalf("status = %q, want unavailable", snapshot.Status)
	}
}

func TestCaptureRejectsUnboundedTopK(t *testing.T) {
	replaceProvider(t, memsnap.LanguageGo, func() memsnap.Provider {
		return providerFunc(func(context.Context,
			memsnap.Request,
		) (*memsnap.Snapshot, error) {
			t.Fatal("provider called with unbounded top-K")
			return nil, nil
		})
	})

	_, err := Capture(t.Context(), memsnap.LanguageGo,
		memsnap.Request{TopK: memsnap.MaxTopK + 1})
	if err == nil || !strings.Contains(err.Error(), "top-K") {
		t.Fatalf("Capture() error = %v, want top-K bound error", err)
	}
}
