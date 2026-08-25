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

// Package capturehelper dispatches bounded runtime memory captures.
package capturehelper

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"huatuo-bamai/internal/memsnap"
)

// ProviderFactory constructs a runtime snapshot provider on demand.
type ProviderFactory func() memsnap.Provider

var providerFactories sync.Map

// RegisterProvider makes a runtime provider available to Capture. Callers
// register factories during package initialization.
func RegisterProvider(language memsnap.Language, factory ProviderFactory) {
	if language == memsnap.LanguageUnknown || factory == nil {
		panic("capturehelper: invalid provider registration")
	}
	if _, loaded := providerFactories.LoadOrStore(language, factory); loaded {
		panic(fmt.Sprintf("capturehelper: provider already registered for %s", language))
	}
}

func providerFor(language memsnap.Language) memsnap.Provider {
	factory, ok := providerFactories.Load(language)
	if !ok {
		return nil
	}
	return factory.(ProviderFactory)()
}

// Capture runs one provider synchronously. Providers bound individual reads and
// check the context before and after each syscall. The timeout is a cooperative
// stop budget, not a wall-clock upper bound: context cancellation cannot preempt
// a synchronous syscall already in progress, and that syscall may block without
// a time bound. Once it returns, the expired budget prevents later reads. This
// accepted limitation avoids requiring a separately managed helper process only
// to enforce a hard per-syscall deadline.
func Capture(ctx context.Context, language memsnap.Language,
	request memsnap.Request,
) (snapshot *memsnap.Snapshot, err error) {
	if _, registered := providerFactories.Load(language); !registered {
		return memsnap.Unavailable("runtime is not supported"), nil
	}
	if request.TopK <= 0 || request.TopK > memsnap.MaxTopK {
		return nil, fmt.Errorf("runtime capture top-K must be in [1, %d], got %d",
			memsnap.MaxTopK, request.TopK)
	}

	defer func() {
		if recovered := recover(); recovered != nil {
			snapshot = nil
			err = fmt.Errorf("runtime capture panic: %v", recovered)
		}
	}()

	snapshot, err = providerFor(language).Capture(ctx, request)
	if err != nil {
		return nil, err
	}
	if captureErr := ctx.Err(); captureErr != nil {
		return nil, fmt.Errorf("runtime capture terminated: %w", captureErr)
	}
	if snapshot == nil {
		return nil, errors.New("runtime capture returned no snapshot")
	}
	return snapshot, nil
}
