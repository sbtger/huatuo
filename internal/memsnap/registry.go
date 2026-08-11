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
	"fmt"
	"sync"
)

type Registry struct {
	mu        sync.RWMutex
	providers map[Language]Provider
}

func NewRegistry() *Registry {
	return &Registry{providers: make(map[Language]Provider)}
}

func (r *Registry) Register(provider Provider) error {
	if provider == nil {
		return fmt.Errorf("register nil snapshot provider")
	}
	language := provider.Language()
	if language == LanguageUnknown {
		return fmt.Errorf("register provider with unknown language")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.providers[language]; exists {
		return fmt.Errorf("snapshot provider for %s already registered", language)
	}
	r.providers[language] = provider
	return nil
}

func (r *Registry) Provider(language Language) (Provider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	provider, ok := r.providers[language]
	return provider, ok
}
