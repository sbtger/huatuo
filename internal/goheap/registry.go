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

// Package goheap discovers and tracks Go processes whose runtime heap metadata
// can be captured before an OOM victim exits.
package goheap

import (
	"context"
	"sort"
	"sync"
)

// DefaultMaxTargets bounds the number of processes registered for heap capture.
const DefaultMaxTargets = 4096

// Identity distinguishes a process from a later process that reuses its PID.
type Identity struct {
	PID            uint32
	StartTimeTicks uint64
}

// Target describes a profileable Go process.
type Target struct {
	Identity
	GoVersion     string
	Executable    string
	BuildID       string
	ExecutableKey string
	SymbolAddress uint64
	LoadBias      uint64
}

// MBucketsAddress returns the runtime address of runtime.mbuckets.
func (t Target) MBucketsAddress() uint64 {
	return t.SymbolAddress + t.LoadBias
}

// Discoverer returns the currently profileable Go processes.
type Discoverer interface {
	Discover(context.Context) ([]Target, error)
}

// Changes is the result of one full registry reconciliation.
type Changes struct {
	Added   []Target
	Updated []Target
	Removed []Target
	Dropped int
}

// Registry maintains a bounded, PID-reuse-safe snapshot of Go targets.
type Registry struct {
	discoverer Discoverer
	maxTargets int

	reconcileMu sync.Mutex
	mu          sync.RWMutex
	targets     map[uint32]Target
}

// NewRegistry constructs a registry. Non-positive maxTargets uses the default.
func NewRegistry(discoverer Discoverer, maxTargets int) *Registry {
	if maxTargets <= 0 {
		maxTargets = DefaultMaxTargets
	}
	return &Registry{
		discoverer: discoverer,
		maxTargets: maxTargets,
		targets:    make(map[uint32]Target),
	}
}

// Reconcile performs a full scan and returns the delta from the last snapshot.
func (r *Registry) Reconcile(ctx context.Context) (Changes, error) {
	r.reconcileMu.Lock()
	defer r.reconcileMu.Unlock()

	discovered, err := r.discoverer.Discover(ctx)
	if err != nil {
		return Changes{}, err
	}

	candidates := make(map[uint32]Target, len(discovered))
	for _, target := range discovered {
		if validTarget(target) {
			candidates[target.PID] = target
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	changes := Changes{}
	next := make(map[uint32]Target, min(len(candidates), r.maxTargets))

	// Keep valid existing entries first to avoid map churn at the capacity limit.
	for _, pid := range sortedTargetPIDs(r.targets) {
		oldTarget := r.targets[pid]
		newTarget, ok := candidates[pid]
		if !ok || oldTarget.Identity != newTarget.Identity {
			changes.Removed = append(changes.Removed, oldTarget)
			continue
		}
		if oldTarget != newTarget {
			changes.Updated = append(changes.Updated, newTarget)
		}
		next[pid] = newTarget
		delete(candidates, pid)
	}

	for _, pid := range sortedTargetPIDs(candidates) {
		if len(next) == r.maxTargets {
			break
		}
		target := candidates[pid]
		next[pid] = target
		changes.Added = append(changes.Added, target)
	}

	changes.Dropped = len(candidates) - len(changes.Added)
	r.targets = next
	return changes, nil
}

// Snapshot returns a stable PID-ordered copy of the current targets.
func (r *Registry) Snapshot() []Target {
	r.mu.RLock()
	defer r.mu.RUnlock()

	targets := make([]Target, 0, len(r.targets))
	for _, target := range r.targets {
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool {
		return targets[i].PID < targets[j].PID
	})
	return targets
}

func validTarget(target Target) bool {
	return target.PID != 0 && target.StartTimeTicks != 0 && target.SymbolAddress != 0
}

func sortedTargetPIDs(targets map[uint32]Target) []uint32 {
	pids := make([]uint32, 0, len(targets))
	for pid := range targets {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	return pids
}
