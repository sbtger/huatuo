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

// Package javastack discovers Java processes and captures a bounded user stack
// when the kernel delivers an OOM SIGKILL to a registered victim.
package javastack

import (
	"context"
	"sort"
	"sync"
)

// DefaultMaxTargets bounds the number of JVMs registered in BPF.
const DefaultMaxTargets = 4096

// Identity distinguishes a process from a later process that reuses its PID.
type Identity struct {
	PID            uint32
	StartTimeTicks uint64
}

// Target describes a Java process eligible for OOM stack capture.
type Target struct {
	Identity
	Executable string
	Command    string
}

// Discoverer returns the currently eligible Java processes.
type Discoverer interface {
	Discover(ctx context.Context) ([]Target, error)
}

// Changes describes one full registry reconciliation.
type Changes struct {
	Added   []Target
	Updated []Target
	Removed []Target
	Dropped int
}

// Registry maintains a bounded, PID-reuse-safe target snapshot.
type Registry struct {
	discoverer Discoverer
	maxTargets int

	reconcileMu sync.Mutex
	mu          sync.RWMutex
	targets     map[uint32]Target
}

// NewRegistry constructs a Java target registry.
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

// Reconcile replaces the current snapshot after a complete discovery pass.
func (r *Registry) Reconcile(ctx context.Context) (Changes, error) {
	r.reconcileMu.Lock()
	defer r.reconcileMu.Unlock()

	discovered, err := r.discoverer.Discover(ctx)
	if err != nil {
		return Changes{}, err
	}
	candidates := make(map[uint32]Target, len(discovered))
	for _, target := range discovered {
		if target.PID != 0 && target.StartTimeTicks != 0 {
			candidates[target.PID] = target
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	changes := Changes{}
	next := make(map[uint32]Target, min(len(candidates), r.maxTargets))
	for _, pid := range sortedPIDs(r.targets) {
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
	for _, pid := range sortedPIDs(candidates) {
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
	sort.Slice(targets, func(i, j int) bool { return targets[i].PID < targets[j].PID })
	return targets
}

func sortedPIDs(targets map[uint32]Target) []uint32 {
	pids := make([]uint32, 0, len(targets))
	for pid := range targets {
		pids = append(pids, pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	return pids
}
