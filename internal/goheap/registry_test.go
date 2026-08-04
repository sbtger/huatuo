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

package goheap

import (
	"context"
	"testing"
)

type fakeDiscoverer struct {
	targets []Target
	err     error
}

func (d *fakeDiscoverer) Discover(context.Context) ([]Target, error) {
	return append([]Target(nil), d.targets...), d.err
}

func TestRegistryReconcileLifecycle(t *testing.T) {
	discoverer := &fakeDiscoverer{targets: []Target{
		newTestTarget(10, 100, 0x1000),
		newTestTarget(20, 200, 0x2000),
	}}
	registry := NewRegistry(discoverer, 10)

	changes, err := registry.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	if len(changes.Added) != 2 || len(changes.Removed) != 0 {
		t.Fatalf("first changes = %+v", changes)
	}

	updated := newTestTarget(10, 100, 0x3000)
	discoverer.targets = []Target{
		updated,
		newTestTarget(20, 201, 0x4000), // PID reuse.
	}
	changes, err = registry.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if len(changes.Updated) != 1 || changes.Updated[0] != updated {
		t.Fatalf("updated = %+v, want %+v", changes.Updated, updated)
	}
	if len(changes.Removed) != 1 || changes.Removed[0].StartTimeTicks != 200 {
		t.Fatalf("removed = %+v", changes.Removed)
	}
	if len(changes.Added) != 1 || changes.Added[0].StartTimeTicks != 201 {
		t.Fatalf("added = %+v", changes.Added)
	}
}

func TestRegistryCapacityRetainsExistingTargets(t *testing.T) {
	discoverer := &fakeDiscoverer{targets: []Target{
		newTestTarget(20, 20, 20),
		newTestTarget(30, 30, 30),
	}}
	registry := NewRegistry(discoverer, 2)
	if _, err := registry.Reconcile(context.Background()); err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}

	discoverer.targets = append(discoverer.targets, newTestTarget(10, 10, 10))
	changes, err := registry.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if changes.Dropped != 1 || len(changes.Added) != 0 {
		t.Fatalf("changes = %+v", changes)
	}
	if got := registry.Snapshot(); len(got) != 2 || got[0].PID != 20 || got[1].PID != 30 {
		t.Fatalf("snapshot = %+v", got)
	}
}

func TestRegistryChurnDoesNotRetainExitedPIDs(t *testing.T) {
	discoverer := &fakeDiscoverer{}
	registry := NewRegistry(discoverer, DefaultMaxTargets)

	for batch := 0; batch < 15; batch++ {
		discoverer.targets = discoverer.targets[:0]
		for offset := 0; offset < 100; offset++ {
			pid := uint32(batch*100 + offset + 1)
			discoverer.targets = append(discoverer.targets, newTestTarget(pid, uint64(pid), uint64(pid)))
		}
		changes, err := registry.Reconcile(context.Background())
		if err != nil {
			t.Fatalf("batch %d Reconcile: %v", batch, err)
		}
		if len(changes.Added) != 100 || len(registry.Snapshot()) != 100 {
			t.Fatalf("batch %d changes = %+v, snapshot size = %d", batch, changes, len(registry.Snapshot()))
		}
		if batch > 0 && len(changes.Removed) != 100 {
			t.Fatalf("batch %d removed %d targets, want 100", batch, len(changes.Removed))
		}
	}
}

func newTestTarget(pid uint32, startTime, address uint64) Target {
	return Target{
		Identity:      Identity{PID: pid, StartTimeTicks: startTime},
		GoVersion:     "go1.test",
		ExecutableKey: "test",
		SymbolAddress: address,
	}
}
