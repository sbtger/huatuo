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

package javastack

import (
	"context"
	"testing"
)

type fakeDiscoverer struct {
	targets []Target
}

func (d *fakeDiscoverer) Discover(context.Context) ([]Target, error) {
	return append([]Target(nil), d.targets...), nil
}

func TestRegistryHandlesPIDReuseAndCapacity(t *testing.T) {
	discoverer := &fakeDiscoverer{targets: []Target{
		{Identity: Identity{PID: 10, StartTimeTicks: 100}},
		{Identity: Identity{PID: 20, StartTimeTicks: 200}},
	}}
	registry := NewRegistry(discoverer, 2)
	changes, err := registry.Reconcile(context.Background())
	if err != nil || len(changes.Added) != 2 {
		t.Fatalf("first Reconcile changes=%+v err=%v", changes, err)
	}

	discoverer.targets = []Target{
		{Identity: Identity{PID: 10, StartTimeTicks: 101}},
		{Identity: Identity{PID: 20, StartTimeTicks: 200}, Command: "java"},
		{Identity: Identity{PID: 30, StartTimeTicks: 300}},
	}
	changes, err = registry.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if len(changes.Removed) != 1 || len(changes.Added) != 1 ||
		len(changes.Updated) != 1 || changes.Dropped != 1 {
		t.Fatalf("second changes = %+v", changes)
	}
}
