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

package events

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"huatuo-bamai/internal/pod"
)

func TestReclaimEventTarget(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		id, attribution, emit := reclaimEventTarget(&pod.Container{ID: "container"}, enabled)
		if id != "container" || attribution != "" || !emit {
			t.Fatal(id, attribution, emit)
		}
		id, attribution, emit = reclaimEventTarget(nil, enabled)
		if id != "" || attribution != "unresolved" || emit != enabled {
			t.Fatal(id, attribution, emit)
		}
	}
}

func BenchmarkReclaimEventTarget(b *testing.B) {
	c := &pod.Container{ID: "container"}
	for b.Loop() {
		reclaimEventTarget(c, true)
	}
}

func TestReclaimCacheMissRefreshIndependentOfOutput(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprint(enabled), func(t *testing.T) {
			var cache reclaimContainerCache
			now := time.Now()
			calls := 0
			available := map[uint64]*pod.Container{}
			refresh := func() (map[uint64]*pod.Container, error) {
				calls++
				return available, nil
			}
			if _, err := cache.lookup(1, now, refresh); err != nil {
				t.Fatal(err)
			}
			available = map[uint64]*pod.Container{1: {ID: "new-container"}}
			for i := range 100 {
				container, err := cache.lookup(uint64(i+1), now.Add(time.Millisecond), refresh)
				_, _, emit := reclaimEventTarget(container, enabled)
				if err != nil || container != nil || emit != enabled || calls != 1 {
					t.Fatal("unresolved events bypassed retry limit", container, err, calls)
				}
			}
			container, err := cache.lookup(1, now.Add(reclaimCacheMissRetry), refresh)
			id, attribution, emit := reclaimEventTarget(container, enabled)
			if err != nil || id != "new-container" || attribution != "" || !emit || calls != 2 {
				t.Fatal("new container not resolved before TTL", id, attribution, emit, calls, err)
			}
			if _, err := cache.lookup(1, now.Add(2*time.Second), refresh); err != nil || calls != 2 {
				t.Fatal("cache hit refreshed", err, calls)
			}
		})
	}
}

func TestReclaimCacheExpiryAndDiscoveryFailure(t *testing.T) {
	var cache reclaimContainerCache
	now := time.Now()
	calls := 0
	failure := false
	refresh := func() (map[uint64]*pod.Container, error) {
		calls++
		if failure {
			return nil, errors.New("discovery unavailable")
		}
		return map[uint64]*pod.Container{1: {ID: "container"}}, nil
	}
	if _, err := cache.lookup(1, now, refresh); err != nil {
		t.Fatal(err)
	}
	failure = true
	expiredAt := now.Add(cssCacheTTL + time.Nanosecond)
	if container, err := cache.lookup(1, expiredAt, refresh); err == nil || container != nil {
		t.Fatal("expired attribution retained on failure", container, err)
	}
	for range 100 {
		if container, err := cache.lookup(1, expiredAt.Add(time.Millisecond), refresh); err != nil || container != nil || calls != 2 {
			t.Fatal("failed discovery not rate limited", container, err, calls)
		}
	}
	failure = false
	if container, err := cache.lookup(1, expiredAt.Add(reclaimCacheMissRetry), refresh); err != nil || container == nil || calls != 3 {
		t.Fatal("discovery did not recover", container, err, calls)
	}
}

func BenchmarkReclaimCacheLookup(b *testing.B) {
	now := time.Now()
	cache := reclaimContainerCache{
		containers:  map[uint64]*pod.Container{1: {ID: "container"}},
		refreshedAt: now, attemptedAt: now,
	}
	refresh := func() (map[uint64]*pod.Container, error) {
		b.Fatal("unexpected refresh")
		return nil, nil
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = cache.lookup(1, now, refresh)
		_, _ = cache.lookup(2, now, refresh)
	}
}
