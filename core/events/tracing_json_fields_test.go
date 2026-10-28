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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ccfos/huatuo/internal/bpf"
	"github.com/ccfos/huatuo/internal/bpf/abi"

	"github.com/ccfos/huatuo/internal/pod"
	"github.com/ccfos/huatuo/internal/tracing"
	"github.com/ccfos/huatuo/pkg/metric"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ccfos/huatuo/pkg/types"
)

func TestEventJSONFieldNames(t *testing.T) {
	tests := []struct {
		name     string
		value    any
		expected []string
	}{
		{
			name: "scheduler tick",
			value: SchedTickTracingData{
				TickIntervalNS:          20,
				TickIntervalThresholdNS: 10,
			},
			expected: []string{"tick_interval_ns", "tick_interval_threshold_ns"},
		},
		{
			name: "memory reclaim",
			value: MemoryReclaimTracingData{
				PID:               10,
				TID:               11,
				ReclaimDurationNS: 20,
			},
			expected: []string{"pid", "tid", "reclaim_duration_ns"},
		},
		{
			name:     "hung task",
			value:    HungTaskTracerData{TID: 11},
			expected: []string{"tid"},
		},
		{
			name:     "oom actor",
			value:    OOMActor{PID: 10},
			expected: []string{"pid"},
		},
		{
			name: "network receive latency",
			value: NetTracingData{
				LatencyMS:          20,
				LatencyThresholdMS: 10,
				PacketLenBytes:     64,
			},
			expected: []string{
				"latency_stage",
				"latency_ms",
				"latency_threshold_ms",
				"packet_len_bytes",
				"net_namespace_inum",
				"net_namespace_cookie",
			},
		},
		{
			name:     "dropwatch",
			value:    types.DropWatchTracing{PacketLenBytes: 64},
			expected: []string{"packet_len_bytes"},
		},
		{
			name:     "ras",
			value:    RasTracingData{Device: "cpu"},
			expected: []string{"dev"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			encoded, err := json.Marshal(tt.value)
			require.NoError(t, err)

			fields := map[string]json.RawMessage{}
			require.NoError(t, json.Unmarshal(encoded, &fields))
			for _, name := range tt.expected {
				assert.Contains(t, fields, name)
			}
		})
	}
}

func TestReclaimUnresolvedOutputCooldown(t *testing.T) {
	attr, err := newMemoryReclaim()
	require.NoError(t, err)
	require.NotZero(t, attr.Flag&tracing.FlagMetric)
	c := attr.TracingData.(*memoryReclaimTracing)
	now := time.Unix(100, 0)
	require.True(t, c.allowReclaimOutput(nil, now))
	for range 100 {
		require.False(t, c.allowReclaimOutput(nil, now), "unresolved flood exceeded output budget")
	}
	require.False(t, c.allowReclaimOutput(nil, now.Add(time.Second-time.Nanosecond)))
	deadline := c.nextUnresolved
	for range 100 {
		require.True(t, c.allowReclaimOutput(&pod.Container{ID: "resolved"}, now))
	}
	require.Equal(t, deadline, c.nextUnresolved, "resolved events consumed or refilled host budget")
	metrics, err := c.Update()
	require.NoError(t, err)
	require.Len(t, metrics, 1)
	assert.Equal(t, "unresolved_suppressed_total", metrics[0].Name())
	assert.Equal(t, metric.MetricTypeCounter, metrics[0].Type())
	assert.Equal(t, float64(101), metrics[0].Value)
	require.True(t, c.allowReclaimOutput(nil, now.Add(time.Second)), "exact cooldown boundary must recover")
	require.False(t, c.allowReclaimOutput(nil, now.Add(time.Second)), "cooldown must begin before saving")
	require.True(t, c.allowReclaimOutput(nil, now.Add(time.Hour)))
	require.False(t, c.allowReclaimOutput(nil, now.Add(time.Hour)), "idle time must not accumulate burst credits")
	metrics, err = c.Update()
	require.NoError(t, err)
	assert.Equal(t, float64(103), metrics[0].Value, "recovery must not reset suppression count")
}

func TestReclaimSuppressionConcurrentScrapes(t *testing.T) {
	c := &memoryReclaimTracing{}
	now := time.Unix(100, 0)
	require.True(t, c.allowReclaimOutput(nil, now))
	start, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		<-start
		for range 1000 {
			c.allowReclaimOutput(nil, now)
		}
	}()
	close(start)
	var previous float64
	for range 1000 {
		metrics, err := c.Update()
		require.NoError(t, err)
		require.GreaterOrEqual(t, metrics[0].Value, previous)
		previous = metrics[0].Value
	}
	<-done
	metrics, err := c.Update()
	require.NoError(t, err)
	assert.Equal(t, float64(1000), metrics[0].Value)
}

func BenchmarkReclaimOutputCooldown(b *testing.B) {
	for _, mode := range []string{"resolved", "allowed", "suppressed"} {
		b.Run(mode, func(b *testing.B) {
			c := &memoryReclaimTracing{}
			now := time.Unix(100, 0)
			var container *pod.Container
			if mode == "resolved" {
				container = &pod.Container{ID: "resolved"}
			}
			if mode == "suppressed" {
				c.nextUnresolved = now.Add(time.Hour)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				if mode == "allowed" {
					now = now.Add(time.Second)
				}
				if c.allowReclaimOutput(container, now) != (mode != "suppressed") {
					b.Fatal("unexpected output decision")
				}
			}
		})
	}
}

type hungTaskAttachStub struct {
	bpf.BPF
	attachErr, closeErr error
	closed              int
}

func (s *hungTaskAttachStub) AttachAndEventPipe(context.Context, string, uint32) (bpf.PerfEventReader, error) {
	return nil, s.attachErr
}
func (s *hungTaskAttachStub) Close() error { s.closed++; return s.closeErr }
func TestHungTaskHostFallback(t *testing.T) {
	for _, stage := range []string{"load", "attach", "host", "close"} {
		t.Run(stage, func(t *testing.T) {
			failure := errors.New("container unavailable")
			hostFailure := errors.New("host unavailable")
			closeFailure := errors.New("close failed")
			first, last := &hungTaskAttachStub{}, &hungTaskAttachStub{}
			calls := []bool{}
			obj, _, err := startHungTaskBPF(context.Background(), "fixture", func(_ string, containers bool) (bpf.BPF, error) {
				calls = append(calls, containers)
				if !containers {
					if stage == "host" {
						return nil, hostFailure
					}
					return last, nil
				}
				if stage == "load" || stage == "host" {
					return nil, failure
				}
				first.attachErr = failure
				if stage == "close" {
					first.closeErr = closeFailure
				}
				return first, nil
			})
			if stage == "host" || stage == "close" {
				if obj != nil || !errors.Is(err, failure) {
					t.Fatalf("obj=%v err=%v", obj, err)
				}
				expected := hostFailure
				if stage == "close" {
					expected = closeFailure
				}
				if !errors.Is(err, expected) {
					t.Fatalf("missing error %v: %v", expected, err)
				}
			} else if err != nil || obj != last {
				t.Fatalf("fallback obj=%v err=%v", obj, err)
			}
			want := 2
			if stage == "close" {
				want = 1
			}
			if len(calls) != want || !calls[0] || (want == 2 && calls[1]) {
				t.Fatalf("load modes=%v", calls)
			}
			if stage == "attach" || stage == "close" {
				if first.closed != 1 {
					t.Fatal("failed object not closed")
				}
			}
		})
	}
}

func TestHungTaskContainerAttribution(t *testing.T) {
	matched := &pod.Container{ID: "matched"}
	for _, css := range []uint64{0, 42, 99} {
		t.Run(fmt.Sprint(css), func(t *testing.T) {
			c := &hungTaskTracing{}
			calls := 0
			before := atomic.LoadInt64(&hungtaskCounter)
			container, err := c.record(&abi.HungtaskEvent{CPUCSSAddr: css}, func(address uint64, subsys string) (*pod.Container, error) {
				calls++
				require.Equal(t, css, address)
				require.Equal(t, "cpu", subsys)
				if address == 42 {
					return matched, nil
				}
				return nil, nil
			})
			require.NoError(t, err)
			require.Equal(t, before+1, atomic.LoadInt64(&hungtaskCounter))
			if css == 0 {
				require.Zero(t, calls)
			} else {
				require.Equal(t, 1, calls, "direct CSS must be queried once")
			}
			if css == 42 {
				require.Same(t, matched, container)
				require.Equal(t, uint64(1), c.containerCounts[matched.ID])
			} else {
				require.Nil(t, container)
				require.Empty(t, c.containerCounts)
			}
		})
	}
}

func TestHungTaskHostCountSurvivesDiscoveryFailure(t *testing.T) {
	c := &hungTaskTracing{}
	failure := errors.New("discovery failed")
	event := abi.HungtaskEvent{CPUCSSAddr: 42}
	before := atomic.LoadInt64(&hungtaskCounter)
	container, err := c.record(&event, func(uint64, string) (*pod.Container, error) { return nil, failure })
	require.Nil(t, container)
	require.ErrorIs(t, err, failure)
	require.Equal(t, before+1, atomic.LoadInt64(&hungtaskCounter))
	event.CPUCSSAddr = 0
	_, err = c.record(&event, func(uint64, string) (*pod.Container, error) {
		t.Fatal("host-only event queried containers")
		return nil, nil
	})
	require.NoError(t, err)
	event.CPUCSSAddr = 42
	matched := &pod.Container{ID: "matched"}
	container, err = c.record(&event, func(uint64, string) (*pod.Container, error) { return matched, nil })
	require.NoError(t, err)
	require.Same(t, matched, container)
	require.Equal(t, uint64(1), c.containerCounts[matched.ID])
}

func TestReclaimContainerCacheTTLAndMissRetry(t *testing.T) {
	hostCache := &reclaimContainerCache{}
	host, hostErr := hostCache.lookup(0, time.Unix(1000, 0), func() (map[uint64]*pod.Container, error) {
		t.Fatal("host CSS queried container metadata")
		return nil, nil
	})
	require.NoError(t, hostErr)
	require.Nil(t, host)
	require.True(t, hostCache.attemptedAt.IsZero())
	now := time.Unix(1000, 0)
	old := &pod.Container{ID: "old"}
	current := &pod.Container{ID: "current"}
	calls := 0
	cache := &reclaimContainerCache{}
	refresh := func() (map[uint64]*pod.Container, error) {
		calls++
		if calls == 1 {
			return map[uint64]*pod.Container{1: old}, nil
		}
		return map[uint64]*pod.Container{1: current, 2: current}, nil
	}
	value, err := cache.lookup(1, now, refresh)
	require.NoError(t, err)
	require.Same(t, old, value)
	value, err = cache.lookup(1, now.Add(cssCacheTTL), refresh)
	require.NoError(t, err)
	require.Same(t, old, value)
	require.Equal(t, 1, calls)
	value, err = cache.lookup(1, now.Add(cssCacheTTL+time.Nanosecond), refresh)
	require.NoError(t, err)
	require.Same(t, current, value)
	require.Equal(t, 2, calls)
	cache = &reclaimContainerCache{}
	calls = 0
	_, err = cache.lookup(1, now, refresh)
	require.NoError(t, err)
	value, err = cache.lookup(2, now.Add(reclaimCacheMissRetry-time.Nanosecond), refresh)
	require.NoError(t, err)
	require.Nil(t, value)
	require.Equal(t, 1, calls)
	value, err = cache.lookup(2, now.Add(reclaimCacheMissRetry), refresh)
	require.NoError(t, err)
	require.Same(t, current, value)
	require.Equal(t, 2, calls)
}

func TestReclaimContainerCacheRefreshFailure(t *testing.T) {
	now := time.Unix(1000, 0)
	old := &pod.Container{ID: "old"}
	failure := errors.New("discovery failed")
	for _, expired := range []bool{false, true} {
		t.Run(fmt.Sprint(expired), func(t *testing.T) {
			cache := &reclaimContainerCache{
				containers:  map[uint64]*pod.Container{1: old},
				refreshedAt: now,
				attemptedAt: now,
			}
			at := now.Add(reclaimCacheMissRetry)
			if expired {
				at = now.Add(cssCacheTTL + time.Nanosecond)
			}
			calls := 0
			refresh := func() (map[uint64]*pod.Container, error) {
				calls++
				return nil, failure
			}
			value, err := cache.lookup(2, at, refresh)
			require.ErrorIs(t, err, failure)
			require.Nil(t, value)
			value, err = cache.lookup(1, at.Add(time.Nanosecond), refresh)
			require.NoError(t, err)
			if expired {
				require.Nil(t, value, "expired identity survived discovery failure")
			} else {
				require.Same(t, old, value, "fresh sibling identity was discarded")
			}
			require.Equal(t, 1, calls)
			current := &pod.Container{ID: "new"}
			value, err = cache.lookup(2, at.Add(reclaimCacheMissRetry), func() (map[uint64]*pod.Container, error) {
				return map[uint64]*pod.Container{2: current}, nil
			})
			require.NoError(t, err)
			require.Same(t, current, value)
		})
	}
}

func TestHungTaskCleanupSerializesWithNewEventCounts(t *testing.T) {
	c := &hungTaskTracing{containerCounts: map[string]uint64{"old": 1}}
	old := &pod.Container{ID: "old", Labels: map[string]any{"HostNamespace": "default"}}
	fresh := &pod.Container{ID: "fresh", Labels: map[string]any{"HostNamespace": "default"}}
	lookedUp, recorded := make(chan struct{}), make(chan error, 1)
	data, err := c.update(func() (map[string]*pod.Container, error) {
		// Discovery must not leave a gap before pruning that permits new counts.
		if c.mu.TryLock() {
			c.mu.Unlock()
			return nil, errors.New("container discovery is outside the count lock")
		}
		snapshot := map[string]*pod.Container{"old": old}
		go func() {
			_, recordErr := c.record(&abi.HungtaskEvent{CPUCSSAddr: 42}, func(uint64, string) (*pod.Container, error) {
				close(lookedUp)
				return fresh, nil
			})
			recorded <- recordErr
		}()
		<-lookedUp
		return snapshot, nil
	})
	require.NoError(t, err)
	require.Len(t, data, 2)
	select {
	case err := <-recorded:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("event counting did not resume after metric collection")
	}
	c.mu.Lock()
	count := c.containerCounts[fresh.ID]
	c.mu.Unlock()
	require.Equal(t, uint64(1), count, "old snapshot removed a newly recorded event")
	data, err = c.update(func() (map[string]*pod.Container, error) {
		return map[string]*pod.Container{"fresh": fresh}, nil
	})
	require.NoError(t, err)
	require.Len(t, data, 2)
	require.Equal(t, float64(1), data[1].Value)
	c.mu.Lock()
	_, oldRetained := c.containerCounts[old.ID]
	c.mu.Unlock()
	require.False(t, oldRetained, "exited container was not pruned")
}
