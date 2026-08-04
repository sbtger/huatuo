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
	"testing"
	"time"

	"huatuo-bamai/internal/goheap"
	"huatuo-bamai/internal/profiler"
	"huatuo-bamai/pkg/tracing"

	"github.com/stretchr/testify/require"
)

type fixedSymbolizer struct{}

func (fixedSymbolizer) Resolve(uint64) string { return "main.allocate" }

func testOOMGoHeapProfiler(t *testing.T) (*oomGoHeapProfiler, *[]*tracing.WriteRequest) {
	t.Helper()
	p := newOOMGoHeapProfiler()
	writes := make([]*tracing.WriteRequest, 0, 2)
	p.symbolize = func(goheap.Target) (goheap.Symbolizer, error) {
		return fixedSymbolizer{}, nil
	}
	p.save = func(req *tracing.WriteRequest) error {
		writes = append(writes, req)
		return nil
	}
	return p, &writes
}

func testOOMGoHeapCapture() *goheap.Capture {
	bucket := goheap.Bucket{StackDepth: 1}
	bucket.Stack[0] = 0x1234
	bucket.Record.Active.Allocs = 7
	bucket.Record.Active.Frees = 2
	bucket.Record.Active.AllocBytes = 700
	bucket.Record.Active.FreeBytes = 200
	return &goheap.Capture{
		Target: goheap.Target{
			Identity:  goheap.Identity{PID: 42, StartTimeTicks: 99},
			GoVersion: "go1.22.4",
			BuildID:   "build-id",
		},
		OOMTimestamp:      123456,
		CaptureStartedNS:  123400,
		CaptureDurationNS: 56,
		CaptureID:         3,
		Flags:             goheap.CaptureFlagComplete,
		Buckets:           []goheap.Bucket{bucket},
	}
}

func TestOOMGoHeapProfilerPairsCaptureThenEvent(t *testing.T) {
	p, writes := testOOMGoHeapProfiler(t)
	capture := testOOMGoHeapCapture()
	eventTime := time.Unix(10, 20)

	require.NoError(t, p.HandleCapture(capture))
	require.Empty(t, *writes)
	require.NoError(t, p.ObserveOOM(42, 123456, "oom-id", "container-id", eventTime))
	assertOOMGoHeapWrites(t, *writes, eventTime)
}

func TestOOMGoHeapProfilerPairsEventThenCapture(t *testing.T) {
	p, writes := testOOMGoHeapProfiler(t)
	eventTime := time.Unix(10, 20)

	require.NoError(t, p.ObserveOOM(42, 123456, "oom-id", "container-id", eventTime))
	require.Empty(t, *writes)
	require.NoError(t, p.HandleCapture(testOOMGoHeapCapture()))
	assertOOMGoHeapWrites(t, *writes, eventTime)
}

func assertOOMGoHeapWrites(t *testing.T, writes []*tracing.WriteRequest, eventTime time.Time) {
	t.Helper()
	require.Len(t, writes, 2)
	profileTypes := make(map[string]bool)
	for _, write := range writes {
		require.Equal(t, oomGoHeapTracerName, write.TracerName)
		require.Equal(t, "oom-id", write.TracerID)
		require.Equal(t, "container-id", write.ContainerID)
		require.Equal(t, eventTime, write.TracerTime)
		require.Equal(t, tracing.TracerRunTypeEvent, write.TracerRunType)
		data, ok := write.TracerData.(*oomGoHeapProfileData)
		require.True(t, ok)
		require.Equal(t, uint32(42), data.Correlation.VictimPID)
		require.Equal(t, uint64(99), data.Correlation.VictimStartTimeTicks)
		require.Equal(t, uint64(123456), data.Correlation.OOMTimestamp)
		require.Equal(t, uint32(3), data.Capture.CaptureID)
		require.Equal(t, 1, data.Capture.BucketCount)
		profileTypes[data.FlameData.ProfileType] = true
	}
	require.True(t, profileTypes[profiler.ProfileTypeMemInuseSpace])
	require.True(t, profileTypes[profiler.ProfileTypeMemInuseObjects])
}

func TestOOMGoHeapProfilerFallsBackToRawPCs(t *testing.T) {
	p, writes := testOOMGoHeapProfiler(t)
	p.symbolize = func(goheap.Target) (goheap.Symbolizer, error) {
		return nil, errors.New("binary disappeared")
	}

	require.NoError(t, p.HandleCapture(testOOMGoHeapCapture()))
	require.NoError(t, p.ObserveOOM(42, 123456, "id", "", time.Now()))
	require.Len(t, *writes, 2)
}

func TestOOMGoHeapProfilerExpiresAndBoundsPending(t *testing.T) {
	p, writes := testOOMGoHeapProfiler(t)
	now := time.Unix(1, 0)
	p.now = func() time.Time { return now }
	p.pendingTTL = time.Second
	p.maxPending = 2

	require.NoError(t, p.ObserveOOM(1, 1, "first", "", now))
	now = now.Add(time.Millisecond)
	require.NoError(t, p.ObserveOOM(2, 2, "second", "", now))
	now = now.Add(time.Millisecond)
	require.NoError(t, p.ObserveOOM(3, 3, "third", "", now))
	require.Len(t, p.pending, 2)
	_, firstRetained := p.pending[oomGoHeapKey{victimPID: 1, oomTimestamp: 1}]
	require.False(t, firstRetained)

	now = now.Add(2 * time.Second)
	require.NoError(t, p.ObserveOOM(4, 4, "fourth", "", now))
	require.Len(t, p.pending, 1)
	require.Empty(t, *writes)
}

func TestOOMGoHeapProfilerRejectsInvalidCapture(t *testing.T) {
	p, _ := testOOMGoHeapProfiler(t)
	require.EqualError(t, p.HandleCapture(nil), "oom go heap: nil capture")
	require.EqualError(t, p.HandleCapture(&goheap.Capture{}), "oom go heap: capture has no correlation key")
}
