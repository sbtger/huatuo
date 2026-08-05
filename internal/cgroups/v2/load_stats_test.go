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

package v2

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"huatuo-bamai/internal/cgroups/paths"
	"huatuo-bamai/internal/cgroups/stats"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

type fakeTaskLoadSnapshotter struct {
	ids    []uint64
	calls  [][]uint64
	result map[uint64]stats.LoadStats
	err    error
}

type taskLoadSnapshotterFunc func([]uint64) (map[uint64]stats.LoadStats, error)

func (f taskLoadSnapshotterFunc) Snapshot(ids []uint64) (map[uint64]stats.LoadStats, error) {
	return f(ids)
}

func (s *fakeTaskLoadSnapshotter) Snapshot(
	ids []uint64,
) (map[uint64]stats.LoadStats, error) {
	s.ids = append([]uint64(nil), ids...)
	s.calls = append(s.calls, append([]uint64(nil), ids...))
	return s.result, s.err
}

type fakeLoadCollector struct {
	capacity   uint32
	closeCalls int
	closeErr   error
}

func (c *fakeLoadCollector) Snapshot(
	[]uint64,
) (map[uint64]stats.LoadStats, error) {
	return map[uint64]stats.LoadStats{}, nil
}

func (c *fakeLoadCollector) Capacity() uint32 {
	return c.capacity
}

func (c *fakeLoadCollector) Close() error {
	c.closeCalls++
	return c.closeErr
}

func TestSharedTaskLoadSnapshotterCoalescesConsumers(t *testing.T) {
	collector := &fakeTaskLoadSnapshotter{
		result: map[uint64]stats.LoadStats{
			10: {NrRunning: 1},
			20: {NrUninterruptible: 2},
		},
	}
	now := time.Now()
	shared := &sharedTaskLoadSnapshotter{
		snapshotter: collector,
		now:         func() time.Time { return now },
	}

	loadavg, err := shared.Snapshot(LoadStatsConsumerLoadavg, []uint64{10})
	if err != nil {
		t.Fatalf("first loadavg snapshot: %v", err)
	}
	if loadavg[10].NrRunning != 1 {
		t.Fatalf("loadavg snapshot = %+v, want running=1", loadavg)
	}

	// The new dload target is not covered by the first generation, so the
	// one-time registration refresh includes both consumers' targets.
	dload, err := shared.Snapshot(LoadStatsConsumerDload, []uint64{20})
	if err != nil {
		t.Fatalf("first dload snapshot: %v", err)
	}
	if dload[20].NrUninterruptible != 2 {
		t.Fatalf("dload snapshot = %+v, want uninterruptible=2", dload)
	}

	// Loadavg has not consumed the refreshed generation and therefore reuses
	// it. Dload already consumed it and must trigger the next generation.
	if _, err := shared.Snapshot(LoadStatsConsumerLoadavg, []uint64{10}); err != nil {
		t.Fatalf("second loadavg snapshot: %v", err)
	}
	if len(collector.calls) != 2 {
		t.Fatalf("collector calls after shared generation = %d, want 2", len(collector.calls))
	}
	if _, err := shared.Snapshot(LoadStatsConsumerDload, []uint64{20}); err != nil {
		t.Fatalf("second dload snapshot: %v", err)
	}

	wantCalls := [][]uint64{{10}, {10, 20}, {10, 20}}
	if !reflect.DeepEqual(collector.calls, wantCalls) {
		t.Fatalf("collector calls = %v, want %v", collector.calls, wantCalls)
	}
}

func TestSharedTaskLoadSnapshotterDoesNotReuseForSameConsumer(t *testing.T) {
	collector := &fakeTaskLoadSnapshotter{}
	shared := &sharedTaskLoadSnapshotter{snapshotter: collector}

	for range 2 {
		if _, err := shared.Snapshot(LoadStatsConsumerDload, []uint64{10}); err != nil {
			t.Fatalf("dload snapshot: %v", err)
		}
	}
	if len(collector.calls) != 2 {
		t.Fatalf("collector calls = %d, want 2", len(collector.calls))
	}
}

func TestSharedTaskLoadSnapshotterBoundsSnapshotAge(t *testing.T) {
	for _, first := range []LoadStatsConsumer{LoadStatsConsumerLoadavg, LoadStatsConsumerDload} {
		for _, tt := range []struct {
			name      string
			age       time.Duration
			wantCalls int
			wantD     uint64
		}{
			{"adjacent", sharedLoadSnapshotMaxAge - time.Nanosecond, 1, 20},
			{"expired", sharedLoadSnapshotMaxAge, 2, 0},
			{"different_intervals", 10 * time.Second, 2, 0},
			{"long_idle", time.Hour, 2, 0},
			{"clock_backwards", -time.Nanosecond, 2, 0},
		} {
			t.Run(fmt.Sprintf("%d/%s", first, tt.name), func(t *testing.T) {
				now := time.Now()
				collector := &fakeTaskLoadSnapshotter{
					result: map[uint64]stats.LoadStats{10: {NrUninterruptible: 20}},
				}
				shared := &sharedTaskLoadSnapshotter{
					snapshotter: collector,
					now:         func() time.Time { return now },
				}
				if _, err := shared.Snapshot(first, []uint64{10}); err != nil {
					t.Fatal(err)
				}
				now = now.Add(tt.age)
				collector.result = map[uint64]stats.LoadStats{10: {}}
				second := LoadStatsConsumerLoadavg + LoadStatsConsumerDload - first
				got, err := shared.Snapshot(second, []uint64{10})
				if err != nil {
					t.Fatal(err)
				}
				if got[10].NrUninterruptible != tt.wantD || len(collector.calls) != tt.wantCalls {
					t.Fatalf("D=%d, calls=%d; want D=%d, calls=%d",
						got[10].NrUninterruptible, len(collector.calls), tt.wantD, tt.wantCalls)
				}
			})
		}
	}
}

func TestSharedTaskLoadSnapshotterExpiredRefreshFailure(t *testing.T) {
	now := time.Now()
	collector := &fakeTaskLoadSnapshotter{
		result: map[uint64]stats.LoadStats{10: {NrUninterruptible: 20}},
	}
	shared := &sharedTaskLoadSnapshotter{
		snapshotter: collector,
		now:         func() time.Time { return now },
	}
	if _, err := shared.Snapshot(LoadStatsConsumerDload, []uint64{10}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(sharedLoadSnapshotMaxAge)
	wantErr := errors.New("iterator failed")
	collector.err = wantErr
	got, err := shared.Snapshot(LoadStatsConsumerLoadavg, []uint64{10})
	if !errors.Is(err, wantErr) || got != nil {
		t.Fatalf("failed refresh returned snapshot=%v, err=%v", got, err)
	}
	if shared.generation != 1 || shared.consumers[LoadStatsConsumerLoadavg].lastGeneration != 0 {
		t.Fatal("failed refresh advanced snapshot generation")
	}
	collector.err = nil
	collector.result = map[uint64]stats.LoadStats{10: {}}
	got, err = shared.Snapshot(LoadStatsConsumerLoadavg, []uint64{10})
	if err != nil || got[10].NrUninterruptible != 0 || len(collector.calls) != 3 {
		t.Fatalf("retry returned snapshot=%v, err=%v, calls=%d", got, err, len(collector.calls))
	}
}

func TestSharedTaskLoadSnapshotterIncludesScanTimeInAge(t *testing.T) {
	now := time.Now()
	calls := 0
	shared := &sharedTaskLoadSnapshotter{
		now: func() time.Time { return now },
		snapshotter: taskLoadSnapshotterFunc(func([]uint64) (map[uint64]stats.LoadStats, error) {
			calls++
			now = now.Add(sharedLoadSnapshotMaxAge)
			return map[uint64]stats.LoadStats{10: {}}, nil
		}),
	}
	for _, consumer := range []LoadStatsConsumer{LoadStatsConsumerDload, LoadStatsConsumerLoadavg} {
		if _, err := shared.Snapshot(consumer, []uint64{10}); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 2 {
		t.Fatalf("collector calls = %d, want 2 after slow scan", calls)
	}
}

func TestSharedTaskLoadSnapshotterForgetLastConsumerClearsSnapshot(t *testing.T) {
	now := time.Now()
	collector := &fakeTaskLoadSnapshotter{
		result: map[uint64]stats.LoadStats{10: {NrUninterruptible: 20}},
	}
	shared := &sharedTaskLoadSnapshotter{
		snapshotter: collector,
		now:         func() time.Time { return now },
	}
	if _, err := shared.Snapshot(LoadStatsConsumerDload, []uint64{10}); err != nil {
		t.Fatal(err)
	}
	shared.Forget(LoadStatsConsumerDload)
	if shared.snapshot != nil || shared.snapshotIDs != nil ||
		shared.generation != 0 || !shared.sampledAt.IsZero() {
		t.Fatal("last consumer left a cached snapshot")
	}
	// Even an immediate restart must sample again when all consumers stopped.
	collector.result = map[uint64]stats.LoadStats{10: {}}
	got, err := shared.Snapshot(LoadStatsConsumerLoadavg, []uint64{10})
	if err != nil || got[10].NrUninterruptible != 0 || len(collector.calls) != 2 {
		t.Fatalf("restart returned snapshot=%v, err=%v, calls=%d", got, err, len(collector.calls))
	}
}

func TestSharedTaskLoadSnapshotterForgetPreservesActiveConsumer(t *testing.T) {
	now := time.Now()
	collector := &fakeTaskLoadSnapshotter{}
	shared := &sharedTaskLoadSnapshotter{
		snapshotter: collector,
		now:         func() time.Time { return now },
	}
	if _, err := shared.Snapshot(LoadStatsConsumerLoadavg, []uint64{10}); err != nil {
		t.Fatal(err)
	}
	if _, err := shared.Snapshot(LoadStatsConsumerDload, []uint64{20}); err != nil {
		t.Fatal(err)
	}
	shared.Forget(LoadStatsConsumerDload)
	if _, err := shared.Snapshot(LoadStatsConsumerLoadavg, []uint64{10}); err != nil {
		t.Fatal(err)
	}
	if len(collector.calls) != 2 {
		t.Fatalf("collector calls = %d, want 2 with fresh snapshot retained", len(collector.calls))
	}
	if _, err := shared.Snapshot(LoadStatsConsumerLoadavg, []uint64{10}); err != nil {
		t.Fatal(err)
	}
	if want := []uint64{10}; !reflect.DeepEqual(collector.ids, want) {
		t.Fatalf("collector targets = %v, want %v", collector.ids, want)
	}
}

func BenchmarkSharedTaskLoadSnapshotter(b *testing.B) {
	result := map[uint64]stats.LoadStats{10: {NrRunning: 1}}
	shared := &sharedTaskLoadSnapshotter{
		snapshotter: taskLoadSnapshotterFunc(func([]uint64) (map[uint64]stats.LoadStats, error) {
			return result, nil
		}),
	}
	ids := []uint64{10}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		for _, consumer := range []LoadStatsConsumer{LoadStatsConsumerDload, LoadStatsConsumerLoadavg} {
			if _, err := shared.Snapshot(consumer, ids); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func TestSharedTaskLoadSnapshotterForgetDropsTargets(t *testing.T) {
	collector := &fakeTaskLoadSnapshotter{}
	shared := &sharedTaskLoadSnapshotter{snapshotter: collector}

	if _, err := shared.Snapshot(LoadStatsConsumerDload, []uint64{20}); err != nil {
		t.Fatalf("dload snapshot: %v", err)
	}
	shared.Forget(LoadStatsConsumerDload)
	if _, err := shared.Snapshot(LoadStatsConsumerLoadavg, []uint64{10}); err != nil {
		t.Fatalf("loadavg snapshot: %v", err)
	}

	wantCalls := [][]uint64{{20}, {10}}
	if !reflect.DeepEqual(collector.calls, wantCalls) {
		t.Fatalf("collector calls = %v, want %v", collector.calls, wantCalls)
	}
}

func TestSharedLoadStatsUpdatesEmptyConsumerTargets(t *testing.T) {
	collector := &fakeTaskLoadSnapshotter{}
	shared := &sharedTaskLoadSnapshotter{snapshotter: collector}
	resolveID := func(path string) (uint64, error) {
		if path == "/cgroup/a" {
			return 10, nil
		}
		return 0, unix.ENOENT
	}
	originalRoot := paths.RootfsDefaultPath
	paths.RootfsDefaultPath = "/cgroup"
	t.Cleanup(func() { paths.RootfsDefaultPath = originalRoot })

	if _, err := sharedLoadStats(
		LoadStatsConsumerLoadavg, []string{"a"}, shared, resolveID); err != nil {
		t.Fatalf("first sharedLoadStats: %v", err)
	}
	if _, err := sharedLoadStats(
		LoadStatsConsumerLoadavg, nil, shared, resolveID); err != nil {
		t.Fatalf("empty sharedLoadStats: %v", err)
	}
	if got := shared.consumers[LoadStatsConsumerLoadavg].ids; len(got) != 0 {
		t.Fatalf("consumer IDs = %v, want empty", got)
	}
	if len(collector.calls) != 1 {
		t.Fatalf("collector calls = %d, want 1", len(collector.calls))
	}
}

func TestLoadStatsCollectsOneSnapshot(t *testing.T) {
	originalRoot := paths.RootfsDefaultPath
	paths.RootfsDefaultPath = "/cgroup"
	t.Cleanup(func() { paths.RootfsDefaultPath = originalRoot })

	wantA := stats.LoadStats{NrRunning: 2, NrUninterruptible: 1}
	snapshotter := &fakeTaskLoadSnapshotter{
		result: map[uint64]stats.LoadStats{10: wantA},
	}
	ids := map[string]uint64{
		"/cgroup/a": 10,
		"/cgroup/b": 20,
	}

	got, err := loadStats(
		[]string{"a", "b", "a", "gone"},
		snapshotter,
		func(path string) (uint64, error) {
			id, ok := ids[path]
			if !ok {
				return 0, unix.ENOENT
			}
			return id, nil
		},
	)
	if err != nil {
		t.Fatalf("loadStats: %v", err)
	}
	if want := []uint64{10, 20}; !reflect.DeepEqual(snapshotter.ids, want) {
		t.Fatalf("snapshot IDs = %v, want %v", snapshotter.ids, want)
	}
	if !reflect.DeepEqual(got["a"], wantA) {
		t.Fatalf("stats for a = %+v, want %+v", got["a"], wantA)
	}
	if got["b"] != (stats.LoadStats{}) {
		t.Fatalf("stats for b = %+v, want zero", got["b"])
	}
	if _, ok := got["gone"]; ok {
		t.Fatal("disappeared cgroup unexpectedly returned")
	}
}

func TestLoadStatsReturnsPartialResultsWithResolveError(t *testing.T) {
	originalRoot := paths.RootfsDefaultPath
	paths.RootfsDefaultPath = "/cgroup"
	t.Cleanup(func() { paths.RootfsDefaultPath = originalRoot })

	wantErr := errors.New("permission denied")
	wantStats := stats.LoadStats{NrRunning: 2}
	snapshotter := &fakeTaskLoadSnapshotter{
		result: map[uint64]stats.LoadStats{10: wantStats},
	}
	got, err := loadStats(
		[]string{"good", "denied"},
		snapshotter,
		func(path string) (uint64, error) {
			if path == "/cgroup/good" {
				return 10, nil
			}
			return 0, wantErr
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("loadStats error = %v, want %v", err, wantErr)
	}
	if want := []uint64{10}; !reflect.DeepEqual(snapshotter.ids, want) {
		t.Fatalf("snapshot IDs = %v, want %v", snapshotter.ids, want)
	}
	if !reflect.DeepEqual(got["good"], wantStats) {
		t.Fatalf("stats for good = %+v, want %+v", got["good"], wantStats)
	}
	if _, ok := got["denied"]; ok {
		t.Fatal("failed cgroup unexpectedly returned")
	}
}

func TestLoadStatsReturnsSnapshotError(t *testing.T) {
	wantErr := errors.New("iterator failed")
	_, err := loadStats(
		[]string{"a"},
		&fakeTaskLoadSnapshotter{err: wantErr},
		func(string) (uint64, error) { return 10, nil },
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("loadStats error = %v, want %v", err, wantErr)
	}
}

func TestLoadStatsSkipsSnapshotWithoutCgroups(t *testing.T) {
	snapshotter := &fakeTaskLoadSnapshotter{err: errors.New("unexpected call")}
	got, err := loadStats(
		nil,
		snapshotter,
		func(string) (uint64, error) { return 0, nil },
	)
	if err != nil {
		t.Fatalf("loadStats: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("loadStats = %v, want empty", got)
	}
	if snapshotter.ids != nil {
		t.Fatalf("snapshot unexpectedly called with %v", snapshotter.ids)
	}
}

func TestLoadStatsSkipsSnapshotWhenCgroupsDisappear(t *testing.T) {
	snapshotter := &fakeTaskLoadSnapshotter{err: errors.New("unexpected call")}
	got, err := loadStats(
		[]string{"gone"},
		snapshotter,
		func(string) (uint64, error) { return 0, unix.ENOENT },
	)
	if err != nil {
		t.Fatalf("loadStats: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("loadStats = %v, want empty", got)
	}
	if snapshotter.ids != nil {
		t.Fatalf("snapshot unexpectedly called with %v", snapshotter.ids)
	}
}

func TestLazyTaskLoadSnapshotterCachesUnsupportedError(t *testing.T) {
	wantErr := fmt.Errorf("%w: tracing program type", ErrTaskIteratorNotSupported)
	calls := 0
	snapshotter := &lazyTaskLoadSnapshotter{
		newCollector: func(uint32) (loadCollector, error) {
			calls++
			return nil, wantErr
		},
	}

	for range 2 {
		if _, err := snapshotter.Snapshot([]uint64{1}); !errors.Is(err, wantErr) {
			t.Fatalf("Snapshot() error = %v, want %v", err, wantErr)
		}
	}
	if calls != 1 {
		t.Fatalf("collector initialization calls = %d, want 1", calls)
	}
}

func TestLazyTaskLoadSnapshotterRetriesTransientError(t *testing.T) {
	wantErr := errors.New("permission denied")
	calls := 0
	snapshotter := &lazyTaskLoadSnapshotter{
		newCollector: func(uint32) (loadCollector, error) {
			calls++
			return nil, wantErr
		},
	}

	for range 2 {
		if _, err := snapshotter.Snapshot([]uint64{1}); !errors.Is(err, wantErr) {
			t.Fatalf("Snapshot() error = %v, want %v", err, wantErr)
		}
	}
	if calls != 2 {
		t.Fatalf("collector initialization calls = %d, want 2", calls)
	}
}

func TestSharedTaskLoadSnapshotterCloseReleasesCollectorOnce(t *testing.T) {
	collector := &fakeLoadCollector{capacity: minLoadStatsMapEntries}
	lazy := &lazyTaskLoadSnapshotter{collector: collector}
	shared := &sharedTaskLoadSnapshotter{
		snapshotter: lazy,
		consumers: map[LoadStatsConsumer]*sharedLoadConsumer{
			LoadStatsConsumerLoadavg: {ids: []uint64{10}},
		},
		generation:  1,
		snapshotIDs: map[uint64]struct{}{10: {}},
		snapshot:    map[uint64]stats.LoadStats{10: {NrRunning: 1}},
		sampledAt:   time.Now(),
	}

	for range 2 {
		if err := shared.Close(); err != nil {
			t.Fatalf("Close() error = %v", err)
		}
	}
	if collector.closeCalls != 1 {
		t.Fatalf("collector Close() calls = %d, want 1", collector.closeCalls)
	}
	if lazy.collector != nil {
		t.Fatal("active collector was not cleared")
	}
	if shared.consumers != nil || shared.snapshot != nil ||
		shared.snapshotIDs != nil || shared.generation != 0 || !shared.sampledAt.IsZero() {
		t.Fatal("shared snapshot state was not cleared")
	}
}

func TestCheckPIDNamespaceStatus(t *testing.T) {
	for _, status := range []uint32{
		pidNamespaceUnchecked, pidNamespaceHost, pidNamespaceNested,
		pidNamespaceReadError, 99,
	} {
		err := checkPIDNamespaceStatus(status)
		if (err == nil) != (status == pidNamespaceHost) {
			t.Fatalf("checkPIDNamespaceStatus(%d) = %v", status, err)
		}
		if errors.Is(err, ErrTaskIteratorNotSupported) != (status == pidNamespaceNested) {
			t.Fatalf("unexpected unsupported classification for status %d: %v", status, err)
		}
	}
}

func TestLoadStatsMapCapacity(t *testing.T) {
	tests := []struct {
		required int
		want     uint32
		wantErr  bool
	}{
		{required: 0, want: 128},
		{required: 1, want: 128},
		{required: 128, want: 128},
		{required: 129, want: 256},
		{required: 65536, want: 65536},
		{required: 65537, wantErr: true},
	}

	for _, test := range tests {
		got, err := loadStatsMapCapacity(test.required)
		if (err != nil) != test.wantErr {
			t.Fatalf("loadStatsMapCapacity(%d) error = %v, wantErr %t",
				test.required, err, test.wantErr)
		}
		if got != test.want {
			t.Fatalf("loadStatsMapCapacity(%d) = %d, want %d",
				test.required, got, test.want)
		}
	}
}

func TestTaskIteratorLinkUnsupported(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "library feature error", err: fmt.Errorf("attach: %w", link.ErrNotSupported), want: true},
		{name: "invalid iterator link", err: fmt.Errorf("attach: %w", unix.EINVAL), want: false},
		{name: "missing syscall", err: fmt.Errorf("attach: %w", unix.ENOSYS), want: true},
		{name: "unsupported operation", err: fmt.Errorf("attach: %w", unix.EOPNOTSUPP), want: true},
		{name: "permission error", err: fmt.Errorf("attach: %w", unix.EPERM), want: false},
		{name: "verifier error", err: errors.New("invalid BPF program"), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isTaskIteratorLinkUnsupported(test.err); got != test.want {
				t.Fatalf("isTaskIteratorLinkUnsupported(%v) = %t, want %t",
					test.err, got, test.want)
			}
		})
	}
}

func TestTaskIteratorLoadErrorPreservesVerifierLog(t *testing.T) {
	verifierErr := &ebpf.VerifierError{Cause: unix.EACCES}
	for i := range 20 {
		verifierErr.Log = append(verifierErr.Log, fmt.Sprintf("verifier line %d", i))
	}
	err := taskIteratorLoadError(fmt.Errorf("program: %w", verifierErr))
	var got *ebpf.VerifierError
	if !errors.As(err, &got) || got != verifierErr || !errors.Is(err, unix.EACCES) {
		t.Fatalf("verifier error chain lost: %v", err)
	}
	for _, line := range verifierErr.Log {
		if !strings.Contains(err.Error(), "\n\t"+line) {
			t.Fatalf("verifier log line %q missing: %v", line, err)
		}
	}
}

func TestLazyTaskLoadSnapshotterDoesNotCacheVerifierFailure(t *testing.T) {
	wantErr := &ebpf.VerifierError{Cause: unix.EACCES}
	calls := 0
	snapshotter := &lazyTaskLoadSnapshotter{
		newCollector: func(uint32) (loadCollector, error) {
			calls++
			return nil, taskIteratorLoadError(wantErr)
		},
	}
	for range 2 {
		_, err := snapshotter.Snapshot([]uint64{1})
		if !errors.Is(err, wantErr) || errors.Is(err, ErrTaskIteratorNotSupported) {
			t.Fatalf("verifier failure misclassified: %v", err)
		}
	}
	if calls != 2 || snapshotter.unsupportedErr != nil {
		t.Fatal("verifier failure was cached as unsupported")
	}
}

func TestTaskIteratorLoadUnsupported(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "library feature error", err: fmt.Errorf("load: %w", ebpf.ErrNotSupported), want: true},
		{name: "verifier rejection", err: &ebpf.VerifierError{Cause: unix.EINVAL}, want: false},
		{name: "wrapped verifier rejection", err: fmt.Errorf("load: %w", &ebpf.VerifierError{Cause: unix.EACCES}), want: false},
		{name: "verifier unsupported cause", err: &ebpf.VerifierError{Cause: ebpf.ErrNotSupported}, want: false},
		{name: "resource error", err: fmt.Errorf("load: %w", unix.ENOMEM), want: false},
		{name: "permission error", err: fmt.Errorf("load: %w", unix.EPERM), want: false},
		{name: "invalid object", err: errors.New("invalid object"), want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isTaskIteratorLoadUnsupported(test.err); got != test.want {
				t.Fatalf("isTaskIteratorLoadUnsupported(%v) = %t, want %t",
					test.err, got, test.want)
			}
		})
	}
}
