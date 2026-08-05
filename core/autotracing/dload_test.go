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

package autotracing

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"testing"
	"time"

	"huatuo-bamai/internal/cgroups"
	cgroupStats "huatuo-bamai/internal/cgroups/stats"
	cgroupV2 "huatuo-bamai/internal/cgroups/v2"
	"huatuo-bamai/internal/pod"
	"huatuo-bamai/pkg/types"
)

func TestNewDloadTracing(t *testing.T) {
	validConfig := &Config{}
	validConfig.Dload.Interval = 10
	validConfig.Dload.IntervalTracing = 30
	validConfig.Dload.ThresholdLoad = 5
	validConfig.Dload.EnableCgroupV2 = true

	tests := []struct {
		name        string
		update      func(*Config)
		expectedErr string
	}{
		{
			name: "valid config",
		},
		{
			name: "maximum sampling interval",
			update: func(config *Config) {
				config.Dload.Interval = maxDurationSeconds
			},
		},
		{
			name: "maximum tracing interval",
			update: func(config *Config) {
				config.Dload.IntervalTracing = maxDurationSeconds
			},
		},
		{
			name: "non-positive sampling interval",
			update: func(config *Config) {
				config.Dload.Interval = 0
			},
			expectedErr: "dload sampling interval must be positive",
		},
		{
			name: "negative tracing interval",
			update: func(config *Config) {
				config.Dload.IntervalTracing = -1
			},
			expectedErr: "dload tracing interval must be non-negative",
		},
		{
			name: "sampling interval duration overflow",
			update: func(config *Config) {
				config.Dload.Interval = maxDurationSeconds + 1
			},
			expectedErr: fmt.Sprintf(
				"dload sampling interval must not exceed %d seconds",
				maxDurationSeconds),
		},
		{
			name: "tracing interval duration overflow",
			update: func(config *Config) {
				config.Dload.IntervalTracing = maxDurationSeconds + 1
			},
			expectedErr: fmt.Sprintf(
				"dload tracing interval must not exceed %d seconds",
				maxDurationSeconds),
		},
		{
			name: "negative load threshold",
			update: func(config *Config) {
				config.Dload.ThresholdLoad = -1
			},
			expectedErr: "dload threshold must be non-negative",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := *validConfig
			if test.update != nil {
				test.update(&config)
			}

			tracer, err := newDloadTracing(&config)
			if test.expectedErr != "" {
				if err == nil || err.Error() != test.expectedErr {
					t.Fatalf("newDloadTracing() error = %v, want %q", err, test.expectedErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("newDloadTracing() error = %v", err)
			}
			if tracer.containers == nil {
				t.Fatal("newDloadTracing() returned a nil container map")
			}
			if !tracer.enableV2 {
				t.Fatal("newDloadTracing() did not preserve EnableCgroupV2")
			}
		})
	}
}

func TestDloadTracingStateIsPerInstance(t *testing.T) {
	config := &Config{}
	config.Dload.Interval = 10

	first, err := newDloadTracing(config)
	if err != nil {
		t.Fatalf("newDloadTracing() error = %v", err)
	}
	second, err := newDloadTracing(config)
	if err != nil {
		t.Fatalf("newDloadTracing() error = %v", err)
	}

	first.containers["container"] = &containerDloadInfo{}
	if len(second.containers) != 0 {
		t.Fatalf("second tracer has %d containers, want 0", len(second.containers))
	}
}

func TestDloadCgroupV2IsOptIn(t *testing.T) {
	if err := validateDloadMode(cgroups.Legacy, false); err != nil {
		t.Fatalf("validateDloadMode(Legacy) error = %v", err)
	}
	if err := validateDloadMode(cgroups.Unified, false); !errors.Is(err, types.ErrNotSupported) {
		t.Fatalf("validateDloadMode(Unified) error = %v, want ErrNotSupported", err)
	}
	if err := validateDloadMode(cgroups.Unified, true); err != nil {
		t.Fatalf("validateDloadMode(Unified) with opt-in error = %v", err)
	}
}

func TestDloadTracingReconcileContainers(t *testing.T) {
	lastTraceAt := time.Unix(100, 0)
	tracer := &dloadTracing{
		containers: map[string]*containerDloadInfo{
			"existing": {
				cgroupName:  "old-path",
				lastTraceAt: lastTraceAt,
				isSeen:      true,
			},
			"removed": {
				isSeen: true,
			},
		},
	}
	existing := &pod.Container{
		ID:         "existing",
		CgroupPath: "new-path",
	}
	added := &pod.Container{
		ID:         "added",
		CgroupPath: "added-path",
	}

	tracer.reconcileContainers(map[string]*pod.Container{
		existing.ID: existing,
		added.ID:    added,
	})

	if len(tracer.containers) != 2 {
		t.Fatalf("container count = %d, want 2", len(tracer.containers))
	}
	if _, ok := tracer.containers["removed"]; ok {
		t.Fatal("removed container remains in tracer state")
	}
	existingInfo := tracer.containers["existing"]
	if existingInfo.container != existing || existingInfo.cgroupName != "new-path" {
		t.Fatalf("existing container was not refreshed: %+v", existingInfo)
	}
	if existingInfo.lastTraceAt != lastTraceAt {
		t.Fatalf("lastTraceAt = %v, want %v", existingInfo.lastTraceAt, lastTraceAt)
	}
	if addedInfo := tracer.containers["added"]; addedInfo == nil || addedInfo.container != added {
		t.Fatalf("added container state = %+v", addedInfo)
	}
}

func TestDloadTracingShouldTrace(t *testing.T) {
	sampledAt := time.Unix(100, 0)

	tests := []struct {
		name        string
		threshold   dloadThreshold
		load        float64
		lastTraceAt time.Time
		expected    bool
	}{
		{
			name: "threshold exceeded after interval",
			threshold: dloadThreshold{
				load:             5,
				minTraceInterval: 10 * time.Second,
			},
			load:        6,
			lastTraceAt: sampledAt.Add(-10 * time.Second),
			expected:    true,
		},
		{
			name: "threshold boundary is not exceeded",
			threshold: dloadThreshold{
				load: 5,
			},
			load:        5,
			lastTraceAt: sampledAt.Add(-time.Hour),
		},
		{
			name: "minimum interval has not elapsed",
			threshold: dloadThreshold{
				load:             5,
				minTraceInterval: 10 * time.Second,
			},
			load:        6,
			lastTraceAt: sampledAt.Add(-9 * time.Second),
		},
		{
			name: "debug bypasses threshold",
			threshold: dloadThreshold{
				load:    5,
				isDebug: true,
			},
			load:     0,
			expected: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tracer := &dloadTracing{threshold: test.threshold}
			container := &containerDloadInfo{
				dLoad:       [2]float64{test.load},
				lastTraceAt: test.lastTraceAt,
			}

			if actual := tracer.shouldTrace(container, sampledAt); actual != test.expected {
				t.Fatalf("shouldTrace() = %t, want %t", actual, test.expected)
			}
		})
	}
}

func TestDloadTracingSelectTraceTargetV2(t *testing.T) {
	container := &pod.Container{ID: "container", CgroupPath: "container-path"}
	tracer := &dloadTracing{
		containers: map[string]*containerDloadInfo{
			container.ID: {
				cgroupName: container.CgroupPath,
				container:  container,
			},
		},
		threshold: dloadThreshold{isDebug: true},
		v2LoadStats: func(paths []string) (map[string]cgroupStats.LoadStats, error) {
			if !reflect.DeepEqual(paths, []string{container.CgroupPath}) {
				t.Fatalf("v2 load stats paths = %q, want %q", paths, container.CgroupPath)
			}
			return map[string]cgroupStats.LoadStats{
				container.CgroupPath: {
					NrRunning:         2,
					NrUninterruptible: 3,
				},
			}, nil
		},
	}

	target, load, err := tracer.selectTraceTarget(time.Unix(100, 0), cgroups.Unified)
	if err != nil {
		t.Fatalf("selectTraceTarget: %v", err)
	}
	if target == nil || target.container != container {
		t.Fatalf("target = %+v, want container %q", target, container.ID)
	}
	if load.NrRunning != 2 || load.NrUninterruptible != 3 {
		t.Fatalf("load stats = %+v, want running=2 uninterruptible=3", load)
	}
}

func TestDloadTracingCollectsSingleV2Snapshot(t *testing.T) {
	containers := map[string]*containerDloadInfo{
		"a": {
			cgroupName: "path-a",
			container:  &pod.Container{ID: "a"},
		},
		"b": {
			cgroupName: "path-b",
			container:  &pod.Container{ID: "b"},
		},
	}
	calls := 0
	tracer := &dloadTracing{
		containers: containers,
		threshold:  dloadThreshold{load: 100},
		v2LoadStats: func(paths []string) (map[string]cgroupStats.LoadStats, error) {
			calls++
			sort.Strings(paths)
			if want := []string{"path-a", "path-b"}; !reflect.DeepEqual(paths, want) {
				t.Fatalf("v2 load stats paths = %q, want %q", paths, want)
			}
			return map[string]cgroupStats.LoadStats{
				"path-a": {NrRunning: 1},
				"path-b": {NrRunning: 2},
			}, nil
		},
	}

	target, _, err := tracer.selectTraceTarget(time.Unix(100, 0), cgroups.Unified)
	if err != nil {
		t.Fatalf("selectTraceTarget: %v", err)
	}
	if target != nil {
		t.Fatalf("target = %+v, want nil", target)
	}
	if calls != 1 {
		t.Fatalf("v2 snapshot calls = %d, want 1", calls)
	}
}

func TestDloadTracingUsesPartialV2Snapshot(t *testing.T) {
	good := &pod.Container{ID: "good"}
	tracer := &dloadTracing{
		containers: map[string]*containerDloadInfo{
			"good": {
				cgroupName: "path-good",
				container:  good,
			},
			"failed": {
				cgroupName: "path-failed",
				container:  &pod.Container{ID: "failed"},
			},
		},
		threshold: dloadThreshold{isDebug: true},
		v2LoadStats: func([]string) (map[string]cgroupStats.LoadStats, error) {
			return map[string]cgroupStats.LoadStats{
				"path-good": {NrRunning: 2},
			}, errors.New("resolve path-failed: permission denied")
		},
	}

	target, load, err := tracer.selectTraceTarget(time.Unix(100, 0), cgroups.Unified)
	if err != nil {
		t.Fatalf("selectTraceTarget: %v", err)
	}
	if target == nil || target.container != good {
		t.Fatalf("target = %+v, want container %q", target, good.ID)
	}
	if load.NrRunning != 2 {
		t.Fatalf("load stats = %+v, want running=2", load)
	}
}

func TestDloadTracingReturnsV2SnapshotErrorWithoutResults(t *testing.T) {
	wantErr := errors.New("iterator failed")
	tracer := &dloadTracing{
		containers: map[string]*containerDloadInfo{
			"container": {
				cgroupName: "container-path",
				container:  &pod.Container{ID: "container"},
			},
		},
		v2LoadStats: func([]string) (map[string]cgroupStats.LoadStats, error) {
			return nil, wantErr
		},
	}

	_, _, err := tracer.selectTraceTarget(time.Unix(100, 0), cgroups.Unified)
	if !errors.Is(err, wantErr) {
		t.Fatalf("selectTraceTarget() error = %v, want %v", err, wantErr)
	}
}

func TestDloadTracingStopsWhenV2TaskIteratorIsUnsupported(t *testing.T) {
	tracer := &dloadTracing{
		containers: map[string]*containerDloadInfo{
			"container": {
				cgroupName: "container-path",
				container:  &pod.Container{ID: "container"},
			},
		},
		v2LoadStats: func([]string) (map[string]cgroupStats.LoadStats, error) {
			return nil, cgroupV2.ErrTaskIteratorNotSupported
		},
	}

	_, _, err := tracer.selectTraceTarget(time.Unix(100, 0), cgroups.Unified)
	if !errors.Is(err, types.ErrNotSupported) {
		t.Fatalf("selectTraceTarget() error = %v, want ErrNotSupported", err)
	}
}

func TestUpdateLoad(t *testing.T) {
	info := &containerDloadInfo{}

	updateLoad(info, 1, 0, loadDecayFactors(10*time.Second))

	expectedRunnableAvg := [2]uint64{314, 67}
	if info.runnableAvg != expectedRunnableAvg {
		t.Fatalf("runnableAvg = %v, want %v", info.runnableAvg, expectedRunnableAvg)
	}
	expectedLoadAvg := [2]float64{0.15, 0.03}
	if info.loadAvg != expectedLoadAvg {
		t.Fatalf("loadAvg = %v, want %v", info.loadAvg, expectedLoadAvg)
	}
}

func TestLoadDecayFactorsFollowSamplingInterval(t *testing.T) {
	tests := []struct {
		interval time.Duration
		want     [2]uint64
	}{
		{interval: 5 * time.Second, want: [2]uint64{1884, 2014}},
		{interval: 10 * time.Second, want: [2]uint64{1734, 1981}},
		{interval: 20 * time.Second, want: [2]uint64{1467, 1916}},
	}

	for _, test := range tests {
		if got := loadDecayFactors(test.interval); got != test.want {
			t.Errorf("loadDecayFactors(%s) = %v, want %v", test.interval, got, test.want)
		}
	}
}
