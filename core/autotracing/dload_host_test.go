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
	"os"
	"testing"
	"time"

	"huatuo-bamai/internal/cgroups/stats"
	"huatuo-bamai/internal/pod"
)

func TestDloadHostThresholdIndependent(t *testing.T) {
	cfg := &Config{}
	cfg.Dload.Interval = 10
	cfg.Dload.IntervalTracing = 30
	cfg.Dload.ThresholdLoad = 100
	cfg.Dload.EnableHost = true
	cfg.Dload.HostThresholdLoad = 2
	d, err := newDloadTracing(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	d.host.dLoad[0] = 3
	if !d.hostThreshold.shouldTrace(&d.host, now) || d.shouldTrace(&d.host, now) {
		t.Fatal("host threshold shares container threshold")
	}
	d.host.lastTraceAt = now
	if d.hostThreshold.shouldTrace(&d.host, now.Add(time.Second)) {
		t.Fatal("host cooldown ignored")
	}
	if !d.hostThreshold.shouldTrace(&d.host, now.Add(30*time.Second)) {
		t.Fatal("host cooldown never expires")
	}
	cfg.Dload.HostThresholdLoad = -1
	if _, err := newDloadTracing(cfg); err == nil {
		t.Fatal("negative host threshold accepted")
	}
}

func TestDloadHostIncludesThreads(t *testing.T) {
	tasks, err := cgroupHostTasks(taskScopeHost, "")
	if err != nil {
		t.Fatal(err)
	}
	threads, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]bool)
	for _, tid := range tasks {
		seen[fmt.Sprint(tid)] = true
	}
	if !seen[fmt.Sprint(os.Getpid())] || len(threads) < 2 {
		t.Fatal("host threads not enumerated")
	}
	var count int
	for _, thread := range threads {
		if seen[thread.Name()] {
			count++
		}
	}
	if count < 2 {
		t.Fatal("only process leader enumerated")
	}
}

func TestDloadStackCapturePerTick(t *testing.T) {
	for _, result := range []struct {
		name  string
		stack string
		err   error
	}{
		{name: "stacks", stack: "host stacks"},
		{name: "empty"},
		{name: "error", err: errors.New("capture failed")},
	} {
		t.Run(result.name, func(t *testing.T) {
			hostCalls, containerCalls := 0, 0
			dump := func(scope taskScope, path string, all bool) (string, error) {
				if all {
					t.Fatal("debug capture unexpectedly enabled")
				}
				if scope == taskScopeHost {
					hostCalls++
					return result.stack, result.err
				}
				containerCalls++
				return path, nil
			}
			for tick := 1; tick <= 2; tick++ {
				capture := dloadStackCapture{dump: dump}
				for range 2 {
					stack, err := capture.capture(taskScopeHost, "", false)
					if stack != result.stack || !errors.Is(err, result.err) {
						t.Fatal("host result changed within tick", stack, err)
					}
				}
				for _, path := range []string{"container-a", "container-b"} {
					stack, err := capture.capture(taskScopeCgroup, path, false)
					if err != nil || stack != path {
						t.Fatal("container stacks were reused", stack, err)
					}
				}
				if hostCalls != tick || containerCalls != 2*tick {
					t.Fatal("unexpected dump counts", hostCalls, containerCalls)
				}
			}
		})
	}
}

func BenchmarkDloadSharedHostStack(b *testing.B) {
	dump := func(taskScope, string, bool) (string, error) { return "host stack", nil }
	b.ReportAllocs()
	for b.Loop() {
		capture := dloadStackCapture{dump: dump}
		_, _ = capture.capture(taskScopeHost, "", false)
		_, _ = capture.capture(taskScopeHost, "", false)
	}
}

func TestDloadBothScopesShareHostCapture(t *testing.T) {
	cfg := &Config{}
	cfg.Dload.Interval = 10
	cfg.Dload.EnableHost = true
	cfg.Dload.EnableDebug = true
	d, err := newDloadTracing(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d.hostStats = &stats.LoadStats{NrUninterruptible: 2}
	hostCalls, containerCalls := 0, 0
	stacks := dloadStackCapture{dump: func(scope taskScope, _ string, _ bool) (string, error) {
		if scope == taskScopeHost {
			hostCalls++
			return "host stacks", nil
		}
		containerCalls++
		return "container stacks;", nil
	}}
	now := time.Now()
	d.traceHost(now, &stacks)
	container := &containerDloadInfo{container: &pod.Container{ID: "container"}}
	if err := d.buildAndSave(container, *d.hostStats, &stacks); err != nil {
		t.Fatal(err)
	}
	if hostCalls != 1 || containerCalls != 1 || !d.host.lastTraceAt.Equal(now) {
		t.Fatal("independent triggers did not share host capture", hostCalls, containerCalls)
	}
}
