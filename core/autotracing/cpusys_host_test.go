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
	"strings"
	"testing"
	"time"
)

func TestCPUHostAdditionalTriggers(t *testing.T) {
	t.Parallel()
	now := time.Unix(1000, 0)
	state := cpuSysState{userPercent: 80, userPercentDelta: 60, totalPercent: 95, totalPercentDelta: 65}
	tracer := cpuSysTracing{
		threshold:        cpuSysThreshold{usage: 45, delta: 20},
		userThreshold:    cpuSysThreshold{usage: 75, delta: 45},
		totalThreshold:   cpuSysThreshold{usage: 90, delta: 55},
		minTraceInterval: time.Minute,
	}
	if tracer.shouldTrace(&state, now) {
		t.Fatal("new triggers must default off")
	}
	tracer.enableUser = true
	if !tracer.shouldTrace(&state, now) {
		t.Fatal("user trigger missing")
	}
	tracer.enableUser = false
	tracer.enableTotal = true
	if !tracer.shouldTrace(&state, now) {
		t.Fatal("total trigger missing")
	}
	tracer.lastTraceAt = now.Add(-time.Second)
	if tracer.shouldTrace(&state, now) {
		t.Fatal("total trigger bypassed shared cooldown")
	}
	tracer.lastTraceAt = now.Add(-time.Minute)
	if !tracer.shouldTrace(&state, now) {
		t.Fatal("cooldown did not expire")
	}
	tracer.totalThreshold.usage = 95
	if tracer.shouldTrace(&state, now) {
		t.Fatal("equal usage threshold must not trigger")
	}
	tracer.totalThreshold.usage = 90
	tracer.totalThreshold.delta = 65
	if tracer.shouldTrace(&state, now) {
		t.Fatal("equal delta threshold must not trigger")
	}
}

func TestCPUHostAdditionalPercentages(t *testing.T) {
	t.Parallel()
	var state cpuSysState
	inputs := []string{
		"cpu 0 0 0 0 0 0 0 0\n",
		"cpu 10 0 10 70 5 2 1 2\n",
		"cpu 90 0 20 75 6 3 2 4\n",
	}
	for i, input := range inputs {
		usage, err := parseCPUUsage(strings.NewReader(input))
		if err != nil {
			t.Fatal(err)
		}
		if got := state.update(usage); got != (i > 0) {
			t.Fatalf("sample %d valid=%v", i, got)
		}
	}
	if state.userPercent != 80 || state.userPercentDelta != 70 ||
		state.totalPercent != 92 || state.totalPercentDelta != 69 ||
		state.systemPercent != 10 || state.systemPercentDelta != 0 {
		t.Fatalf("wrong percentages: %+v", state)
	}
	// New counters must reset their percentages instead of underflowing.
	usage := state.previousUsage
	usage.user = 0
	usage.total += 100
	if state.update(usage) || state.userPercent != 0 || state.totalPercentDelta != 0 {
		t.Fatalf("rollback was not reset: %+v", state)
	}
}

func TestCPUHostAdditionalConfig(t *testing.T) {
	previous := configSnapshot()
	defer Set(previous)
	cfg := &Config{}
	cfg.CPUSys.Interval = 1
	cfg.CPUSys.IntervalTracing = 60
	cfg.CPUSys.RunTracingToolTimeout = 1
	cfg.CPUSys.EnableUser = true
	cfg.CPUSys.EnableTotal = true
	cfg.CPUSys.UserThreshold = 75
	cfg.CPUSys.DeltaUserThreshold = 45
	cfg.CPUSys.UsageThreshold = 90
	cfg.CPUSys.DeltaUsageThreshold = 55
	Set(cfg)
	attr, err := newCPUSys()
	if err != nil {
		t.Fatal(err)
	}
	c := attr.TracingData.(*cpuSysTracing)
	if !c.enableUser || !c.enableTotal || c.userThreshold.usage != 75 || c.totalThreshold.delta != 55 {
		t.Fatalf("new configuration not bound: %+v", c)
	}
	cfg.CPUSys.UserThreshold = 101
	Set(cfg)
	if _, err := newCPUSys(); err == nil {
		t.Fatal("invalid user threshold accepted")
	}
	cfg.CPUSys.UserThreshold = 75
	cfg.CPUSys.DeltaUsageThreshold = -1
	Set(cfg)
	if _, err := newCPUSys(); err == nil {
		t.Fatal("invalid total delta accepted")
	}
}

func BenchmarkCPUHostStateUpdate(b *testing.B) {
	var state cpuSysState
	usage := cpuUsage{}
	b.ReportAllocs()
	for b.Loop() {
		usage.user += 80
		usage.system += 10
		usage.busy += 92
		usage.total += 100
		state.update(usage)
	}
}
