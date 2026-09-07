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

package collector

import (
	"errors"
	"testing"
	"time"

	"huatuo-bamai/internal/cgroups"
	"huatuo-bamai/internal/cgroups/stats"
	"huatuo-bamai/internal/pod"
	"huatuo-bamai/pkg/metric"
)

type cpuUsageCgroup struct {
	cgroups.Cgroup
	usage stats.CpuUsage
	err   error
}

func (c *cpuUsageCgroup) CpuUsage(string) (*stats.CpuUsage, error) {
	return &c.usage, c.err
}

func TestCPUUtilCollectorHostMetrics(t *testing.T) {
	c := cpuUtilCollector{
		cgroup:   &cpuUsageCgroup{},
		numCores: 8,
		cpuDataCache: cpuUtilStat{
			lastTimestamp: time.Now(),
			usrUtil:       12,
			sysUtil:       3,
			totalUtil:     15,
		},
	}
	metrics, err := c.updateHostDataCache()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]float64{"usr": 12, "sys": 3, "total": 15}
	if len(metrics) != len(want) {
		t.Fatalf("got %d metrics, want %d", len(metrics), len(want))
	}
	for _, m := range metrics {
		value, ok := want[m.Name()]
		if !ok || m.Value != value || m.Type() != metric.MetricTypeGauge {
			t.Fatalf("unexpected metric: %s = %v, type %v", m.Name(), m.Value, m.Type())
		}
		labels := m.Labels()
		if len(labels) != 2 {
			t.Fatalf("unexpected host labels: %v", labels)
		}
		for _, key := range []string{"host", "region"} {
			if _, ok := labels[key]; !ok {
				t.Fatalf("missing label %q: %v", key, labels)
			}
		}
		delete(want, m.Name())
	}
}

func BenchmarkCPUUtilCollectorHostMetrics(b *testing.B) {
	c := cpuUtilCollector{cgroup: &cpuUsageCgroup{}, numCores: 8}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := c.updateHostDataCache(); err != nil {
			b.Fatal(err)
		}
	}
}

func TestCPUUtilCollectorFailureIsolation(t *testing.T) {
	discoveryErr := errors.New("kubelet unavailable")
	usageErr := errors.New("cpu accounting unavailable")
	for _, tt := range []struct {
		name                   string
		discoveryErr, usageErr error
		wantMetrics            int
	}{
		{"no containers", nil, nil, 3},
		{"discovery fails", discoveryErr, nil, 3},
		{"usage fails", nil, usageErr, 0},
		{"both fail", discoveryErr, usageErr, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := cpuUtilCollector{cgroup: &cpuUsageCgroup{err: tt.usageErr}, numCores: 8}
			metrics, err := c.update(func() (map[string]*pod.Container, error) {
				return nil, tt.discoveryErr
			})
			if tt.discoveryErr == nil && tt.usageErr == nil && err != nil {
				t.Fatal(err)
			}
			for _, wantErr := range []error{tt.discoveryErr, tt.usageErr} {
				if wantErr != nil && !errors.Is(err, wantErr) {
					t.Errorf("error = %v, want %v", err, wantErr)
				}
			}
			if len(metrics) != tt.wantMetrics {
				t.Fatalf("got %d metrics, want %d", len(metrics), tt.wantMetrics)
			}
			for _, m := range metrics {
				if m.Name() == "cores" {
					t.Fatal("host capacity metric must not be exported")
				}
			}
		})
	}
}

func TestCPUUtilCollectorUpdateDataCacheCounterRegression(t *testing.T) {
	tests := []struct {
		name    string
		current stats.CpuUsage
	}{
		{
			name:    "total usage regresses",
			current: stats.CpuUsage{Usage: 9, User: 6, System: 4},
		},
		{
			name:    "user usage regresses",
			current: stats.CpuUsage{Usage: 10, User: 5, System: 4},
		},
		{
			name:    "system usage regresses",
			current: stats.CpuUsage{Usage: 10, User: 6, System: 3},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lastTimestamp := time.Now().Add(-2 * time.Second)
			cache := cpuUtilStat{
				lastUsage:     stats.CpuUsage{Usage: 10, User: 6, System: 4},
				lastTimestamp: lastTimestamp,
				totalUtil:     11,
				usrUtil:       22,
				sysUtil:       33,
			}
			collector := cpuUtilCollector{
				cgroup: &cpuUsageCgroup{usage: tt.current},
			}

			if err := collector.updateDataCache(&cache, nil, 1); err != nil {
				t.Fatalf("updateDataCache() error = %v", err)
			}
			if cache.lastUsage != tt.current {
				t.Fatalf("last usage = %+v, want %+v", cache.lastUsage, tt.current)
			}
			if !cache.lastTimestamp.After(lastTimestamp) {
				t.Fatalf("last timestamp = %v, want after %v", cache.lastTimestamp, lastTimestamp)
			}
			if cache.totalUtil != 11 || cache.usrUtil != 22 || cache.sysUtil != 33 {
				t.Fatalf(
					"utilization changed after counter regression: total=%v user=%v system=%v",
					cache.totalUtil,
					cache.usrUtil,
					cache.sysUtil,
				)
			}
		})
	}
}
