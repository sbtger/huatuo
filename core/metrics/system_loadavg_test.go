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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"huatuo-bamai/internal/cgroups"
	cgroupV2 "huatuo-bamai/internal/cgroups/v2"
	"huatuo-bamai/internal/pod"
	"huatuo-bamai/internal/procfs"
	"huatuo-bamai/pkg/metric"

	cadvisorV1 "github.com/google/cadvisor/info/v1"
)

func TestParseHostRunnable(t *testing.T) {
	for _, tt := range []struct {
		name, raw string
		want      uint64
		wantErr   bool
	}{
		{"present", "cpu 1 2 3\nprocs_running 7\nprocs_blocked 9\n", 7, false},
		{"zero", "procs_running\t0", 0, false},
		{"missing", "procs_blocked 2\n", 0, true},
		{"prefix", "procs_running_other 7\n", 0, true},
		{"empty value", "procs_running\n", 0, true},
		{"negative", "procs_running -1\n", 0, true},
		{"invalid", "procs_running nope\n", 0, true},
		{"extra", "procs_running 1 2\n", 0, true},
		{"overflow", "procs_running 18446744073709551616\n", 0, true},
		{"long irq line", "intr " + strings.Repeat("0 ", 100_000) + "\nprocs_running 3\n", 3, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseHostRunnable([]byte(tt.raw))
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Fatalf("got %d, %v; want %d, error %v", got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestLoadavgFailureIsolation(t *testing.T) {
	originalRoot := filepath.Dir(procfs.DefaultPath())
	t.Cleanup(func() { procfs.RootPrefix(originalRoot) })
	failure := errors.New("netlink unavailable")
	for _, tt := range []struct {
		name         string
		mode         cgroups.Mode
		stat, avg    string
		containerErr error
		want         map[string]float64
		wantErr      bool
	}{
		{
			"legacy", cgroups.Legacy, "procs_running 4\n", "1 2 3 4/5 6\n", nil,
			map[string]float64{"nr_running": 4, "load1": 1, "load5": 2, "load15": 3, "container_nr_running": 2},
			false,
		},
		{
			"container failure", cgroups.Legacy, "procs_running 0\n", "1 2 3 4/5 6\n", failure,
			map[string]float64{"nr_running": 0, "load1": 1, "load5": 2, "load15": 3},
			true,
		},
		{
			"missing stat", cgroups.Legacy, "", "1 2 3 4/5 6\n", nil,
			map[string]float64{"load1": 1, "load5": 2, "load15": 3, "container_nr_running": 2},
			true,
		},
		{
			"missing average", cgroups.Legacy, "procs_running 4\n", "", nil,
			map[string]float64{"nr_running": 4, "container_nr_running": 2},
			true,
		},
		{
			"v2", cgroups.Unified, "procs_running 4\n", "1 2 3 4/5 6\n", nil,
			map[string]float64{"nr_running": 4, "load1": 1, "load5": 2, "load15": 3},
			false,
		},
		{
			"no cgroup", cgroups.Unavailable, "procs_running 4\n", "1 2 3 4/5 6\n", nil,
			map[string]float64{"nr_running": 4, "load1": 1, "load5": 2, "load15": 3},
			false,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			procfs.RootPrefix(root)
			if err := os.Mkdir(filepath.Join(root, "proc"), 0o755); err != nil {
				t.Fatal(err)
			}
			for name, raw := range map[string]string{"stat": tt.stat, "loadavg": tt.avg} {
				if raw != "" {
					if err := os.WriteFile(procfs.Path(name), []byte(raw), 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			called := false
			c := loadavgCollector{}
			data, err := c.update(tt.mode, func() ([]containerLoadSample, error) {
				called = true
				if tt.containerErr != nil {
					return nil, tt.containerErr
				}
				return []containerLoadSample{{vmstatTestContainer(""), 2, 0}}, nil
			}, nil)
			if called != (tt.mode == cgroups.Legacy) {
				t.Fatalf("container called = %v", called)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v", err)
			}
			if tt.containerErr != nil && !errors.Is(err, tt.containerErr) {
				t.Fatalf("lost error: %v", err)
			}
			if _, ok := tt.want["container_nr_running"]; ok {
				tt.want["container_nr_uninterruptible"] = 0
			}
			assertVMStatMetrics(t, data, tt.want)
		})
	}
}

func TestHostRunnableLive(t *testing.T) {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		t.Skipf("host procfs unavailable: %v", err)
	}
	if _, err := parseHostRunnable(raw); err != nil {
		t.Fatal(err)
	}
}

func TestLoadavgMergedHostContainerCoverage(t *testing.T) {
	originalRoot := filepath.Dir(procfs.DefaultPath())
	t.Cleanup(func() { procfs.RootPrefix(originalRoot) })
	readErr := errors.New("container sampling failed")
	for _, tt := range []struct {
		name       string
		mode       cgroups.Mode
		enabled    bool
		readErr    error
		missing    string
		wantReader string
		wantErr    bool
	}{
		{"legacy", cgroups.Legacy, true, nil, "", "v1", false},
		{"hybrid", cgroups.Hybrid, false, nil, "", "v1", false},
		{"hybrid failure", cgroups.Hybrid, true, readErr, "", "v1", true},
		{"v2 disabled", cgroups.Unified, false, nil, "", "", false},
		{"v2 enabled", cgroups.Unified, true, nil, "", "v2", false},
		{"v2 unsupported", cgroups.Unified, true, cgroupV2.ErrTaskIteratorNotSupported, "", "v2", false},
		{"v2 partial failure", cgroups.Unified, true, readErr, "", "v2", true},
		{"v2 missing stat", cgroups.Unified, true, nil, "stat", "v2", true},
		{"v2 missing average", cgroups.Unified, true, nil, "loadavg", "v2", true},
		{"unavailable", cgroups.Unavailable, true, nil, "", "", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			procfs.RootPrefix(t.TempDir())
			if err := os.MkdirAll(procfs.DefaultPath(), 0o755); err != nil {
				t.Fatal(err)
			}
			want := map[string]float64{}
			for name, raw := range map[string]string{"stat": "procs_running 4\n", "loadavg": "1 2 3 4/5 6\n"} {
				if name == tt.missing {
					continue
				}
				if err := os.WriteFile(procfs.Path(name), []byte(raw), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tt.missing != "stat" {
				want["nr_running"] = 4
			}
			if tt.missing != "loadavg" {
				want["load1"], want["load5"], want["load15"] = 1, 2, 3
			}
			called := ""
			read := func(reader string) ([]containerLoadSample, error) {
				if called != "" {
					t.Fatal("container reader called more than once")
				}
				called = reader
				return []containerLoadSample{{vmstatTestContainer(""), 2, 3}}, tt.readErr
			}
			c := loadavgCollector{enableCgroupV2: tt.enabled}
			data, err := c.update(tt.mode,
				func() ([]containerLoadSample, error) { return read("v1") },
				func() ([]containerLoadSample, error) { return read("v2") },
			)
			if called != tt.wantReader || (err != nil) != tt.wantErr {
				t.Fatalf("reader = %q, error = %v; want reader %q, error %v", called, err, tt.wantReader, tt.wantErr)
			}
			if tt.wantErr && tt.readErr != nil && !errors.Is(err, tt.readErr) {
				t.Fatalf("lost container error: %v", err)
			}
			if tt.wantReader != "" && !errors.Is(tt.readErr, cgroupV2.ErrTaskIteratorNotSupported) {
				want["container_nr_running"], want["container_nr_uninterruptible"] = 2, 3
			}
			assertVMStatMetrics(t, data, want)
		})
	}
}

func BenchmarkParseHostRunnable(b *testing.B) {
	raw := []byte("cpu 1 2 3 4 5 6 7 8 9 10\n" + strings.Repeat("cpu0 1 2 3 4 5 6 7 8 9 10\n", 256) + "intr " + strings.Repeat("0 ", 4096) + "\nprocs_running 4\n")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := parseHostRunnable(raw); err != nil {
			b.Fatal(err)
		}
	}
}

func TestContainerLoadMetrics(t *testing.T) {
	container := &pod.Container{
		Type:   pod.ContainerTypeNormal,
		Labels: map[string]any{"HostNamespace": "namespace"},
	}
	metrics := containerLoadMetrics(container, 2, 3)
	if len(metrics) != 2 {
		t.Fatalf("metric count = %d, want 2", len(metrics))
	}

	if metrics[0].Name() != "container_nr_running" || metrics[0].Value != 2 {
		t.Fatalf("running metric = %s %v, want container_nr_running 2",
			metrics[0].Name(), metrics[0].Value)
	}
	if metrics[1].Name() != "container_nr_uninterruptible" || metrics[1].Value != 3 {
		t.Fatalf("uninterruptible metric = %s %v, want container_nr_uninterruptible 3",
			metrics[1].Name(), metrics[1].Value)
	}
}

func TestCollectLoadavgReturnsHostAndPartialContainerMetrics(t *testing.T) {
	wantErr := errors.New("one container failed")
	containerMetric := metric.NewGaugeData(
		"container_load", 1, "container load", nil)
	hostMetric := metric.NewGaugeData("load1", 2, "host load", nil)

	got, err := collectLoadavg(
		func() ([]*metric.Data, error) {
			return []*metric.Data{containerMetric}, wantErr
		},
		func() ([]*metric.Data, error) {
			return []*metric.Data{hostMetric}, nil
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("collectLoadavg error = %v, want %v", err, wantErr)
	}
	if len(got) != 2 || got[0] != containerMetric || got[1] != hostMetric {
		t.Fatalf("collectLoadavg metrics = %v, want container and host metrics", got)
	}
}

func TestReadContainerLoadIgnoresUnsupportedIterator(t *testing.T) {
	collector := &loadavgCollector{enableCgroupV2: true}
	got, err := collector.readContainerLoad(cgroups.Unified, nil, func() ([]containerLoadSample, error) {
		return nil, cgroupV2.ErrTaskIteratorNotSupported
	})
	if err != nil {
		t.Fatalf("readContainerLoad() error = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Fatalf("readContainerLoad() samples = %v, want none", got)
	}
}

func TestReadContainerLoadPreservesRuntimeErrorAndPartialSamples(t *testing.T) {
	wantErr := errors.New("iterator read failed")
	wantSample := containerLoadSample{vmstatTestContainer(""), 2, 3}
	collector := &loadavgCollector{enableCgroupV2: true}

	got, err := collector.readContainerLoad(cgroups.Unified, nil, func() ([]containerLoadSample, error) {
		return []containerLoadSample{wantSample}, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("readContainerLoad() error = %v, want %v", err, wantErr)
	}
	if len(got) != 1 || got[0] != wantSample {
		t.Fatalf("readContainerLoad() samples = %v, want partial sample", got)
	}
}

func TestNewLoadavgBindsCgroupV2Config(t *testing.T) {
	original := configSnapshot()
	t.Cleanup(func() { Set(original) })

	cfg := &Config{}
	cfg.Loadavg.EnableCgroupV2 = true
	Set(cfg)
	attr, err := newLoadavg()
	if err != nil {
		t.Fatalf("newLoadavg() error = %v", err)
	}
	collector, ok := attr.TracingData.(*loadavgCollector)
	if !ok || !collector.enableCgroupV2 {
		t.Fatalf("newLoadavg() collector = %#v, want cgroup v2 enabled", attr.TracingData)
	}
}

func TestReadContainerLoadSamplesV1SilentlySkipsFailures(t *testing.T) {
	wantErr := errors.New("netlink failed")
	containers := map[string]*pod.Container{
		"good": {
			ID: "good", Hostname: "good-host", CgroupPath: "good",
			Labels: map[string]any{"HostNamespace": "namespace"},
		},
		"failed": {
			ID: "failed", Hostname: "failed-host", CgroupPath: "failed",
			Labels: map[string]any{"HostNamespace": "namespace"},
		},
		"gone": {
			ID: "gone", Hostname: "gone-host", CgroupPath: "gone",
			Labels: map[string]any{"HostNamespace": "namespace"},
		},
	}

	got, err := readContainerLoadSamplesV1(
		containers,
		func(name, _ string) (cadvisorV1.LoadStats, error) {
			switch name {
			case "good-host":
				return cadvisorV1.LoadStats{NrRunning: 2, NrUninterruptible: 3}, nil
			case "failed-host":
				return cadvisorV1.LoadStats{}, wantErr
			default:
				return cadvisorV1.LoadStats{}, errors.New("cgroup disappeared")
			}
		},
	)
	if err != nil {
		t.Fatalf("readContainerLoadSamplesV1 error = %v, want nil", err)
	}
	if len(got) != 1 {
		t.Fatalf("sample count = %d, want 1", len(got))
	}
	if got[0].container != containers["good"] || got[0].running != 2 || got[0].uninterruptible != 3 {
		t.Fatalf("samples = %v, want good container running 2 and uninterruptible 3", got)
	}
}
