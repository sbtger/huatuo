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
	"huatuo-bamai/internal/procfs"
	"huatuo-bamai/pkg/metric"
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
			data, err := c.update(tt.mode, func() ([]*metric.Data, error) {
				called = true
				if tt.containerErr != nil {
					return nil, tt.containerErr
				}
				return []*metric.Data{metric.NewContainerGaugeData(vmstatTestContainer(""), "nr_running", 2, "test", nil)}, nil
			})
			if called != (tt.mode == cgroups.Legacy) {
				t.Fatalf("container called = %v", called)
			}
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v", err)
			}
			if tt.containerErr != nil && !errors.Is(err, tt.containerErr) {
				t.Fatalf("lost error: %v", err)
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
