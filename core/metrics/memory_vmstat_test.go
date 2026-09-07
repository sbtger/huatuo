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
	"huatuo-bamai/internal/matcher"
	"huatuo-bamai/internal/pod"
	"huatuo-bamai/internal/procfs"
	"huatuo-bamai/internal/utils/parseutil"
	"huatuo-bamai/pkg/metric"

	"github.com/pelletier/go-toml"
)

func shippedVMStatConfig(t *testing.T) *Config {
	t.Helper()
	data, err := os.ReadFile("../../huatuo-bamai.conf")
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct{ MetricCollector Config }
	if err := toml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	return &cfg.MetricCollector
}

func TestVMStatShippedSlabFilters(t *testing.T) {
	cfg := shippedVMStatConfig(t)
	f, err := matcher.NewValueMatcher(cfg.Vmstat.IncludedOnContainer, cfg.Vmstat.ExcludedOnContainer)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"slab_reclaimable":         false,
		"slab_unreclaimable":       false,
		"active_anon":              true,
		"total_slab_reclaimable":   false,
		"total_slab_unreclaimable": false,
		"total_active_anon":        false,
		"unsupported_field":        false,
	} {
		if got := f.Match(name); got != want {
			t.Errorf("Match(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestVMStatShippedOptionalFilters(t *testing.T) {
	cfg := shippedVMStatConfig(t)
	for _, scope := range []struct {
		name, include, exclude string
	}{
		{"host", cfg.Vmstat.IncludedOnHost, cfg.Vmstat.ExcludedOnHost},
		{"container", cfg.Vmstat.IncludedOnContainer, cfg.Vmstat.ExcludedOnContainer},
	} {
		t.Run(scope.name, func(t *testing.T) {
			f, err := matcher.NewValueMatcher(scope.include, scope.exclude)
			if err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"pgfault", "pgmajfault", "thp_fault_alloc", "thp_collapse_alloc", "numa_pages_migrated"} {
				want := scope.name == "host" && name == "numa_pages_migrated"
				if got := f.Match(name); got != want {
					t.Errorf("Match(%q) = %v, want %v", name, got, want)
				}
				if scope.name == "container" && f.Match("total_"+name) {
					t.Errorf("shipped filter includes total_%s", name)
				}
			}
		})
	}
}

// Explicit test filters exercise existing collection without widening defaults.
func configuredVMStatConfig(t *testing.T) *Config {
	t.Helper()
	cfg := shippedVMStatConfig(t)
	cfg.Vmstat.IncludedOnHost += "|pgfault|pgmajfault|thp_fault_alloc|thp_collapse_alloc"
	cfg.Vmstat.IncludedOnContainer += "|slab_reclaimable|slab_unreclaimable|pgfault|pgmajfault|thp_fault_alloc|thp_collapse_alloc|numa_pages_migrated"
	return cfg
}

func TestVMStatHostPageFaults(t *testing.T) {
	originalConfig := configSnapshot()
	originalRoot := filepath.Dir(procfs.DefaultPath())
	t.Cleanup(func() {
		Set(originalConfig)
		procfs.RootPrefix(originalRoot)
	})
	Set(configuredVMStatConfig(t))
	root := t.TempDir()
	procfs.RootPrefix(root)
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, raw string
		want      map[string]float64
	}{
		{"present", "pgfault 123\npgmajfault 0\n", map[string]float64{"pgfault": 123, "pgmajfault": 0}},
		{"missing", "pgfault 124\n", map[string]float64{"pgfault": 124}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(procfs.Path("vmstat"), []byte(tt.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			c := memoryVmStat{}
			metrics, err := c.hostVmstat()
			if err != nil {
				t.Fatal(err)
			}
			if len(metrics) != len(tt.want) {
				t.Fatalf("got %d metrics, want %d", len(metrics), len(tt.want))
			}
			for _, m := range metrics {
				value, ok := tt.want[m.Name()]
				if !ok || m.Value != value {
					t.Errorf("unexpected metric %s = %v", m.Name(), m.Value)
				}
			}
		})
	}
}

type vmstatFileCgroup struct{ cgroups.Cgroup }

func (*vmstatFileCgroup) MemoryStatRaw(path string) (map[string]uint64, error) {
	return parseutil.RawKV(filepath.Join(path, "memory.stat"))
}

func vmstatFixture(t *testing.T, host string) string {
	t.Helper()
	originalConfig := configSnapshot()
	originalRoot := filepath.Dir(procfs.DefaultPath())
	t.Cleanup(func() {
		Set(originalConfig)
		procfs.RootPrefix(originalRoot)
	})
	Set(configuredVMStatConfig(t))
	root := t.TempDir()
	procfs.RootPrefix(root)
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if host != "" {
		if err := os.WriteFile(procfs.Path("vmstat"), []byte(host), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func vmstatTestContainer(root string) *pod.Container {
	return &pod.Container{
		ID: "vmstat-test", Name: "workload", CgroupPath: root,
		Type:   pod.ContainerTypeNormal,
		Labels: map[string]any{"HostNamespace": "test"},
	}
}

func TestVMStatFailureIsolation(t *testing.T) {
	discoveryErr := errors.New("kubelet unavailable")
	for _, tt := range []struct {
		name, host   string
		discoveryErr error
	}{
		{"both succeed", "pgfault 12\n", nil},
		{"discovery fails", "pgfault 12\n", discoveryErr},
		{"host fails", "", nil},
		{"both fail", "", discoveryErr},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := vmstatFixture(t, tt.host)
			if err := os.WriteFile(filepath.Join(root, "memory.stat"), []byte("pgfault 5\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			c := memoryVmStat{cgroup: &vmstatFileCgroup{}}
			metrics, err := c.update(func() (map[string]*pod.Container, error) {
				return map[string]*pod.Container{"test": vmstatTestContainer(root)}, tt.discoveryErr
			})
			if tt.discoveryErr != nil && !errors.Is(err, tt.discoveryErr) {
				t.Errorf("error = %v, want discovery error", err)
			}
			if tt.host == "" && !errors.Is(err, os.ErrNotExist) {
				t.Errorf("error = %v, want missing host file error", err)
			}
			if tt.host != "" && tt.discoveryErr == nil && err != nil {
				t.Fatal(err)
			}
			want := map[string]float64{}
			if tt.host != "" {
				want["pgfault"] = 12
			}
			if tt.discoveryErr == nil {
				want["container_pgfault"] = 5
			}
			assertVMStatMetrics(t, metrics, want)
		})
	}
}

func assertVMStatMetrics(t *testing.T, metrics []*metric.Data, want map[string]float64) {
	t.Helper()
	if len(metrics) != len(want) {
		t.Fatalf("got %d metrics, want %d", len(metrics), len(want))
	}
	for _, m := range metrics {
		value, ok := want[m.Name()]
		if !ok || m.Value != value || m.Type() != metric.MetricTypeGauge {
			t.Errorf("unexpected metric %s = %v, type %v", m.Name(), m.Value, m.Type())
		}
		if strings.HasPrefix(m.Name(), "container_") && m.Labels()["container_name"] != "workload" {
			t.Errorf("unexpected container labels: %v", m.Labels())
		}
		delete(want, m.Name())
	}
}

func TestVMStatContainerMemoryStatFields(t *testing.T) {
	for _, tt := range []struct {
		name, raw string
		want      map[string]float64
	}{
		{
			"NUMA migration", "numa_pages_migrated 17\nnuma_hit 9\ntotal_numa_pages_migrated 99\n",
			map[string]float64{"container_numa_pages_migrated": 17},
		},
		{
			"THP fields", "thp_fault_alloc 3\nthp_collapse_alloc 0\nthp_fault_fallback 7\ntotal_thp_fault_alloc 9\n",
			map[string]float64{"container_thp_fault_alloc": 3, "container_thp_collapse_alloc": 0},
		},
		{
			"v1 without slab", "pgfault 13\npgmajfault 0\ntotal_pgfault 20\ntotal_pgmajfault 2\n",
			map[string]float64{"container_pgfault": 13, "container_pgmajfault": 0},
		},
		{
			"v2 with slab", "pgfault 21\npgmajfault 1\nslab_reclaimable 8192\nslab_unreclaimable 0\n",
			map[string]float64{"container_pgfault": 21, "container_pgmajfault": 1, "container_slab_reclaimable": 8192, "container_slab_unreclaimable": 0},
		},
		{
			"missing fields", "active_anon 4096\n",
			map[string]float64{"container_active_anon": 4096},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := vmstatFixture(t, "")
			if err := os.WriteFile(filepath.Join(root, "memory.stat"), []byte(tt.raw), 0o600); err != nil {
				t.Fatal(err)
			}
			c := memoryVmStat{cgroup: &vmstatFileCgroup{}}
			metrics, err := c.containerVmstat(func() (map[string]*pod.Container, error) {
				return map[string]*pod.Container{"test": vmstatTestContainer(root)}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			assertVMStatMetrics(t, metrics, tt.want)
		})
	}
}

func TestVMStatShippedFiltersKeepExistingOutput(t *testing.T) {
	root := vmstatFixture(t, "nr_slab_reclaimable 2\nnuma_pages_migrated 3\npgfault 4\npgmajfault 0\nthp_fault_alloc 5\nthp_collapse_alloc 6\n")
	Set(shippedVMStatConfig(t))
	raw := "active_anon 4096\nslab_reclaimable 7\nslab_unreclaimable 8\npgfault 9\npgmajfault 0\nthp_fault_alloc 10\nthp_collapse_alloc 11\nnuma_pages_migrated 12\n"
	if err := os.WriteFile(filepath.Join(root, "memory.stat"), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	c := memoryVmStat{cgroup: &vmstatFileCgroup{}}
	metrics, err := c.update(func() (map[string]*pod.Container, error) {
		return map[string]*pod.Container{"test": vmstatTestContainer(root)}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	assertVMStatMetrics(t, metrics, map[string]float64{
		"nr_slab_reclaimable":   2,
		"numa_pages_migrated":   3,
		"container_active_anon": 4096,
	})
}

func TestVMStatFilterFailureIsolation(t *testing.T) {
	for _, scope := range []string{"host", "container"} {
		t.Run(scope, func(t *testing.T) {
			root := vmstatFixture(t, "pgfault 12\n")
			if err := os.WriteFile(filepath.Join(root, "memory.stat"), []byte("pgfault 5\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := configSnapshot().Clone()
			want := map[string]float64{"pgfault": 12}
			if scope == "host" {
				cfg.Vmstat.IncludedOnHost = "["
				want = map[string]float64{"container_pgfault": 5}
			} else {
				cfg.Vmstat.IncludedOnContainer = "["
			}
			Set(cfg)
			c := memoryVmStat{cgroup: &vmstatFileCgroup{}}
			metrics, err := c.update(func() (map[string]*pod.Container, error) {
				return map[string]*pod.Container{"test": vmstatTestContainer(root)}, nil
			})
			if err == nil || !strings.Contains(err.Error(), scope+" filter") {
				t.Fatalf("error = %v, want %s filter error", err, scope)
			}
			assertVMStatMetrics(t, metrics, want)
		})
	}
}
