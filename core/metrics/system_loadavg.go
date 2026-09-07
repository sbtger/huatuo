// Copyright 2025, 2026 The HuaTuo Authors
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
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"
	"sync"
	"time"

	"huatuo-bamai/internal/cgroups"
	"huatuo-bamai/internal/cgroups/paths"
	"huatuo-bamai/internal/cgroups/subsystem"
	cgroupV2 "huatuo-bamai/internal/cgroups/v2"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/internal/pod"
	"huatuo-bamai/internal/procfs"
	"huatuo-bamai/pkg/metric"
	"huatuo-bamai/pkg/tracing"

	cadvisorV1 "github.com/google/cadvisor/info/v1"
	"github.com/google/cadvisor/utils/cpuload/netlink"
)

type loadavgCollector struct {
	sampleInterval            time.Duration
	enableCgroupV2            bool
	enableHostUninterruptible bool
	unsupportedHost           sync.Once
	unsupportedV2             sync.Once
	mu                        sync.Mutex
	sampling                  bool
	sampledAt                 time.Time
	sampledData               []*metric.Data
	sampledErr                error
	averages                  map[containerLoadKey]containerLoadAverage
}

func init() {
	tracing.RegisterEventTracing("loadavg", newLoadavg)
}

// newLoadavg returns a new Collector exposing load average stats.
func newLoadavg() (*tracing.EventTracingAttr, error) {
	cfg := configSnapshot().Loadavg
	// The three-interval expiry must also fit in time.Duration.
	const maxIntervalSeconds = math.MaxInt64 / int64(time.Second) / 3
	if cfg.Interval < 0 || cfg.Interval > maxIntervalSeconds {
		return nil, fmt.Errorf("loadavg interval must be between 0 and %d seconds (0 uses the default)", maxIntervalSeconds)
	}
	return &tracing.EventTracingAttr{
		TracingData: &loadavgCollector{
			sampleInterval:            time.Duration(cfg.Interval) * time.Second,
			enableCgroupV2:            cfg.EnableCgroupV2,
			enableHostUninterruptible: cfg.EnableHostUninterruptible,
		},
		Interval: 5,
		Flag:     tracing.FlagMetric | tracing.FlagTracing,
	}, nil
}

// Load average of last 1, 5, 15 minutes.
// See linux kernel Documentation/filesystems/proc.rst
func nodeLoadAvg() ([]*metric.Data, error) {
	fs, err := procfs.NewDefaultFS()
	if err != nil {
		return nil, err
	}

	load, err := fs.LoadAvg()
	if err != nil {
		return nil, err
	}

	return []*metric.Data{
		metric.NewGaugeData("load1", load.Load1, "system load average, 1 minute", nil),
		metric.NewGaugeData("load5", load.Load5, "system load average, 5 minutes", nil),
		metric.NewGaugeData("load15", load.Load15, "system load average, 15 minutes", nil),
	}, nil
}

func readContainerLoadV1() ([]containerLoadSample, error) {
	n, err := netlink.New()
	if err != nil {
		return nil, err
	}
	defer n.Stop()

	containers, err := pod.ContainersByType(pod.ContainerTypeNormal | pod.ContainerTypeSidecar)
	if err != nil {
		return nil, err
	}

	return readContainerLoadSamplesV1(
		containers,
		n.GetCpuLoad,
	)
}

func readContainerLoadSamplesV1(
	containers map[string]*pod.Container,
	getCpuLoad func(string, string) (cadvisorV1.LoadStats, error),
) ([]containerLoadSample, error) {
	samples := make([]containerLoadSample, 0, len(containers))
	for _, container := range containers {
		cgroupPath := paths.Path(subsystem.SubsystemCPU, container.CgroupPath)
		stats, err := getCpuLoad(container.Hostname, cgroupPath)
		if err != nil {
			continue
		}

		samples = append(samples, containerLoadSample{container, stats.NrRunning, stats.NrUninterruptible})
	}

	return samples, nil
}

func readContainerLoadV2() ([]containerLoadSample, error) {
	containers, err := pod.ContainersByType(pod.ContainerTypeNormal | pod.ContainerTypeSidecar)
	if err != nil {
		return nil, err
	}

	paths := make([]string, 0, len(containers))
	for _, container := range containers {
		paths = append(paths, container.CgroupPath)
	}
	statsByPath, err := cgroupV2.SharedLoadStats(
		cgroupV2.LoadStatsConsumerLoadavg, paths)

	samples := make([]containerLoadSample, 0, len(containers))
	for _, container := range containers {
		stats, ok := statsByPath[container.CgroupPath]
		if !ok {
			continue
		}

		samples = append(samples, containerLoadSample{container, stats.NrRunning, stats.NrUninterruptible})
	}

	return samples, err
}

func containerLoadMetrics(
	container *pod.Container,
	nrRunning uint64,
	nrUninterruptible uint64,
) []*metric.Data {
	return []*metric.Data{
		metric.NewContainerGaugeData(container,
			"nr_running", float64(nrRunning), "nr_running of container", nil),
		metric.NewContainerGaugeData(container,
			"nr_uninterruptible", float64(nrUninterruptible),
			"nr_uninterruptible of container", nil),
	}
}

func (c *loadavgCollector) Update() ([]*metric.Data, error) {
	data, err, sampling := c.cachedContainerLoad(time.Now())
	if sampling {
		return collectLoadavg(func() ([]*metric.Data, error) { return data, err }, nodeLoadMetrics)
	}
	return c.update(cgroups.CgroupMode(), readContainerLoadV1, readContainerLoadV2)
}

func (c *loadavgCollector) update(
	mode cgroups.Mode,
	readV1, readV2 func() ([]containerLoadSample, error),
) ([]*metric.Data, error) {
	return collectLoadavg(func() ([]*metric.Data, error) {
		samples, err := c.readContainerLoad(mode, readV1, readV2)
		return instantaneousContainerLoad(samples), err
	}, nodeLoadMetrics)
}

// Scrape fallback and background sampling share the same readers and policy.
func (c *loadavgCollector) readContainerLoad(
	mode cgroups.Mode,
	readV1, readV2 func() ([]containerLoadSample, error),
) ([]containerLoadSample, error) {
	switch mode {
	case cgroups.Legacy, cgroups.Hybrid:
		return readV1()
	case cgroups.Unified:
		if c.enableCgroupV2 {
			samples, err := readV2()
			if errors.Is(err, cgroupV2.ErrTaskIteratorNotSupported) {
				c.unsupportedV2.Do(func() {
					log.WithError(err).Warn(
						"cgroup v2 container load metrics are unavailable; host load metrics remain enabled")
				})
				return nil, nil
			}
			return samples, err
		}
	}
	return nil, nil
}

func nodeLoadMetrics() ([]*metric.Data, error) {
	var loadavgs []*metric.Data
	var errs []error
	data, err := nodeLoadAvg()
	loadavgs = append(loadavgs, data...)
	if err != nil {
		errs = append(errs, fmt.Errorf("read host load average: %w", err))
	}

	raw, err := os.ReadFile(procfs.Path("stat"))
	if err == nil {
		var running uint64
		running, err = parseHostRunnable(raw)
		if err == nil {
			loadavgs = append(loadavgs, metric.NewGaugeData("nr_running", float64(running),
				"number of running or runnable host tasks", nil))
		}
	}
	if err != nil {
		errs = append(errs, fmt.Errorf("read host runnable tasks: %w", err))
	}
	return loadavgs, errors.Join(errs...)
}

func collectLoadavg(
	containerLoadavgFn func() ([]*metric.Data, error),
	nodeLoadavgFn func() ([]*metric.Data, error),
) ([]*metric.Data, error) {
	var loadavgs []*metric.Data
	var containerErr error
	if containerLoadavgFn != nil {
		containersLoads, err := containerLoadavgFn()
		loadavgs = append(loadavgs, containersLoads...)
		if err != nil {
			containerErr = fmt.Errorf("read container load: %w", err)
		}
	}

	data, nodeErr := nodeLoadavgFn()
	loadavgs = append(loadavgs, data...)

	return loadavgs, errors.Join(containerErr, nodeErr)
}

func parseHostRunnable(raw []byte) (uint64, error) {
	// Parse only this field: unrelated CPU/IRQ columns can be very large.
	// A missing field must not become a synthetic zero.
	for len(raw) > 0 {
		var line []byte
		line, raw, _ = bytes.Cut(raw, []byte{'\n'})
		if !bytes.HasPrefix(line, []byte("procs_running")) {
			continue
		}
		fields := bytes.Fields(line)
		if len(fields) == 0 || !bytes.Equal(fields[0], []byte("procs_running")) {
			continue
		}
		if len(fields) != 2 {
			return 0, fmt.Errorf("invalid procs_running field: %q", line)
		}
		value, err := strconv.ParseUint(string(fields[1]), 10, 64)
		if err != nil {
			return 0, err
		}
		return value, nil
	}
	return 0, errors.New("procs_running missing from proc stat")
}
