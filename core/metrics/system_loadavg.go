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
	"errors"
	"sync"

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
	enableCgroupV2 bool
	unsupportedV2  sync.Once
}

func init() {
	tracing.RegisterEventTracing("loadavg", newLoadavg)
}

// newLoadavg returns a new Collector exposing load average stats.
func newLoadavg() (*tracing.EventTracingAttr, error) {
	return &tracing.EventTracingAttr{
		TracingData: &loadavgCollector{
			enableCgroupV2: configSnapshot().Loadavg.EnableCgroupV2,
		},
		Flag: tracing.FlagMetric,
	}, nil
}

func (c *loadavgCollector) collectContainerV2(
	collect func() ([]*metric.Data, error),
) ([]*metric.Data, error) {
	loadavgs, err := collect()
	if !errors.Is(err, cgroupV2.ErrTaskIteratorNotSupported) {
		return loadavgs, err
	}

	c.unsupportedV2.Do(func() {
		log.WithError(err).Warn(
			"cgroup v2 container load metrics are unavailable; host load metrics remain enabled")
	})
	return nil, nil
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

func containerLoadavg() ([]*metric.Data, error) {
	n, err := netlink.New()
	if err != nil {
		return nil, err
	}
	defer n.Stop()

	containers, err := pod.ContainersByType(pod.ContainerTypeNormal | pod.ContainerTypeSidecar)
	if err != nil {
		return nil, err
	}

	return collectContainerLoadavgV1(
		containers,
		n.GetCpuLoad,
	)
}

func collectContainerLoadavgV1(
	containers map[string]*pod.Container,
	getCpuLoad func(string, string) (cadvisorV1.LoadStats, error),
) ([]*metric.Data, error) {
	loadavgs := []*metric.Data{}
	for _, container := range containers {
		cgroupPath := paths.Path(subsystem.SubsystemCPU, container.CgroupPath)
		stats, err := getCpuLoad(container.Hostname, cgroupPath)
		if err != nil {
			continue
		}

		loadavgs = append(loadavgs, containerLoadMetrics(
			container, stats.NrRunning, stats.NrUninterruptible)...)
	}

	return loadavgs, nil
}

func containerLoadavgV2() ([]*metric.Data, error) {
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

	loadavgs := []*metric.Data{}
	for _, container := range containers {
		stats, ok := statsByPath[container.CgroupPath]
		if !ok {
			continue
		}

		loadavgs = append(loadavgs, containerLoadMetrics(
			container, stats.NrRunning, stats.NrUninterruptible)...)
	}

	return loadavgs, err
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
	var containerLoadavgFn func() ([]*metric.Data, error)
	switch cgroups.CgroupMode() {
	case cgroups.Legacy, cgroups.Hybrid:
		// Preserve the historical best-effort semantics for cgroup v1:
		// container failures must not mark the loadavg collector as failed.
		containerLoadavgFn = func() ([]*metric.Data, error) {
			loadavgs, _ := containerLoadavg()
			return loadavgs, nil
		}
	case cgroups.Unified:
		if c.enableCgroupV2 {
			containerLoadavgFn = func() ([]*metric.Data, error) {
				return c.collectContainerV2(containerLoadavgV2)
			}
		}
	}
	return collectLoadavg(containerLoadavgFn, nodeLoadAvg)
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
		containerErr = err
	}

	data, nodeErr := nodeLoadavgFn()
	loadavgs = append(loadavgs, data...)

	return loadavgs, errors.Join(containerErr, nodeErr)
}
