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

	"huatuo-bamai/internal/cgroups"
	"huatuo-bamai/internal/cgroups/stats"
	cgroupV2 "huatuo-bamai/internal/cgroups/v2"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/internal/pod"
)

func (c *loadavgCollector) readLoadSample(
	mode cgroups.Mode,
	readV1, readV2 func() ([]containerLoadSample, error),
	readWithHost func(bool) ([]containerLoadSample, *stats.LoadStats, error),
) ([]containerLoadSample, *stats.LoadStats, error) {
	if !c.enableHostUninterruptible {
		samples, err := c.readContainerLoad(mode, readV1, readV2)
		return samples, nil, err
	}
	includeContainers := mode == cgroups.Unified && c.enableCgroupV2
	samples, host, err := readWithHost(includeContainers)
	if errors.Is(err, cgroupV2.ErrTaskIteratorNotSupported) {
		c.unsupportedHost.Do(func() {
			log.WithError(err).Warn("BPF task load metrics unavailable; procfs host load and v1 container load remain enabled")
		})
		samples, host, err = nil, nil, nil
	}
	if mode == cgroups.Legacy || mode == cgroups.Hybrid {
		var containerErr error
		samples, containerErr = readV1()
		err = errors.Join(err, containerErr)
	}
	return samples, host, err
}

func readTaskLoadWithHost(includeContainers bool) ([]containerLoadSample, *stats.LoadStats, error) {
	var containers map[string]*pod.Container
	var containerErr error
	if includeContainers {
		containers, containerErr = pod.ContainersByType(pod.ContainerTypeNormal | pod.ContainerTypeSidecar)
	}
	paths := make([]string, 0, len(containers))
	for _, container := range containers {
		paths = append(paths, container.CgroupPath)
	}
	byPath, host, err := cgroupV2.SharedLoadStatsWithHost(cgroupV2.LoadStatsConsumerLoadavg, paths)
	samples := make([]containerLoadSample, 0, len(containers))
	for _, container := range containers {
		if load, ok := byPath[container.CgroupPath]; ok {
			samples = append(samples, containerLoadSample{container, load.NrRunning, load.NrUninterruptible})
		}
	}
	return samples, host, errors.Join(containerErr, err)
}
