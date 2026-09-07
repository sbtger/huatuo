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
	"context"
	"errors"
	"math"
	"time"

	"huatuo-bamai/internal/cgroups"
	"huatuo-bamai/internal/cgroups/stats"
	cgroupV2 "huatuo-bamai/internal/cgroups/v2"
	"huatuo-bamai/internal/pod"
	"huatuo-bamai/pkg/metric"
)

const defaultLoadSampleInterval = 15 * time.Second

func (c *loadavgCollector) samplingInterval() time.Duration {
	if c.sampleInterval == 0 {
		return defaultLoadSampleInterval
	}
	return c.sampleInterval
}

type containerLoadSample struct {
	container                *pod.Container
	running, uninterruptible uint64
}

// A new container or a reused cgroup must not inherit another task set's EMA.
type containerLoadKey struct {
	ID, Path  string
	StartedAt time.Time
}

type containerLoadAverage struct {
	last   time.Time
	values [3]float64
}

func instantaneousContainerLoad(samples []containerLoadSample) []*metric.Data {
	data := make([]*metric.Data, 0, len(samples)*2)
	for _, sample := range samples {
		data = append(data, containerLoadMetrics(sample.container, sample.running, sample.uninterruptible)...)
	}
	return data
}

// Start samples independently of Prometheus scrapes and dload profiling.
// The tracing manager owns cancellation and restart; no detached goroutine lives
// beyond the collector lifecycle.
func (c *loadavgCollector) Start(ctx context.Context) error {
	return c.sampleLoad(ctx, func() ([]containerLoadSample, *stats.LoadStats, error) {
		return c.readLoadSample(cgroups.CgroupMode(), readContainerLoadV1, readContainerLoadV2, readTaskLoadWithHost)
	})
}

func (c *loadavgCollector) sampleLoad(ctx context.Context, read func() ([]containerLoadSample, *stats.LoadStats, error)) error {
	c.mu.Lock()
	c.sampling = true
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		c.sampling = false
		c.sampledData, c.sampledErr, c.averages = nil, nil, nil
		c.sampledAt = time.Time{}
		c.mu.Unlock()
		cgroupV2.ForgetSharedLoadStatsConsumer(cgroupV2.LoadStatsConsumerLoadavg)
	}()
	ticker := time.NewTicker(c.samplingInterval())
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return nil
		}
		at := time.Now()
		samples, host, err := read()
		c.publishContainerLoad(at, samples, err, host)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (c *loadavgCollector) publishContainerLoad(at time.Time, samples []containerLoadSample, err error, host *stats.LoadStats) {
	c.mu.Lock()
	defer c.mu.Unlock()
	data := instantaneousContainerLoad(samples)
	if host != nil {
		data = append(data, metric.NewGaugeData("nr_uninterruptible", float64(host.NrUninterruptible),
			"number of host uninterruptible tasks contributing to load", nil))
	}
	next := make(map[containerLoadKey]containerLoadAverage, len(samples))
	for _, sample := range samples {
		container := sample.container
		key := containerLoadKey{ID: container.ID, Path: container.CgroupPath, StartedAt: container.StartedAt}
		average := c.averages[key]
		dt := at.Sub(average.last)
		if average.last.IsZero() || dt <= 0 || dt > 3*c.samplingInterval() {
			// Establish a baseline, then warm up from zero over observed time.
			// Never extrapolate across a missing sample or a long suspension.
			average = containerLoadAverage{last: at}
		} else {
			active := float64(sample.running) + float64(sample.uninterruptible)
			for i, window := range [...]float64{60, 300, 900} {
				weight := -math.Expm1(-dt.Seconds() / window)
				average.values[i] += (active - average.values[i]) * weight
				name := [...]string{"load1", "load5", "load15"}[i]
				data = append(data, metric.NewContainerGaugeData(container, name, average.values[i],
					"estimated container R+D load average, "+name, nil))
			}
			average.last = at
		}
		next[key] = average
	}
	// Missing/failed containers are omitted and pruned, never sampled as zero.
	c.averages, c.sampledData, c.sampledErr, c.sampledAt = next, data, err, at
}

func (c *loadavgCollector) cachedContainerLoad(now time.Time) ([]*metric.Data, error, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.sampling {
		return nil, nil, false
	}
	if c.sampledAt.IsZero() {
		return nil, nil, true
	}
	if now.Sub(c.sampledAt) > 3*c.samplingInterval() {
		return nil, errors.New("container load sample expired; check loadavg sampler"), true
	}
	return c.sampledData, c.sampledErr, true
}
