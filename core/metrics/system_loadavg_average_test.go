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
	"fmt"
	"math"
	"sync"
	"testing"
	"time"

	"huatuo-bamai/internal/cgroups"
	"huatuo-bamai/internal/cgroups/stats"
	cgroupV2 "huatuo-bamai/internal/cgroups/v2"
	"huatuo-bamai/pkg/metric"
)

func loadMetricValues(data []*metric.Data) map[string]float64 {
	values := make(map[string]float64, len(data))
	for _, d := range data {
		values[d.Name()] = d.Value
	}
	return values
}

func TestLoadavgIntervalConfig(t *testing.T) {
	original := configSnapshot()
	t.Cleanup(func() { Set(original) })
	for _, seconds := range []int64{0, 5, 15, 30, -1, math.MaxInt64/int64(time.Second)/3 + 1} {
		t.Run(fmt.Sprint(seconds), func(t *testing.T) {
			cfg := &Config{}
			cfg.Loadavg.Interval = seconds
			Set(cfg)
			attr, err := newLoadavg()
			if seconds < 0 || seconds > math.MaxInt64/int64(time.Second)/3 {
				if err == nil {
					t.Fatal("invalid sampling interval accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := time.Duration(seconds) * time.Second
			if seconds == 0 {
				want = 15 * time.Second
			}
			c := attr.TracingData.(*loadavgCollector)
			if got := c.samplingInterval(); got != want {
				t.Fatalf("sampling interval = %s, want %s", got, want)
			}
			// A running collector keeps its configuration snapshot.
			Set(&Config{})
			if c.samplingInterval() != want {
				t.Fatal("configuration update changed the running sampler")
			}
		})
	}
}

func TestLoadavgIntervalControlsAverageAndExpiry(t *testing.T) {
	for _, interval := range []time.Duration{5 * time.Second, 15 * time.Second, 30 * time.Second} {
		t.Run(interval.String(), func(t *testing.T) {
			c := &loadavgCollector{sampling: true, sampleInterval: interval}
			at := time.Unix(100, 0)
			samples := []containerLoadSample{{vmstatTestContainer("/one"), 2, 3}}
			c.publishContainerLoad(at, samples, nil, nil)
			dt := interval + 2*time.Second
			at = at.Add(dt)
			c.publishContainerLoad(at, samples, nil, nil)
			data, err, _ := c.cachedContainerLoad(at)
			if err != nil {
				t.Fatal(err)
			}
			values := loadMetricValues(data)
			for i, window := range []float64{60, 300, 900} {
				name := []string{"container_load1", "container_load5", "container_load15"}[i]
				want := 5 * (1 - math.Exp(-dt.Seconds()/window))
				if math.Abs(values[name]-want) > 1e-12 {
					t.Fatalf("%s = %g, want %g", name, values[name], want)
				}
			}
			expires := at.Add(3 * interval)
			if data, err, _ := c.cachedContainerLoad(expires); err != nil || len(data) != 5 {
				t.Fatalf("sample expired early: data=%v err=%v", data, err)
			}
			expires = expires.Add(time.Nanosecond)
			if data, err, _ := c.cachedContainerLoad(expires); err == nil || len(data) != 0 {
				t.Fatal("stale sample exported")
			}
			c.publishContainerLoad(expires, samples, nil, nil)
			if data, _, _ := c.cachedContainerLoad(expires); len(data) != 2 {
				t.Fatal("average survived a gap longer than three intervals")
			}
		})
	}
}

func TestLoadSamplerUsesInterval(t *testing.T) {
	c := &loadavgCollector{sampleInterval: time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	reads := 0
	err := c.sampleLoad(ctx, func() ([]containerLoadSample, *stats.LoadStats, error) {
		reads++
		if reads == 2 {
			cancel()
		}
		return nil, nil, nil
	})
	if err != nil || reads != 2 {
		t.Fatalf("sampler ignored interval: reads=%d err=%v", reads, err)
	}
}

func TestContainerLoadAverage(t *testing.T) {
	c := &loadavgCollector{sampling: true, sampleInterval: 5 * time.Second}
	at := time.Unix(100, 0)
	samples := []containerLoadSample{{vmstatTestContainer("/one"), 2, 3}}
	c.publishContainerLoad(at, samples, nil, nil)
	data, _, _ := c.cachedContainerLoad(at)
	if len(data) != 2 {
		t.Fatalf("baseline emitted averages: %v", loadMetricValues(data))
	}
	for _, dt := range []time.Duration{5 * time.Second, 7 * time.Second} {
		at = at.Add(dt)
		c.publishContainerLoad(at, samples, nil, nil)
	}
	data, err, active := c.cachedContainerLoad(at)
	if err != nil || !active {
		t.Fatalf("cache: %v, %v", err, active)
	}
	values := loadMetricValues(data)
	for i, window := range []float64{60, 300, 900} {
		name := []string{"container_load1", "container_load5", "container_load15"}[i]
		want := 5 * (1 - math.Exp(-12/window))
		if math.Abs(values[name]-want) > 1e-12 {
			t.Errorf("%s = %g, want %g", name, values[name], want)
		}
	}
	samples[0].running, samples[0].uninterruptible = 0, 0
	c.publishContainerLoad(at.Add(5*time.Second), samples, nil, nil)
	data, _, _ = c.cachedContainerLoad(at.Add(5 * time.Second))
	if got := loadMetricValues(data)["container_load1"]; math.Abs(got-values["container_load1"]*math.Exp(-5.0/60)) > 1e-12 {
		t.Fatalf("decay = %g", got)
	}
	for range 10 {
		again, _, _ := c.cachedContainerLoad(at.Add(6 * time.Second))
		if loadMetricValues(again)["container_load1"] != loadMetricValues(data)["container_load1"] {
			t.Fatal("scrape advanced average")
		}
	}
	if data, err, _ := c.cachedContainerLoad(at.Add(21 * time.Second)); len(data) != 0 || err == nil {
		t.Fatal("expired sample exported")
	}
}

func TestContainerLoadAverageReset(t *testing.T) {
	for _, reason := range []string{"missing", "failure", "restart", "path", "gap"} {
		t.Run(reason, func(t *testing.T) {
			c := &loadavgCollector{sampling: true, sampleInterval: 5 * time.Second}
			at := time.Unix(100, 0)
			samples := []containerLoadSample{{vmstatTestContainer("/one"), 2, 3}}
			c.publishContainerLoad(at, samples, nil, nil)
			c.publishContainerLoad(at.Add(5*time.Second), samples, nil, nil)
			next := at.Add(15 * time.Second)
			switch reason {
			case "missing":
				c.publishContainerLoad(at.Add(10*time.Second), nil, nil, nil)
			case "failure":
				c.publishContainerLoad(at.Add(10*time.Second), nil, errors.New("read failed"), nil)
			case "restart":
				samples[0].container.StartedAt = at
			case "path":
				samples[0].container.CgroupPath = "/two"
			case "gap":
				next = at.Add(21 * time.Second)
			}
			c.publishContainerLoad(next, samples, nil, nil)
			data, _, _ := c.cachedContainerLoad(next)
			if len(data) != 2 {
				t.Fatalf("history survived %s", reason)
			}
		})
	}
}

func TestContainerLoadSamplingModes(t *testing.T) {
	failure := errors.New("partial read")
	for _, mode := range []cgroups.Mode{cgroups.Legacy, cgroups.Hybrid, cgroups.Unified, cgroups.Unavailable} {
		for _, enabled := range []bool{false, true} {
			c := &loadavgCollector{enableCgroupV2: enabled}
			v1, v2 := 0, 0
			read1 := func() ([]containerLoadSample, error) {
				v1++
				return []containerLoadSample{{vmstatTestContainer("/one"), 1, 0}}, failure
			}
			read2 := func() ([]containerLoadSample, error) { v2++; return nil, cgroupV2.ErrTaskIteratorNotSupported }
			samples, err := c.readContainerLoad(mode, read1, read2)
			if mode == cgroups.Legacy || mode == cgroups.Hybrid {
				if v1 != 1 || v2 != 0 || len(samples) != 1 || !errors.Is(err, failure) {
					t.Fatal("lost v1 partial sample")
				}
			} else if err != nil || len(samples) != 0 || v1 != 0 || (v2 == 1) != (mode == cgroups.Unified && enabled) {
				t.Fatal("incorrect mode selection")
			}
		}
	}
}

func TestLoadSamplerLifecycle(t *testing.T) {
	c := &loadavgCollector{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- c.sampleLoad(ctx, func() ([]containerLoadSample, *stats.LoadStats, error) {
			close(ready)
			return []containerLoadSample{{vmstatTestContainer("/one"), 1, 2}}, nil, nil
		})
	}()
	<-ready
	var readers sync.WaitGroup
	for range 4 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 100 {
				_, _, _ = c.cachedContainerLoad(time.Now())
			}
		}()
	}
	readers.Wait()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, _, active := c.cachedContainerLoad(time.Now()); active || len(c.averages) != 0 {
		t.Fatal("sampler state leaked after stop")
	}
}

func BenchmarkContainerLoadAverage(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			c := &loadavgCollector{}
			samples := make([]containerLoadSample, count)
			for i := range samples {
				container := vmstatTestContainer(fmt.Sprint(i))
				samples[i] = containerLoadSample{container, 2, 3}
			}
			at := time.Unix(100, 0)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				at = at.Add(c.samplingInterval())
				c.publishContainerLoad(at, samples, nil, nil)
			}
		})
	}
}
