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
	cgroupV2 "huatuo-bamai/internal/cgroups/v2"
)

func TestHostLoadSampleModes(t *testing.T) {
	for _, mode := range []cgroups.Mode{cgroups.Legacy, cgroups.Hybrid, cgroups.Unified, cgroups.Unavailable} {
		for _, enabled := range []bool{false, true} {
			c := &loadavgCollector{enableHostUninterruptible: true, enableCgroupV2: enabled}
			v1Calls, iterCalls := 0, 0
			read1 := func() ([]containerLoadSample, error) {
				v1Calls++
				return []containerLoadSample{{vmstatTestContainer("one"), 1, 2}}, nil
			}
			read2 := func() ([]containerLoadSample, error) { t.Fatal("second iterator scan"); return nil, nil }
			readHost := func(containers bool) ([]containerLoadSample, *stats.LoadStats, error) {
				iterCalls++
				if containers != (mode == cgroups.Unified && enabled) {
					t.Fatal("wrong iterator targets")
				}
				return nil, &stats.LoadStats{NrUninterruptible: 7}, nil
			}
			_, host, err := c.readLoadSample(mode, read1, read2, readHost)
			if err != nil || host == nil || host.NrUninterruptible != 7 || iterCalls != 1 || (v1Calls == 1) != (mode == cgroups.Legacy || mode == cgroups.Hybrid) {
				t.Fatalf("mode %v: host=%v err=%v", mode, host, err)
			}
		}
	}
}

func TestHostLoadSampleFailures(t *testing.T) {
	for _, hostErr := range []error{nil, cgroupV2.ErrTaskIteratorNotSupported, errors.New("iterator failed")} {
		c := &loadavgCollector{enableHostUninterruptible: true}
		v1 := func() ([]containerLoadSample, error) {
			return []containerLoadSample{{vmstatTestContainer("one"), 1, 2}}, nil
		}
		readHost := func(bool) ([]containerLoadSample, *stats.LoadStats, error) {
			if hostErr != nil {
				return nil, nil, hostErr
			}
			return nil, &stats.LoadStats{}, nil
		}
		samples, host, err := c.readLoadSample(cgroups.Legacy, v1, nil, readHost)
		if len(samples) != 1 || (host != nil) != (hostErr == nil) {
			t.Fatal("iterator failure broke v1")
		}
		if (err != nil) != (hostErr != nil && !errors.Is(hostErr, cgroupV2.ErrTaskIteratorNotSupported)) {
			t.Fatalf("unexpected error %v", err)
		}
	}
	c := &loadavgCollector{}
	_, host, err := c.readLoadSample(cgroups.Unified, nil, nil, func(bool) ([]containerLoadSample, *stats.LoadStats, error) {
		t.Fatal("disabled host scanned")
		return nil, nil, nil
	})
	if host != nil || err != nil {
		t.Fatal("disabled host returned metric")
	}
}

func TestHostLoadCache(t *testing.T) {
	c := &loadavgCollector{sampling: true}
	at := time.Unix(100, 0)
	c.publishContainerLoad(at, nil, nil, &stats.LoadStats{NrUninterruptible: 7})
	data, err, _ := c.cachedContainerLoad(at)
	if err != nil || loadMetricValues(data)["nr_uninterruptible"] != 7 {
		t.Fatal("missing host metric")
	}
	c.publishContainerLoad(at.Add(5*time.Second), nil, errors.New("iterator failed"), nil)
	data, err, _ = c.cachedContainerLoad(at.Add(5 * time.Second))
	if err == nil || len(data) != 0 {
		t.Fatal("failed host sample reused old value")
	}
}

func TestHostLoadConfigDefault(t *testing.T) {
	if shippedVMStatConfig(t).Loadavg.EnableHostUninterruptible {
		t.Fatal("host iterator enabled by default")
	}
}
