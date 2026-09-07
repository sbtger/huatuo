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

	cgroupV2 "huatuo-bamai/internal/cgroups/v2"
	"huatuo-bamai/internal/pod"
	"huatuo-bamai/pkg/metric"

	cadvisorV1 "github.com/google/cadvisor/info/v1"
)

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

func TestCollectContainerV2IgnoresUnsupportedIterator(t *testing.T) {
	collector := &loadavgCollector{enableCgroupV2: true}
	got, err := collector.collectContainerV2(func() ([]*metric.Data, error) {
		return nil, cgroupV2.ErrTaskIteratorNotSupported
	})
	if err != nil {
		t.Fatalf("collectContainerV2() error = %v, want nil", err)
	}
	if len(got) != 0 {
		t.Fatalf("collectContainerV2() metrics = %v, want none", got)
	}
}

func TestCollectContainerV2PreservesRuntimeErrorAndPartialMetrics(t *testing.T) {
	wantErr := errors.New("iterator read failed")
	wantMetric := metric.NewGaugeData("container_load", 1, "container load", nil)
	collector := &loadavgCollector{enableCgroupV2: true}

	got, err := collector.collectContainerV2(func() ([]*metric.Data, error) {
		return []*metric.Data{wantMetric}, wantErr
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("collectContainerV2() error = %v, want %v", err, wantErr)
	}
	if len(got) != 1 || got[0] != wantMetric {
		t.Fatalf("collectContainerV2() metrics = %v, want partial metric", got)
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

func TestCollectContainerLoadavgV1SilentlySkipsFailures(t *testing.T) {
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

	got, err := collectContainerLoadavgV1(
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
		t.Fatalf("collectContainerLoadavgV1 error = %v, want nil", err)
	}
	if len(got) != 2 {
		t.Fatalf("metric count = %d, want 2", len(got))
	}
	if got[0].Value != 2 || got[1].Value != 3 {
		t.Fatalf("metrics = %v, want running 2 and uninterruptible 3", got)
	}
}
