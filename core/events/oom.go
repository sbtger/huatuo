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

package events

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/bpf/abi"
	"huatuo-bamai/internal/cgroups"
	"huatuo-bamai/internal/cgroups/subsystem"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/internal/memsnap"
	"huatuo-bamai/internal/pod"
	"huatuo-bamai/internal/utils/bytesutil"
	"huatuo-bamai/internal/utils/kernaddr"
	"huatuo-bamai/pkg/metric"
	"huatuo-bamai/pkg/tracing"
)

//go:generate $BPF_COMPILE $BPF_INCLUDE -s $BPF_DIR/oom.c -o $BPF_DIR/oom.o

type OOMActor struct {
	MemoryCgroupCSSAddr string                   `json:"memory_cgroup_css_addr"`
	ContainerID         string                   `json:"container_id,omitempty"`
	ContainerHostname   string                   `json:"container_hostname,omitempty"`
	Pid                 int32                    `json:"pid"`
	Comm                string                   `json:"comm"`
	Cgroup              *OOMCgroupMemorySnapshot `json:"cgroup,omitempty"`
}

type OOMTracingData struct {
	Trigger               OOMActor                  `json:"trigger"`
	Victim                OOMActor                  `json:"victim"`
	MemorySnapshot        *OOMMemorySnapshot        `json:"memory_snapshot,omitempty"`
	RuntimeMemorySnapshot *OOMRuntimeMemorySnapshot `json:"runtime_memory_snapshot,omitempty"`
}

type oomMetric struct {
	count            int
	latestVictimComm string
}

type oomCollector struct {
	cgroup          cgroups.Cgroup
	runtimeSnapshot *oomRuntimeSnapshotService
}

var (
	outOfMemoryCounterHost      float64
	outOfMemoryCounterContainer = make(map[string]*oomMetric)
	mutex                       sync.Mutex
)

func init() {
	tracing.RegisterEventTracing("oom", newOOMCollector)
}

func newOOMCollector() (*tracing.EventTracingAttr, error) {
	cgroup, err := cgroups.NewManager()
	if err != nil {
		log.Warnf("failed to initialize cgroup reader for oom snapshot: %v", err)
	}

	collector := &oomCollector{cgroup: cgroup}
	eventConfig := configSnapshot()
	// Build the service regardless of the enable flag so a live PUT /config can
	// later enable the gate through the existing service; the CPU-affinity
	// requirement only applies while the synchronous gate is enabled.
	service, err := buildOOMRuntimeSnapshotService(&eventConfig.OOMRuntimeSnapshot)
	if err != nil {
		return nil, err
	}
	service.useLiveConfig()
	collector.runtimeSnapshot = service
	if eventConfig.OOMRuntimeSnapshot.Enabled {
		if err := eventConfig.OOMRuntimeSnapshot.Validate(); err != nil {
			return nil, err
		}
		if err := validateOOMRuntimeSnapshotCPUCapacity(); err != nil {
			return nil, err
		}
	}
	return &tracing.EventTracingAttr{
		TracingData: collector,
		Interval:    10,
		Flag:        tracing.FlagTracing | tracing.FlagMetric,
	}, nil
}

func (c *oomCollector) Update() ([]*metric.Data, error) {
	containers, err := pod.NormalContainers()
	if err != nil {
		return nil, fmt.Errorf("get normal container: %w", err)
	}

	var metrics []*metric.Data

	mutex.Lock()

	metrics = append(metrics, metric.NewCounterData("host_total", outOfMemoryCounterHost, "host oom counter", nil))
	for _, container := range containers {
		if val, exists := outOfMemoryCounterContainer[container.ID]; exists {
			metrics = append(
				metrics,
				metric.NewContainerCounterData(container, "total", float64(val.count), "containers oom counter", map[string]string{"latest_victim_comm": val.latestVictimComm}),
			)
		}
	}

	mutex.Unlock()
	if c.runtimeSnapshot != nil {
		metrics = append(metrics, c.runtimeSnapshot.Update()...)
	}
	return metrics, nil
}

func (c *oomCollector) Start(ctx context.Context) error {
	b, err := bpf.LoadBPF(bpf.ThisBpfOBJ(), nil)
	if err != nil {
		return err
	}
	defer b.Close()

	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	if c.runtimeSnapshot != nil {
		if err := c.runtimeSnapshot.attachBPF(b); err != nil {
			return err
		}
		defer c.runtimeSnapshot.detachBPF()
		// Default-disabled: leave the capture-freeze probe detached so it does
		// not fire on every process exit. A live PUT /config enable reconciles
		// it through refreshBPFConfig -> AttachProgram.
		if !configSnapshot().OOMRuntimeSnapshot.Enabled {
			b.SetAttachSkip(oomRuntimeSnapshotExitMMReleaseProgram)
		}
	}

	reader, err := b.AttachAndEventPipe(childCtx, "oom_perf_events", 8192)
	if err != nil {
		return err
	}
	defer reader.Close()

	var pendingSaves sync.WaitGroup
	defer pendingSaves.Wait()
	runtimeWaitSlot := make(chan struct{}, 1)
	queueSave := func(oomData *OOMTracingData, eventTime time.Time,
		key oomRuntimeSnapshotKey, admissionDeadlineNS uint64,
	) {
		save := func() {
			if err := tracing.Save(&tracing.WriteRequest{
				TracerName: "oom", TracerTime: eventTime, TracerData: oomData,
				ContainerID: oomData.Victim.ContainerID,
			}); err != nil {
				log.Warnf("failed to save tracing data: %v", err)
			}
		}
		if !configSnapshot().OOMRuntimeSnapshot.Enabled || key.oomMonotonicNS == 0 {
			save()
			return
		}
		if snapshot, ok := runtimeSnapshotBridge.wait(
			childCtx, key, 0); ok {
			oomData.RuntimeMemorySnapshot = snapshot
			save()
			return
		}
		waitSnapshot := func() (*OOMRuntimeMemorySnapshot, bool) {
			remaining := c.runtimeSnapshot.waitBudget(eventTime, admissionDeadlineNS)
			return runtimeSnapshotBridge.wait(childCtx, key, remaining)
		}
		select {
		case runtimeWaitSlot <- struct{}{}:
		default:
			// The wait slot is held by another event's pending save. Wait
			// synchronously instead of mislabeling an admitted event as
			// SKIPPED_BUSY; the kernel single-slot gate already bounds
			// concurrent captures, and this backpressures the perf loop under
			// an OOM storm.
			snapshot, ok := waitSnapshot()
			if !ok {
				snapshot = runtimeSnapshotStatus(key,
					memsnap.StatusGateTimeout,
					"Runtime snapshot did not arrive before the OOM event deadline")
			}
			oomData.RuntimeMemorySnapshot = snapshot
			save()
			return
		}
		pendingSaves.Add(1)
		go func() {
			defer pendingSaves.Done()
			defer func() { <-runtimeWaitSlot }()
			snapshot, ok := waitSnapshot()
			if !ok {
				snapshot = runtimeSnapshotStatus(key,
					memsnap.StatusGateTimeout,
					"Runtime snapshot did not arrive before the OOM event deadline")
			}
			oomData.RuntimeMemorySnapshot = snapshot
			save()
		}()
	}

	b.DetachOnContextDone(childCtx, cancel)

	for {
		select {
		case <-childCtx.Done():
			return nil
		default:
			var data abi.OOMEvent
			if err := reader.ReadInto(&data); err != nil {
				if errors.Is(err, bpf.ErrPerfEventSamplesLost) {
					log.WithError(err).Warn("lost BPF perf event samples")
					continue
				}
				return fmt.Errorf("failed to read perf event: %w", err)
			}
			eventTime := time.Now()
			if c.runtimeSnapshot != nil && configSnapshot().OOMRuntimeSnapshot.Enabled {
				c.runtimeSnapshot.submit(childCtx, b, &data)
			}

			containers, err := pod.Containers()
			if err != nil {
				return fmt.Errorf("failed to fetch containers: %w", err)
			}

			oomData := buildTracingData(data, containers, c.cgroup)

			mutex.Lock()

			if container, ok := containers[oomData.Victim.ContainerID]; ok {
				containerCounterUpdate(container.ID, oomData.Victim.Comm)
			} else {
				outOfMemoryCounterHost++
			}

			mutex.Unlock()

			queueSave(oomData, eventTime, oomRuntimeSnapshotKey{
				victimTGID: data.VictimPID, oomMonotonicNS: data.Timestamp,
			}, data.SnapshotAdmissionDeadlineNS)
		}
	}
}

func buildTracingData(data abi.OOMEvent, containers map[string]*pod.Container, cgroup cgroups.Cgroup) *OOMTracingData {
	cssContainers := pod.BuildCssContainersID(containers, subsystem.SubsystemMemory)

	triggerID := cssContainers[data.TriggerMemcgCSS]
	victimID := cssContainers[data.VictimMemcgCSS]

	oomData := &OOMTracingData{
		Trigger: OOMActor{
			MemoryCgroupCSSAddr: kernaddr.Format(data.TriggerMemcgCSS),
			ContainerID:         triggerID,
			Pid:                 int32(data.TriggerPID),
			Comm:                bytesutil.ToStr(data.TriggerComm[:]),
		},
		Victim: OOMActor{
			MemoryCgroupCSSAddr: kernaddr.Format(data.VictimMemcgCSS),
			ContainerID:         victimID,
			Pid:                 int32(data.VictimPID),
			Comm:                bytesutil.ToStr(data.VictimComm[:]),
		},
	}

	if container, ok := containers[triggerID]; ok {
		oomData.Trigger.ContainerHostname = container.Hostname
		if snap, err := cgroupMemorySnapshot(cgroup, container); err != nil {
			log.Warnf("trigger cgroup snapshot: %v", err)
		} else {
			oomData.Trigger.Cgroup = snap
		}
	}

	if container, ok := containers[victimID]; ok {
		oomData.Victim.ContainerHostname = container.Hostname
		if snap, err := cgroupMemorySnapshot(cgroup, container); err != nil {
			log.Warnf("victim cgroup snapshot: %v", err)
		} else {
			oomData.Victim.Cgroup = snap
		}
	}

	if snap, err := hostMemorySnapshot(); err != nil {
		log.Warnf("host memory snapshot: %v", err)
	} else {
		oomData.MemorySnapshot = snap
	}
	return oomData
}

func containerCounterUpdate(containerID, comm string) {
	if val, exists := outOfMemoryCounterContainer[containerID]; exists {
		val.count++
		val.latestVictimComm = comm
		return
	}

	outOfMemoryCounterContainer[containerID] = &oomMetric{count: 1, latestVictimComm: comm}
}
