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
	"fmt"
	"os"
	"sync"
	"time"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/bpf/abi"
	"huatuo-bamai/internal/cgroups"
	"huatuo-bamai/internal/cgroups/subsystem"
	"huatuo-bamai/internal/log"
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
	Cmdline             string                   `json:"cmdline,omitempty"`
	CmdlineTruncated    bool                     `json:"cmdline_truncated,omitempty"`
	Environ             []string                 `json:"environ,omitempty"`
	EnvironTruncated    bool                     `json:"environ_truncated,omitempty"`
	RssAnonBytes        uint64                   `json:"rss_anon_bytes,omitempty"`
	RssFileBytes        uint64                   `json:"rss_file_bytes,omitempty"`
	RssShmemBytes       uint64                   `json:"rss_shmem_bytes,omitempty"`
	TotalVmBytes        uint64                   `json:"total_vm_bytes,omitempty"`
	Cgroup              *OOMCgroupMemorySnapshot `json:"cgroup,omitempty"`
}

type OOMTracingData struct {
	Trigger        OOMActor           `json:"trigger"`
	Victim         OOMActor           `json:"victim"`
	MemorySnapshot *OOMMemorySnapshot `json:"memory_snapshot,omitempty"`
	LanguageInfo   *OOMLanguageInfo   `json:"language_info,omitempty"`
}

type oomMetric struct {
	count            int
	latestVictimComm string
}

type oomCollector struct {
	cgroup cgroups.Cgroup
}

var (
	outOfMemoryCounterHost      float64
	outOfMemoryCounterContainer = make(map[string]*oomMetric)
	mutex                       sync.Mutex
)

var pageSize uint64

func init() {
	pageSize = uint64(os.Getpagesize())
	tracing.RegisterEventTracing("oom", newOOMCollector)
}

func newOOMCollector() (*tracing.EventTracingAttr, error) {
	cgroup, err := cgroups.NewManager()
	if err != nil {
		log.Warnf("failed to initialize cgroup reader for oom snapshot: %v", err)
	}

	return &tracing.EventTracingAttr{
		TracingData: &oomCollector{
			cgroup: cgroup,
		},
		Interval: 10,
		Flag:     tracing.FlagTracing | tracing.FlagMetric,
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
	return metrics, nil
}

/*
 * Start reads base OOM events continuously while separate workers correlate
 * exit context. It keeps kernel perf draining independent from the bounded
 * exit wait and returns the first reader or processing failure.
 */
func (c *oomCollector) Start(ctx context.Context) error {
	b, err := bpf.LoadBpf(bpf.ThisBpfOBJ(), nil)
	if err != nil {
		return err
	}
	defer b.Close()

	childCtx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	var processMu sync.Mutex
	runErr := make(chan error, 1)

	/*
	 * reportError preserves the first asynchronous failure and wakes the base
	 * reader so Start can return that original error instead of a cancel error.
	 */
	reportError := func(err error) {
		select {
		case runErr <- err:
			cancel()
		default:
		}
	}

	exitReader, err := b.EventPipeByName(childCtx, "oom_exit_events", 8192)
	if err != nil {
		cancel()
		return fmt.Errorf("open oom exit context reader: %w", err)
	}

	reader, err := b.AttachAndEventPipe(childCtx, "oom_perf_events", 8192)
	if err != nil {
		cancel()
		exitReader.Close()
		return err
	}
	defer func() {
		cancel()
		reader.Close()
		exitReader.Close()
		workers.Wait()
	}()

	workers.Add(1)
	go func() {
		defer workers.Done()
		if err := startOOMExitReader(childCtx, exitReader); err != nil {
			reportError(fmt.Errorf("read oom exit context: %w", err))
		}
	}()

	b.WaitDetachByBreaker(childCtx, cancel)

	for {
		select {
		case err := <-runErr:
			return err
		case <-childCtx.Done():
			return asynchronousOOMError(runErr)
		default:
			var data abi.OOMEvent
			if err := reader.ReadInto(&data); err != nil {
				if asyncErr := asynchronousOOMError(runErr); asyncErr != nil {
					return asyncErr
				}
				if childCtx.Err() != nil {
					return nil
				}
				return fmt.Errorf("failed to read perf event: %w", err)
			}
			eventTime := time.Now()

			/*
			 * Base enrichment starts immediately outside this reader loop.
			 * processMu serializes enrichment and storage without being held
			 * while workers wait for independently delivered exit context.
			 */
			workers.Add(1)
			go func(data abi.OOMEvent, eventTime time.Time) {
				defer workers.Done()

				processMu.Lock()
				oomData, err := c.prepareOOMEvent(data)
				processMu.Unlock()
				if err != nil {
					reportError(err)
					return
				}

				exitContext := oomExitEvents.wait(
					childCtx, data.VictimPID, data.Timestamp)
				if childCtx.Err() != nil {
					return
				}
				mergeOOMExitContext(oomData, exitContext)
				completeLanguageInfo(oomData)

				processMu.Lock()
				defer processMu.Unlock()
				if childCtx.Err() != nil {
					return
				}
				saveOOMEvent(oomData, eventTime)
			}(data, eventTime)
		}
	}
}

/*
 * asynchronousOOMError returns a queued worker or exit-reader failure without
 * blocking. A nil result means cancellation came from the parent context.
 */
func asynchronousOOMError(errs <-chan error) error {
	select {
	case err := <-errs:
		return err
	default:
		return nil
	}
}

/*
 * prepareOOMEvent captures container association, resource snapshots, language,
 * and accounting before waiting for the victim exit event.
 */
func (c *oomCollector) prepareOOMEvent(
	data abi.OOMEvent,
) (*OOMTracingData, error) {
	containers, err := pod.Containers()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch containers: %w", err)
	}

	oomData := buildTracingData(data, nil, containers, c.cgroup)

	mutex.Lock()
	if container, ok := containers[oomData.Victim.ContainerID]; ok {
		containerCounterUpdate(container.ID, oomData.Victim.Comm)
	} else {
		outOfMemoryCounterHost++
	}
	mutex.Unlock()

	return oomData, nil
}

/*
 * mergeOOMExitContext adds best-effort data captured immediately before the
 * victim address space is torn down.
 */
func mergeOOMExitContext(
	oomData *OOMTracingData, exitContext *oomExitContext,
) {
	if exitContext == nil {
		return
	}

	oomData.Victim.Cmdline = exitContext.cmdline
	oomData.Victim.CmdlineTruncated = exitContext.cmdlineTruncated
	oomData.Victim.Environ = exitContext.environ
	oomData.Victim.EnvironTruncated = exitContext.environTruncated
}

/*
 * saveOOMEvent writes the enriched base event and any correlated exit context
 * as one tracing record.
 */
func saveOOMEvent(oomData *OOMTracingData, eventTime time.Time) {
	if err := tracing.Save(&tracing.WriteRequest{
		TracerName:  "oom",
		TracerTime:  eventTime,
		TracerData:  oomData,
		ContainerID: oomData.Victim.ContainerID,
	}); err != nil {
		log.Warnf("failed to save tracing data: %v", err)
	}
}

func buildTracingData(data abi.OOMEvent, exitContext *oomExitContext,
	containers map[string]*pod.Container, cgroup cgroups.Cgroup) *OOMTracingData {
	cssContainers := pod.BuildCssContainersID(containers, subsystem.SubsystemMemory)

	triggerID := cssContainers[data.TriggerMemcgCSS]
	victimID := cssContainers[data.VictimMemcgCSS]
	if exitContext == nil {
		exitContext = &oomExitContext{}
	}

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
			Cmdline:             exitContext.cmdline,
			CmdlineTruncated:    exitContext.cmdlineTruncated,
			Environ:             exitContext.environ,
			EnvironTruncated:    exitContext.environTruncated,
			RssAnonBytes:        data.VictimRssAnonPages * pageSize,
			RssFileBytes:        data.VictimRssFilePages * pageSize,
			RssShmemBytes:       data.VictimRssShmemPages * pageSize,
			TotalVmBytes:        data.VictimTotalVmPages * pageSize,
		},
	}
	oomData.LanguageInfo = detectLanguageInfo(oomData.Victim)

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
