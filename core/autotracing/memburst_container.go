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

package autotracing

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/shirou/gopsutil/process"

	"huatuo-bamai/internal/cgroups"
	"huatuo-bamai/internal/cgroups/paths"
	"huatuo-bamai/internal/cgroups/pids"
	"huatuo-bamai/internal/cgroups/subsystem"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/internal/pod"
	"huatuo-bamai/pkg/tracing"
)

type containerMemBurst struct {
	path      string
	limit     int
	history   []int
	index     int
	full      bool
	lastTrace time.Time
}

func (s *containerMemBurst) resetHistory() {
	if s == nil {
		return
	}
	// Missing samples invalidate the window, not the last successful trace.
	s.history = nil
	s.index = 0
	s.full = false
}

func (s *containerMemBurst) recordSample(dir string, current, limit int, cfg *MemBurstConfig, now time.Time) bool {
	if s.path != dir || s.limit != limit {
		s.resetHistory()
		s.path, s.limit = dir, limit
	}
	if len(s.history) == 0 {
		s.history = make([]int, cfg.SlidingWindowLength)
	}
	burst := recordMemoryBurst(current, limit, s.history, &s.index, &s.full,
		1+float64(cfg.DeltaMemoryBurst)/100, cfg.DeltaAnonThreshold)
	return burst && now.Sub(s.lastTrace) >= time.Duration(cfg.IntervalTracing)*time.Second
}

// Keep the existing host window semantics: newest vs oldest retained sample.
func recordMemoryBurst(current, total int, history []int, index *int, full *bool, ratio float64, threshold int) bool {
	history[*index] = current
	if *index == len(history)-1 {
		*full = true
	}
	*index = (*index + 1) % len(history)
	// Preserve the host's integer-KiB threshold without multiplication overflow.
	minimum := total/100*threshold + total%100*threshold/100
	return *full && float64(current) >= ratio*float64(history[*index]) &&
		current >= minimum
}

func (c *memBurstTracing) sampleContainers(cfg *MemBurstConfig, hostTotal int, now time.Time) {
	containers, err := pod.NormalContainers()
	if err != nil {
		for _, state := range c.containers {
			state.resetHistory()
		}
		log.WithError(err).Debug("discover memburst containers")
		return
	}
	manager, err := cgroups.NewManager()
	if err != nil {
		for _, state := range c.containers {
			state.resetHistory()
		}
		return
	}
	unified := cgroups.CgroupMode() == cgroups.Unified
	for id := range c.containers {
		if containers[id] == nil {
			delete(c.containers, id)
		}
	}
	for id, container := range containers {
		raw, err := manager.MemoryStatRaw(container.CgroupPath)
		if err != nil {
			c.containers[id].resetHistory()
			continue
		}
		root := paths.RootfsDefaultPath
		if !unified {
			root = filepath.Join(root, subsystem.SubsystemMemory)
		}
		dir := filepath.Join(root, container.CgroupPath)
		current, limit, err := containerBurstMemory(raw, root, dir, hostTotal, unified)
		if err != nil {
			c.containers[id].resetHistory()
			log.WithError(err).Debug("read container memburst memory")
			continue
		}
		state := c.containers[id]
		if state == nil {
			state = &containerMemBurst{}
			c.containers[id] = state
		}
		if !state.recordSample(dir, current, limit, cfg, now) {
			continue
		}
		procs, err := containerMemoryProcesses(dir, cfg.DumpProcessMaxNum)
		if err != nil {
			log.WithError(err).Debug("capture container memburst processes")
			continue
		}
		if len(procs) == 0 {
			continue
		}
		if err := tracing.Save(&tracing.WriteRequest{
			TracerName: "memburst", ContainerID: id, TracerTime: now,
			TracerData:    &MemoryTracingData{TopMemoryUsage: procs},
			TracerRunType: tracing.TracerRunTypeAutotracing,
		}); err != nil {
			log.WithError(err).Warn("save container memburst trace")
			continue
		}
		state.lastTrace = now
	}
}

func containerBurstMemory(raw map[string]uint64, root, dir string, hostTotal int, unified bool) (int, int, error) {
	prefix := "total_"
	if unified {
		prefix = ""
	}
	active, activeOK := raw[prefix+"active_anon"]
	inactive, inactiveOK := raw[prefix+"inactive_anon"]
	if !activeOK || !inactiveOK || hostTotal <= 0 {
		return 0, 0, fmt.Errorf("container memburst requires anonymous LRU counters and positive host MemTotal")
	}
	limit := uint64(hostTotal) * 1024
	if unified {
		for current := dir; ; current = filepath.Dir(current) {
			data, err := os.ReadFile(filepath.Join(current, "memory.max"))
			if err != nil {
				if current == root && os.IsNotExist(err) {
					break
				}
				return 0, 0, err
			}
			if text := strings.TrimSpace(string(data)); text != "max" {
				value, err := strconv.ParseUint(text, 10, 64)
				if err != nil {
					return 0, 0, err
				}
				limit = min(limit, value)
			}
			if current == root {
				break
			}
			if current == filepath.Dir(current) {
				return 0, 0, fmt.Errorf("memburst path %q outside cgroup root %q", dir, root)
			}
		}
	} else {
		value, ok := raw["hierarchical_memory_limit"]
		if !ok {
			return 0, 0, fmt.Errorf("memory.stat missing hierarchical_memory_limit")
		}
		limit = min(limit, value)
	}
	if limit < 1024 || inactive > uint64(^uint(0)>>1) || active > uint64(^uint(0)>>1)-inactive {
		return 0, 0, fmt.Errorf("container memburst memory counters or limit out of range")
	}
	return int((active + inactive) / 1024), int(limit / 1024), nil
}

func containerMemoryProcesses(dir string, topN int) ([]*processMemInfo, error) {
	seen := make(map[int32]bool)
	var procs []*process.Process
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		ids, err := pids.Tasks(path, "cgroup.procs")
		if err != nil {
			return err
		}
		for _, pid := range ids {
			if seen[pid] {
				continue
			}
			seen[pid] = true
			p, err := process.NewProcess(pid)
			if err == nil {
				procs = append(procs, p)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return topMemoryProcessList(procs, topN, memoryRSS), nil
}
