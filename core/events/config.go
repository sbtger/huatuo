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

package events

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sync/atomic"
)

type OOMRuntimeSnapshotFilter struct {
	Included []string
	Excluded []string
}

type OOMRuntimeSnapshotConfig struct {
	Enabled bool
	// Deprecated storage fields are retained so existing configuration files
	// continue to load. Runtime snapshots are now embedded in the original OOM
	// tracing document and are not persisted separately.
	RootDirectory string `default:"/var/lib/huatuo/runtime-snapshots"`
	// Deprecated: kept for compatibility with old config layouts.
	// Runtime snapshots are now embedded in the original OOM document.
	KernelGateDevice               string `default:"/dev/huatuo_oom_snapshot"`
	GateTimeoutMilliseconds        int64  `default:"50"`
	CaptureCooldownMilliseconds    int64  `default:"30000"`
	FailureCooldownMilliseconds    int64  `default:"60000"`
	MaxFailureCooldownMilliseconds int64  `default:"300000"`
	MaxConcurrentGates             int    `default:"1"` // Deprecated; first-wins is fixed at one.
	MaxOutputBytes                 int64  `default:"1048576"`
	MaxObjects                     int    `default:"100000"`
	MaxStacks                      int    `default:"4096"`
	MaxStackDepth                  int    `default:"64"`
	// Deprecated: kept for compatibility; retention is no longer managed
	// by the snapshot runtime.
	RetentionCountPerTarget int `default:"3"`
	// Deprecated: kept for compatibility; retention is no longer managed
	// by the snapshot runtime.
	RetentionTTLSeconds int `default:"86400"`
	// Deprecated: kept for compatibility; retention is no longer managed
	// by the snapshot runtime.
	MaxStorageBytes int64 `default:"1073741824"`
	Filter          OOMRuntimeSnapshotFilter
}

func (c *OOMRuntimeSnapshotConfig) Validate() error {
	// Limits are validated even when the gate is disabled: the live PUT
	// /config path publishes them into the BPF map without re-validation, so
	// an invalid "disabled" configuration must not become activatable later.
	if c.GateTimeoutMilliseconds <= 0 || c.GateTimeoutMilliseconds > 50 ||
		c.CaptureCooldownMilliseconds < 0 ||
		c.FailureCooldownMilliseconds <= 0 ||
		c.MaxFailureCooldownMilliseconds < c.FailureCooldownMilliseconds ||
		c.MaxConcurrentGates != 1 ||
		c.MaxOutputBytes < 4096 || c.MaxObjects <= 0 || c.MaxStacks <= 0 ||
		c.MaxStackDepth <= 0 {
		return errors.New("OOM runtime snapshot limits are invalid")
	}
	for _, value := range c.Filter.Included {
		if _, err := regexp.Compile(value); err != nil {
			return fmt.Errorf("OOM runtime snapshot included filter %q is invalid: %w",
				value, err)
		}
	}
	for _, value := range c.Filter.Excluded {
		if _, err := regexp.Compile(value); err != nil {
			return fmt.Errorf("OOM runtime snapshot excluded filter %q is invalid: %w",
				value, err)
		}
	}
	return nil
}

// Config holds event tracing configuration.
type Config struct {
	OOMRuntimeSnapshot OOMRuntimeSnapshotConfig
	Softirq            struct {
		// 10ms
		DisabledThreshold uint64 `default:"10000000"`
	}

	MemoryReclaim struct {
		// 900ms
		BlockedThreshold uint64 `default:"900000000"`
	}

	NetRxLatency struct {
		Driver2NetRx             uint64 `default:"5"`
		Driver2TCP               uint64 `default:"10"`
		Driver2Userspace         uint64 `default:"115"`
		ExcludedHostNetnamespace bool   `default:"true"`
		ExcludedContainerQos     []string
	}

	Dropwatch struct {
		Filter             string `default:"tcp"`
		MaxEventsPerSecond uint64 `default:"100"`
		ExcludeContainers  []string
	}

	TCPRetransmit struct {
		Filter             string `default:""`
		EnableTLP          bool   `default:"false"`
		MaxEventsPerSecond uint64 `default:"100"`
	}

	Netdev struct {
		DeviceList []string
	}

	Ras struct {
		MceThrBackoff int64 `default:"1800"`
	}

	IssuesList [][]string
}

func (c *Config) Validate() error {
	return c.OOMRuntimeSnapshot.Validate()
}

var (
	currentConfig                                    atomic.Pointer[Config]
	oomRuntimeSnapshotGateTimeoutMilliseconds        atomic.Int64
	oomRuntimeSnapshotCaptureCooldownMilliseconds    atomic.Int64
	oomRuntimeSnapshotFailureCooldownMilliseconds    atomic.Int64
	oomRuntimeSnapshotMaxFailureCooldownMilliseconds atomic.Int64
)

func init() {
	currentConfig.Store(&Config{})
}

// Set atomically publishes an immutable copy of the events config. A nil
// argument resets it to the zero value.
func Set(c *Config) {
	snapshot := c.Clone()
	currentConfig.Store(snapshot)
	oomRuntimeSnapshotGateTimeoutMilliseconds.Store(
		snapshot.OOMRuntimeSnapshot.GateTimeoutMilliseconds)
	oomRuntimeSnapshotCaptureCooldownMilliseconds.Store(
		snapshot.OOMRuntimeSnapshot.CaptureCooldownMilliseconds)
	oomRuntimeSnapshotFailureCooldownMilliseconds.Store(
		snapshot.OOMRuntimeSnapshot.FailureCooldownMilliseconds)
	oomRuntimeSnapshotMaxFailureCooldownMilliseconds.Store(
		snapshot.OOMRuntimeSnapshot.MaxFailureCooldownMilliseconds)
	if service := activeOOMRuntimeSnapshot.Load(); service != nil {
		service.refreshBPFConfig()
	}
}

func configSnapshot() *Config {
	return currentConfig.Load()
}

// Clone returns a deep copy suitable for immutable publication.
func (c *Config) Clone() *Config {
	if c == nil {
		return &Config{}
	}

	dst := *c
	dst.OOMRuntimeSnapshot.Filter.Included = slices.Clone(
		c.OOMRuntimeSnapshot.Filter.Included)
	dst.OOMRuntimeSnapshot.Filter.Excluded = slices.Clone(
		c.OOMRuntimeSnapshot.Filter.Excluded)
	dst.NetRxLatency.ExcludedContainerQos = slices.Clone(c.NetRxLatency.ExcludedContainerQos)
	dst.Dropwatch.ExcludeContainers = slices.Clone(c.Dropwatch.ExcludeContainers)
	dst.Netdev.DeviceList = slices.Clone(c.Netdev.DeviceList)
	dst.IssuesList = slices.Clone(c.IssuesList)
	for i := range dst.IssuesList {
		dst.IssuesList[i] = slices.Clone(c.IssuesList[i])
	}
	return &dst
}

// currentOOMRuntimeSnapshotGateTimeoutMilliseconds returns the live timeout
// used for newly received OOM gate requests. Set updates it atomically so the
// generic PUT /config path can change the budget without restarting Huatuo.
func currentOOMRuntimeSnapshotGateTimeoutMilliseconds() int64 {
	return oomRuntimeSnapshotGateTimeoutMilliseconds.Load()
}

// currentOOMRuntimeSnapshotCaptureCooldownMilliseconds returns the live
// first-wins cooldown. Zero disables cooldown without disabling busy rejection.
func currentOOMRuntimeSnapshotCaptureCooldownMilliseconds() int64 {
	return oomRuntimeSnapshotCaptureCooldownMilliseconds.Load()
}

func currentOOMRuntimeSnapshotFailureCooldownMilliseconds() int64 {
	return oomRuntimeSnapshotFailureCooldownMilliseconds.Load()
}

func currentOOMRuntimeSnapshotMaxFailureCooldownMilliseconds() int64 {
	return oomRuntimeSnapshotMaxFailureCooldownMilliseconds.Load()
}
