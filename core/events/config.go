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
	"slices"
	"sync/atomic"
	"time"

	"huatuo-bamai/internal/matcher"
	"huatuo-bamai/internal/memsnap"
)

// BeforeOOMConfig controls event-driven runtime snapshots for
// container cgroups approaching their memory limit.
type BeforeOOMConfig struct {
	// Enabled is evaluated when the tracing registry is initialized. Publishing
	// a new runtime config does not rebuild that registry, so changing this value
	// takes effect only after huatuo-bamai restarts.
	Enabled          bool `default:"false"`
	ThresholdPercent int  `default:"90"`
	CooldownSeconds  int  `default:"300"`
	// CaptureTimeout names are kept for configuration compatibility. These
	// values are cooperative stop budgets, not wall-clock upper bounds; an
	// in-flight synchronous syscall cannot be interrupted by context cancellation.
	GoCaptureTimeoutMilliseconds     int `default:"100"`
	JavaCaptureTimeoutMilliseconds   int `default:"2000"`
	PythonCaptureTimeoutMilliseconds int `default:"2000"`
	TopK                             int `default:"10"`
}

// Config holds event tracing configuration.
type Config struct {
	SchedTick struct {
		// 10ms
		IntervalThreshold uint64 `default:"10000000"`
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

	BeforeOOMMemorySnapshot BeforeOOMConfig

	IssuesList [][]string
}

var currentConfig atomic.Pointer[Config]

func init() {
	currentConfig.Store(&Config{})
}

// Set atomically publishes an immutable copy of the events config. A nil
// argument resets it to the zero value.
func Set(c *Config) {
	currentConfig.Store(c.Clone())
}

func configSnapshot() *Config {
	return currentConfig.Load()
}

// Validate rejects invalid event tracing settings.
func (c *Config) Validate() error {
	if c.SchedTick.IntervalThreshold == 0 {
		return errors.New("scheduler tick interval threshold must be greater than zero")
	}
	if err := matcher.ValidateClassifications(c.IssuesList); err != nil {
		return fmt.Errorf("validating issues list: %w", err)
	}
	if err := validateBeforeOOMConfig(&c.BeforeOOMMemorySnapshot); err != nil {
		return fmt.Errorf("validating before-OOM memory snapshot: %w", err)
	}

	return nil
}

func validateBeforeOOMConfig(cfg *BeforeOOMConfig) error {
	const maxTimeDuration = time.Duration(1<<63 - 1)

	if cfg.ThresholdPercent <= 0 || cfg.ThresholdPercent > 100 {
		return fmt.Errorf("threshold percent must be in [1, 100], got %d",
			cfg.ThresholdPercent)
	}
	for _, duration := range []struct {
		name  string
		value int
		unit  time.Duration
	}{
		{"cooldown seconds", cfg.CooldownSeconds, time.Second},
		{"Go capture timeout milliseconds", cfg.GoCaptureTimeoutMilliseconds, time.Millisecond},
		{"Java capture timeout milliseconds", cfg.JavaCaptureTimeoutMilliseconds, time.Millisecond},
		{"Python capture timeout milliseconds", cfg.PythonCaptureTimeoutMilliseconds, time.Millisecond},
	} {
		if duration.value <= 0 {
			return fmt.Errorf("%s must be positive", duration.name)
		}
		if uint64(duration.value) > uint64(maxTimeDuration)/uint64(duration.unit) {
			return fmt.Errorf("%s overflows time.Duration: %d", duration.name,
				duration.value)
		}
	}
	if cfg.TopK <= 0 || cfg.TopK > memsnap.MaxTopK {
		return fmt.Errorf("snapshot top-K must be in [1, %d], got %d",
			memsnap.MaxTopK, cfg.TopK)
	}
	return nil
}

// Clone returns a deep copy suitable for immutable publication.
func (c *Config) Clone() *Config {
	if c == nil {
		return &Config{}
	}

	dst := *c
	dst.NetRxLatency.ExcludedContainerQos = slices.Clone(c.NetRxLatency.ExcludedContainerQos)
	dst.Dropwatch.ExcludeContainers = slices.Clone(c.Dropwatch.ExcludeContainers)
	dst.Netdev.DeviceList = slices.Clone(c.Netdev.DeviceList)
	dst.IssuesList = slices.Clone(c.IssuesList)
	for i := range dst.IssuesList {
		dst.IssuesList[i] = slices.Clone(c.IssuesList[i])
	}
	return &dst
}
