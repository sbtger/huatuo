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

	"huatuo-bamai/internal/goheap"
)

// OOMGoHeapConfig controls the optional pre-exit Go heap snapshot path.
type OOMGoHeapConfig struct {
	Enabled                   bool   `default:"false"`
	CaptureBudgetMicroseconds uint64 `default:"2000"`
	ReconcileIntervalSeconds  uint64 `default:"10"`
	MaxTargets                int    `default:"4096"`
}

// Validate rejects settings that could make the optional exit hook unbounded.
func (c OOMGoHeapConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if c.CaptureBudgetMicroseconds == 0 || c.CaptureBudgetMicroseconds > 10000 {
		return errors.New("capture budget must be between 1 and 10000 microseconds")
	}
	if c.ReconcileIntervalSeconds == 0 {
		return errors.New("reconcile interval must be greater than zero seconds")
	}
	if c.MaxTargets <= 0 || c.MaxTargets > goheap.DefaultMaxTargets {
		return fmt.Errorf("maximum targets must be between 1 and %d", goheap.DefaultMaxTargets)
	}
	return nil
}

// Config holds event tracing configuration.
type Config struct {
	Softirq struct {
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

	OOMGoHeap OOMGoHeapConfig

	IssuesList [][]string
}

// Validate checks event-tracing settings that have operational bounds.
func (c Config) Validate() error {
	if err := c.OOMGoHeap.Validate(); err != nil {
		return fmt.Errorf("validating OOM Go heap config: %w", err)
	}
	return nil
}

var cfg = &Config{}

// Set sets the events config. A nil argument resets to the zero value so
// callers never need to nil-check cfg.
func Set(c *Config) {
	if c == nil {
		cfg = &Config{}
		return
	}
	cfg = c
}
