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

package memsnap

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const bootIDPath = "/proc/sys/kernel/random/boot_id"

type IdentityReader interface {
	Read(pid int) (ProcessIdentity, error)
}

type ProcIdentityReader struct {
	ProcRoot   string
	BootIDPath string
}

func (r ProcIdentityReader) Read(pid int) (ProcessIdentity, error) {
	if pid <= 0 {
		return ProcessIdentity{}, errors.New("pid must be greater than zero")
	}
	procRoot := r.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	bootPath := r.BootIDPath
	if bootPath == "" {
		bootPath = bootIDPath
	}
	stat, err := os.ReadFile(fmt.Sprintf("%s/%d/stat", procRoot, pid))
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("read process stat: %w", err)
	}
	starttime, err := ParseProcStatStartTime(stat)
	if err != nil {
		return ProcessIdentity{}, err
	}
	bootID, err := os.ReadFile(bootPath)
	if err != nil {
		return ProcessIdentity{}, fmt.Errorf("read boot ID: %w", err)
	}
	identity := ProcessIdentity{
		TGID: pid, StartTimeTicks: starttime, BootID: strings.TrimSpace(string(bootID)),
	}
	if err := identity.Validate(); err != nil {
		return ProcessIdentity{}, err
	}
	return identity, nil
}

// ParseProcStatStartTime handles spaces and parentheses in comm by parsing
// fields only after the final ')' delimiter. starttime is proc field 22.
func ParseProcStatStartTime(stat []byte) (uint64, error) {
	closing := strings.LastIndexByte(string(stat), ')')
	if closing < 0 || closing+1 >= len(stat) {
		return 0, errors.New("process stat has no comm terminator")
	}
	fields := strings.Fields(string(stat[closing+1:]))
	// The first suffix field is field 3 (state), so starttime is index 19.
	if len(fields) <= 19 {
		return 0, fmt.Errorf("process stat has %d suffix fields, need at least 20", len(fields))
	}
	starttime, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse process starttime %q: %w", fields[19], err)
	}
	if starttime == 0 {
		return 0, errors.New("process starttime must be greater than zero")
	}
	return starttime, nil
}

type Clock interface {
	Now() time.Time
	MonotonicNS() uint64
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

func (SystemClock) MonotonicNS() uint64 {
	var value unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &value); err != nil {
		return 0
	}
	return uint64(unix.TimespecToNsec(value))
}
