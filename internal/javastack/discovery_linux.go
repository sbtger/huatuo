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

package javastack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// ProcDiscoverer finds JVMs from a host procfs mount.
type ProcDiscoverer struct {
	procRoot string
}

// NewProcDiscoverer creates a procfs-backed Java process discoverer.
func NewProcDiscoverer(procRoot string) *ProcDiscoverer {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return &ProcDiscoverer{procRoot: procRoot}
}

// Discover returns processes whose executable or argv[0] is java.
func (d *ProcDiscoverer) Discover(ctx context.Context) ([]Target, error) {
	entries, err := os.ReadDir(d.procRoot)
	if err != nil {
		return nil, fmt.Errorf("javastack: read procfs %q: %w", d.procRoot, err)
	}
	pids := make([]int, 0, len(entries))
	for _, entry := range entries {
		pid, parseErr := strconv.Atoi(entry.Name())
		if entry.IsDir() && parseErr == nil && pid > 0 {
			pids = append(pids, pid)
		}
	}
	sort.Ints(pids)

	targets := make([]Target, 0)
	for _, pid := range pids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		target, inspectErr := d.inspectPID(pid)
		if inspectErr == nil {
			targets = append(targets, target)
		}
	}
	return targets, nil
}

func (d *ProcDiscoverer) inspectPID(pid int) (Target, error) {
	dir := filepath.Join(d.procRoot, strconv.Itoa(pid))
	startTime, err := readStartTimeTicks(filepath.Join(dir, "stat"))
	if err != nil {
		return Target{}, err
	}
	executable, _ := os.Readlink(filepath.Join(dir, "exe"))
	command := readArgv0(filepath.Join(dir, "cmdline"))
	if !isJavaCommand(executable) && !isJavaCommand(command) {
		return Target{}, errors.New("javastack: process is not Java")
	}
	return Target{
		Identity:   Identity{PID: uint32(pid), StartTimeTicks: startTime},
		Executable: strings.TrimSuffix(executable, " (deleted)"),
		Command:    command,
	}, nil
}

func isJavaCommand(command string) bool {
	return filepath.Base(strings.TrimSuffix(command, " (deleted)")) == "java"
}

func readArgv0(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if end := bytes.IndexByte(data, 0); end >= 0 {
		data = data[:end]
	}
	return string(data)
}

func readStartTimeTicks(path string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	closingParen := bytes.LastIndex(data, []byte(") "))
	if closingParen < 0 {
		return 0, errors.New("javastack: malformed proc stat command")
	}
	fields := bytes.Fields(data[closingParen+2:])
	if len(fields) <= 19 {
		return 0, errors.New("javastack: proc stat does not contain starttime")
	}
	startTime, err := strconv.ParseUint(string(fields[19]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("javastack: parse proc stat starttime: %w", err)
	}
	return startTime, nil
}
