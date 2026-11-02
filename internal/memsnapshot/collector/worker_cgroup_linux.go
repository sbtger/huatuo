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
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// WorkerMemoryLimitBytes is a hard per-slot limit, independent of target cgroups.
const WorkerMemoryLimitBytes = 256 << 20

func defaultWorkerCgroupRoot() (string, error) {
	data, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	unified := ""
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, " - ", 2)
		if len(parts) != 2 {
			continue
		}
		left, right := strings.Fields(parts[0]), strings.Fields(parts[1])
		if len(left) < 5 || len(right) < 3 {
			continue
		}
		mount := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\134`, `\`).Replace(left[4])
		if right[0] == "cgroup2" {
			unified = mount
		}
		if right[0] == "cgroup" {
			for _, controller := range strings.Split(right[2], ",") {
				if controller == "memory" {
					return filepath.Join(mount, "huatuo-memsnapshot-worker"), nil
				}
			}
		}
	}
	if unified != "" {
		return filepath.Join(unified, "huatuo-memsnapshot-worker"), nil
	}
	return "", errors.New("memory snapshot worker requires a memory cgroup mount")
}

func workerCgroupPIDs(path string) ([]int, error) {
	data, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	var pids []int
	for _, value := range strings.Fields(string(data)) {
		pid, err := strconv.Atoi(value)
		if err != nil || pid <= 0 {
			return nil, errors.New("invalid worker cgroup process list")
		}
		pids = append(pids, pid)
	}
	return pids, nil
}

func prepareWorkerCgroups(config WorkerConfig) (directories [workerSlots]string, lock *os.File, failure error) {
	root := config.CgroupRoot
	if root == "" {
		var err error
		root, err = defaultWorkerCgroupRoot()
		if err != nil {
			return directories, nil, err
		}
	}
	if !filepath.IsAbs(root) || !strings.HasPrefix(filepath.Base(root), "huatuo-memsnapshot-worker") {
		return directories, nil, errors.New("memory snapshot worker cgroup must be an absolute dedicated huatuo-memsnapshot-worker subtree")
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(filepath.Dir(root), &fs); err != nil {
		return directories, nil, err
	}
	if fs.Type != unix.CGROUP_SUPER_MAGIC && fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return directories, nil, errors.New("memory snapshot worker containment is not a cgroup filesystem")
	}
	if os.Geteuid() != 0 {
		return directories, nil, errors.New("memory snapshot worker cgroup setup requires root")
	}
	var created []string
	defer func() {
		if failure != nil {
			if lock != nil {
				_ = lock.Close()
			}
			for i := len(created) - 1; i >= 0; i-- {
				_ = os.Remove(created[i])
			}
		}
	}()
	create := func(path string) error {
		err := os.Mkdir(path, 0o755)
		if err == nil {
			created = append(created, path)
		} else if !os.IsExist(err) {
			return err
		}
		var stat unix.Stat_t
		if err := unix.Lstat(path, &stat); err != nil {
			return err
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR || stat.Uid != 0 {
			return errors.New("worker cgroup path is not a root-owned directory")
		}
		return nil
	}
	if err := create(root); err != nil {
		return directories, nil, err
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return directories, nil, err
	}
	lock = os.NewFile(uintptr(fd), root)
	// The cgroup inode is shared across mount namespaces, unlike a private /run lock.
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return directories, lock, fmt.Errorf("lock memory snapshot worker subtree: %w", err)
	}
	pids, err := workerCgroupPIDs(root)
	if err != nil || len(pids) != 0 {
		return directories, lock, errors.New("worker cgroup root must be empty")
	}
	if err := validateWorkerSubtree(root); err != nil {
		return directories, lock, err
	}
	if fs.Type == unix.CGROUP2_SUPER_MAGIC {
		if _, err := os.Stat(filepath.Join(root, "memory.max")); err != nil {
			return directories, lock, fmt.Errorf("worker parent must delegate memory controller: %w", err)
		}
		if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("+memory"), 0); err != nil {
			return directories, lock, err
		}
	}
	var residual []*os.Process
	defer func() {
		for _, process := range residual {
			_ = process.Release()
		}
	}()
	for slot := range directories {
		directories[slot] = filepath.Join(root, strconv.Itoa(slot))
		if err := create(directories[slot]); err != nil {
			return directories, lock, err
		}
		processes, err := ownedResidualWorkers(directories[slot], config.Executable)
		if err != nil {
			return directories, lock, err
		}
		residual = append(residual, processes...)
	}
	for _, process := range residual {
		if err := process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return directories, lock, fmt.Errorf("terminate residual worker: %w", err)
		}
	}
	setLimit := func(path string, limit int) error {
		limits := map[string]string{}
		if fs.Type == unix.CGROUP2_SUPER_MAGIC {
			limits["memory.max"] = strconv.Itoa(limit)
			limits["memory.swap.max"] = "0"
			limits["memory.oom.group"] = "1"
		} else {
			limits["memory.limit_in_bytes"] = strconv.Itoa(limit)
			if _, err := os.Stat(filepath.Join(path, "memory.memsw.limit_in_bytes")); err == nil {
				limits["memory.memsw.limit_in_bytes"] = strconv.Itoa(limit)
			}
		}
		// Set memory before memsw: memsw must never be lower than memory.
		memoryFile := "memory.limit_in_bytes"
		if fs.Type == unix.CGROUP2_SUPER_MAGIC {
			memoryFile = "memory.max"
		}
		if err := os.WriteFile(filepath.Join(path, memoryFile), []byte(strconv.Itoa(limit)), 0); err != nil {
			return err
		}
		delete(limits, memoryFile)
		for name, value := range limits {
			if err := os.WriteFile(filepath.Join(path, name), []byte(value), 0); err != nil {
				return fmt.Errorf("set worker %s: %w", name, err)
			}
		}
		return nil
	}
	if err := setLimit(root, workerSlots*WorkerMemoryLimitBytes); err != nil {
		return directories, lock, err
	}
	for _, path := range directories {
		if err := setLimit(path, WorkerMemoryLimitBytes); err != nil {
			return directories, lock, err
		}
	}
	return directories, lock, nil
}

// A reserved root contains exactly its two leaf slots, never foreign descendants.
func validateWorkerSubtree(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if entry.Name() != "0" && entry.Name() != "1" {
			return fmt.Errorf("unexpected child cgroup %s; refusing to constrain foreign workloads", entry.Name())
		}
		children, err := os.ReadDir(filepath.Join(root, entry.Name()))
		if err != nil {
			return err
		}
		for _, child := range children {
			if child.IsDir() {
				return errors.New("worker slots must be leaf cgroups; foreign descendant refused")
			}
		}
	}
	return nil
}

func residualExecutableMatches(pid int, path, executable string) bool {
	image, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return false
	}
	image = strings.TrimSuffix(image, " (deleted)")
	expected, err := filepath.EvalSymlinks(executable)
	if err != nil {
		return false
	}
	if image == expected {
		return true
	}
	command, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	argv := bytes.Split(bytes.TrimRight(command, "\x00"), []byte{0})
	// Kernel script execution names the configured script in a fixed position.
	// An arbitrary later argument must never establish process ownership.
	file, err := os.Open(executable)
	if err == nil {
		prefix := make([]byte, 512)
		n, _ := file.Read(prefix)
		_ = file.Close()
		first := strings.SplitN(string(prefix[:n]), "\n", 2)[0]
		if strings.HasPrefix(first, "#!") {
			fields := strings.Fields(strings.TrimPrefix(first, "#!"))
			if len(fields) == 1 && filepath.IsAbs(fields[0]) {
				interpreter, err := filepath.EvalSymlinks(fields[0])
				if err == nil && image == interpreter && len(argv) == 2 && string(argv[1]) == executable {
					return true
				}
			}
		}
	}
	shell, err := filepath.EvalSymlinks("/bin/sh")
	return err == nil && image == shell && len(argv) == 6 && string(argv[1]) == "-c" && string(argv[2]) == workerLaunchScript &&
		string(argv[3]) == "huatuo-memsnapshot-launcher" && string(argv[4]) == filepath.Join(path, "cgroup.procs") && string(argv[5]) == executable
}

func ownedResidualWorkers(path, executable string) (owned []*os.Process, failure error) {
	pids, err := workerCgroupPIDs(path)
	if err != nil {
		return nil, err
	}
	defer func() {
		if failure != nil {
			for _, process := range owned {
				_ = process.Release()
			}
		}
	}()
	for _, pid := range pids {
		process, err := os.FindProcess(pid)
		if err != nil {
			return owned, err
		}
		members, err := workerCgroupPIDs(path)
		if err != nil {
			_ = process.Release()
			return owned, err
		}
		member := false
		for _, current := range members {
			member = member || current == pid
		}
		if !member {
			_ = process.Release()
			continue
		}
		if !residualExecutableMatches(pid, path, executable) {
			_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
			_ = process.Release()
			if os.IsNotExist(err) {
				continue
			}
			return owned, fmt.Errorf("unexpected executable for process %d in worker cgroup; refusing to signal", pid)
		}
		owned = append(owned, process)
	}
	return owned, nil
}
