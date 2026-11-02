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

//go:build integration && linux

package collector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/ccfos/huatuo/internal/memsnapshot"
)

func workerFixture(t *testing.T, mode string) (*WorkerManager, string, string) {
	t.Helper()
	parent := os.Getenv("HUATUO_MEMSNAP_WORKER_CGROUP_PARENT")
	if parent == "" || os.Geteuid() != 0 {
		t.Skip("requires isolated root Linux cgroup parent")
	}
	root := filepath.Join(parent, fmt.Sprintf("huatuo-memsnapshot-worker-test-%d", time.Now().UnixNano()))
	directory := t.TempDir()
	executable := filepath.Join(directory, "huatuo-memsnapshot-worker")
	ready := filepath.Join(directory, "ready")
	writeWorkerFixture(t, executable, ready, mode)
	manager, err := NewWorkerManager(WorkerConfig{Executable: executable, CgroupRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := manager.Close(ctx); err != nil {
			t.Error(err)
		}
		for i := 0; i < 2; i++ {
			if err := os.Remove(filepath.Join(root, strconv.Itoa(i))); err != nil {
				t.Error(err)
			}
		}
		if err := os.Remove(root); err != nil {
			t.Error(err)
		}
	})
	return manager, executable, ready
}

func writeWorkerFixture(t *testing.T, executable, ready, mode string) {
	t.Helper()
	script := fmt.Sprintf(`#!/usr/bin/python3
import datetime,json,os,resource,sys,time
assert resource.getrlimit(resource.RLIMIT_NOFILE)==(128,128), "worker descriptor limit not applied before exec"
request=json.load(sys.stdin)
with open(%q,'a') as f:f.write(str(os.getpid())+'\n')
mode=%q
if mode=='block':time.sleep(60)
if mode=='early':sys.exit(7)
if mode=='stderr':sys.stderr.write('x'*1024);sys.stderr.flush()
if mode=='stderr_oversized':sys.stderr.write('x'*(2<<20));sys.stderr.flush()
if mode=='oom':allocation=bytearray(400<<20)
if mode=='oversized':
 sys.stdout.write('x'*((1<<20)+1));sys.stdout.flush();time.sleep(60)
if mode=='malformed':sys.stdout.write('{');sys.exit(0)
response={'version':1,'id':request['id'],'result':{'Process':request['request']['identity'],'Language':'unknown','SnapshotStartedAt':datetime.datetime.now(datetime.timezone.utc).isoformat(),'Snapshot':{'status':'unavailable','status_reason':'fixture','duration_ms':0}}}
if mode=='identity':response['result']['Process']['start_time_ticks']+=1
if mode=='version':response['version']=99
json.dump(response,sys.stdout)
if mode=='trailing':sys.stdout.write('{}')
`, ready, mode)
	temporary := executable + ".new"
	if err := os.WriteFile(temporary, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(temporary, executable); err != nil {
		t.Fatal(err)
	}
}

func readyWorkerPIDs(t *testing.T, ready string, n int) []int {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		data, _ := os.ReadFile(ready)
		lines := strings.Fields(string(data))
		if len(lines) >= n {
			pids := make([]int, 0, len(lines))
			for _, line := range lines {
				pid, err := strconv.Atoi(line)
				if err != nil {
					t.Fatal(err)
				}
				pids = append(pids, pid)
			}
			return pids
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("worker never reached private request")
	return nil
}

func workerGone(t *testing.T, pid int) {
	t.Helper()
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
		if os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("worker %d not reaped", pid)
}

func TestWorkerSubprocessTimeoutAndHealthyCapacity(t *testing.T) {
	manager, executable, ready := workerFixture(t, "block")
	process := processInstanceIDForTest(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := manager.Snapshot(ctx, process, Options{SnapshotTimeout: 3 * time.Second})
		done <- err
	}()
	pids := readyWorkerPIDs(t, ready, 1)
	writeWorkerFixture(t, executable, ready, "ok")
	result, err := manager.Snapshot(t.Context(), process, Options{SnapshotTimeout: time.Second})
	if err != nil || result == nil || result.Snapshot.Status != memsnapshot.SnapshotStatusUnavailable {
		t.Fatalf("healthy target blocked by independent worker: %+v %v", result, err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation: %v", err)
	}
	workerGone(t, pids[0])
}

func TestWorkerSubprocessBoundsAndReaping(t *testing.T) {
	for _, mode := range []string{"block", "early", "oversized", "malformed", "identity", "version", "trailing"} {
		t.Run(mode, func(t *testing.T) {
			manager, _, ready := workerFixture(t, mode)
			started := time.Now()
			result, err := manager.Snapshot(t.Context(), processInstanceIDForTest(t), Options{SnapshotTimeout: 300 * time.Millisecond})
			if time.Since(started) > time.Second {
				t.Fatal("caller exceeded bounded deadline")
			}
			if err != nil || result == nil || result.Snapshot.Status != memsnapshot.SnapshotStatusFailed {
				t.Fatalf("failed worker accepted: %+v %v", result, err)
			}
			for _, pid := range readyWorkerPIDs(t, ready, 1) {
				workerGone(t, pid)
			}
		})
	}
}

func TestWorkerSubprocessBusyAdmission(t *testing.T) {
	manager, _, ready := workerFixture(t, "block")
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{}, 2)
	for i := 0; i < 2; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _ = manager.Snapshot(ctx, processInstanceIDForTest(t), Options{SnapshotTimeout: 5 * time.Second})
		}()
	}
	pids := readyWorkerPIDs(t, ready, 2)
	started := time.Now()
	result, err := manager.Snapshot(t.Context(), processInstanceIDForTest(t), Options{SnapshotTimeout: time.Second})
	if result != nil || !errors.Is(err, ErrCaptureBusy) || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("excess admission: %+v %v", result, err)
	}
	cancel()
	<-done
	<-done
	for _, pid := range pids {
		workerGone(t, pid)
	}
}

func TestWorkerCgroupLockAndForeignProcessProtection(t *testing.T) {
	manager, executable, _ := workerFixture(t, "ok")
	config := manager.config
	root := filepath.Dir(manager.directories[0])
	if second, err := NewWorkerManager(config); err == nil {
		_ = second.Close(context.Background())
		t.Fatal("second manager acquired node slots")
	}
	if _, err := manager.Snapshot(t.Context(), processInstanceIDForTest(t), Options{}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", "-c", `printf '%s\n' "$$" > "$1"; exec /bin/sleep 60`, "foreign-test", filepath.Join(root, "0", "cgroup.procs"))
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		pids, _ := workerCgroupPIDs(filepath.Join(root, "0"))
		if len(pids) > 0 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if second, err := NewWorkerManager(WorkerConfig{Executable: executable, CgroupRoot: root}); err == nil {
		_ = second.Close(context.Background())
		t.Fatal("foreign member accepted")
	}
	if err := command.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("foreign process was signaled: %v", err)
	}
}

func TestWorkerCgroupOOMLeavesTargetAlive(t *testing.T) {
	manager, executable, ready := workerFixture(t, "oom")
	process := processInstanceIDForTest(t)
	result, err := manager.Snapshot(t.Context(), process, Options{SnapshotTimeout: 3 * time.Second})
	if err != nil || result == nil || result.Snapshot.Status != memsnapshot.SnapshotStatusFailed {
		t.Fatalf("unbounded memory allocation succeeded: %+v %v", result, err)
	}
	for _, pid := range readyWorkerPIDs(t, ready, 1) {
		workerGone(t, pid)
	}
	if err := memsnapshot.ValidateProcessInstanceID(process); err != nil {
		t.Fatal("worker OOM affected target:", err)
	}
	killed := false
	for _, path := range manager.directories {
		for _, name := range []string{"memory.failcnt", "memory.memsw.failcnt", "memory.oom_control", "memory.events"} {
			data, err := os.ReadFile(filepath.Join(path, name))
			if err != nil {
				continue
			}
			t.Logf("slot %s %s: %s", filepath.Base(path), name, strings.TrimSpace(string(data)))
			if name != "memory.oom_control" && name != "memory.events" {
				continue
			}
			for _, line := range strings.Split(string(data), "\n") {
				fields := strings.Fields(line)
				if len(fields) == 2 && fields[0] == "oom_kill" {
					count, parseErr := strconv.ParseUint(fields[1], 10, 64)
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					killed = killed || count > 0
				}
			}
		}
	}
	if !killed {
		t.Fatal("worker memory cap has no kernel oom_kill witness")
	}
	writeWorkerFixture(t, executable, ready, "ok")
	if result, err := manager.Snapshot(t.Context(), process, Options{SnapshotTimeout: time.Second}); err != nil || result.Snapshot.Status == memsnapshot.SnapshotStatusFailed {
		t.Fatalf("worker did not recover after OOM: %+v %v", result, err)
	}
}

func TestWorkerCgroupRestartReconcilesResidualHelper(t *testing.T) {
	manager, executable, ready := workerFixture(t, "block")
	config := manager.config
	if err := manager.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	request := workerRequest{Version: 1, ID: 1, Deadline: time.Now().Add(time.Minute).UnixNano(), Request: memsnapshot.Request{Process: processInstanceIDForTest(t), MaxMemoryObjectEntries: 7}}
	encoded, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", "-c", workerLaunchScript, "residual-test", filepath.Join(manager.directories[0], "cgroup.procs"), executable)
	command.Stdin = strings.NewReader(string(encoded))
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	pids := readyWorkerPIDs(t, ready, 1)
	second, err := NewWorkerManager(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := second.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	_ = command.Wait()
	workerGone(t, pids[0])
	writeWorkerFixture(t, executable, ready, "ok")
	result, err := second.Snapshot(t.Context(), processInstanceIDForTest(t), Options{WaitForCapture: true, SnapshotTimeout: time.Second})
	if err != nil || result.Snapshot.Status == memsnapshot.SnapshotStatusFailed {
		t.Fatalf("residual helper prevented new capture: %+v %v", result, err)
	}
}

func TestWorkerLiveGoProvider(t *testing.T) {
	helper := os.Getenv("HUATUO_MEMSNAP_WORKER_BINARY")
	if helper == "" {
		t.Skip("requires built shipping helper")
	}
	manager, _, _ := workerFixture(t, "ok")
	config := manager.config
	config.Executable = helper
	if err := manager.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	realManager, err := NewWorkerManager(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := realManager.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	before := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	t.Cleanup(func() { runtime.MemProfileRate = before })
	allocation := make([]byte, 2<<20)
	allocation[0] = 1
	runtime.GC()
	runtime.GC()
	result, err := realManager.Snapshot(t.Context(), processInstanceIDForTest(t), Options{MaxMemoryObjectEntries: 7, SnapshotTimeout: 2 * time.Second})
	runtime.KeepAlive(allocation)
	if err != nil || result == nil || result.Language != memsnapshot.LanguageGo || result.Snapshot.Status != memsnapshot.SnapshotStatusComplete || len(result.Snapshot.Entries) == 0 {
		t.Fatalf("shipping worker Go capture failed: %+v %v", result, err)
	}
}

func TestWorkerRejectsForeignDescendantCgroups(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(strconv.FormatBool(nested), func(t *testing.T) {
			manager, _, _ := workerFixture(t, "ok")
			config := manager.config
			if err := manager.Close(t.Context()); err != nil {
				t.Fatal(err)
			}
			parent := filepath.Dir(manager.directories[0])
			if nested {
				parent = manager.directories[0]
			}
			foreign := filepath.Join(parent, "foreign")
			if err := os.Mkdir(foreign, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := os.Remove(foreign); err != nil {
					t.Error(err)
				}
			})
			if next, err := NewWorkerManager(config); err == nil {
				_ = next.Close(t.Context())
				t.Fatal("unknown descendant cgroup accepted")
			}
		})
	}
}

func TestWorkerHelperArgumentDoesNotProveOwnership(t *testing.T) {
	manager, executable, _ := workerFixture(t, "ok")
	config := manager.config
	if err := manager.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("/bin/sh", "-c", `printf '%s\n' "$$" > "$1"; exec /usr/bin/python3 -c 'import time; time.sleep(60)' "$2"`, "foreign-argument", filepath.Join(manager.directories[0], "cgroup.procs"), executable)
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = command.Process.Kill(); _ = command.Wait() })
	until := time.Now().Add(time.Second)
	for time.Now().Before(until) {
		data, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", command.Process.Pid))
		pids, _ := workerCgroupPIDs(manager.directories[0])
		member := false
		for _, pid := range pids {
			member = member || pid == command.Process.Pid
		}
		if strings.HasPrefix(string(data), "/usr/bin/python3\x00-c\x00") && member {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if next, err := NewWorkerManager(config); err == nil {
		_ = next.Close(t.Context())
		t.Fatal("foreign process identified by arbitrary helper argument")
	}
	if err := command.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("foreign process was killed", err)
	}
}

func TestWorkerCloseRetainsLockUntilStderrDrains(t *testing.T) {
	manager, _, _ := workerFixture(t, "stderr")
	var fds [2]int
	if err := unix.Pipe2(fds[:], unix.O_NONBLOCK|unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	reader, writer := os.NewFile(uintptr(fds[0]), "blocked-stderr-reader"), os.NewFile(uintptr(fds[1]), "blocked-stderr-writer")
	for {
		_, err := unix.Write(fds[1], make([]byte, 4096))
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	previous := os.Stderr
	os.Stderr = writer
	t.Cleanup(func() {
		_ = writer.Close()
		_ = reader.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = manager.Close(ctx)
		os.Stderr = previous
	})
	result, err := manager.Snapshot(t.Context(), processInstanceIDForTest(t), Options{SnapshotTimeout: 300 * time.Millisecond})
	if err != nil || result.Snapshot.Status != memsnapshot.SnapshotStatusFailed {
		t.Fatalf("blocked stderr did not bound caller: %+v %v", result, err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := manager.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected pending IO at close: %v", err)
	}
	if next, err := NewWorkerManager(manager.config); err == nil {
		_ = next.Close(t.Context())
		t.Fatal("ownership released before child IO cleanup")
	}
}

func TestWorkerActualReadAfterTargetExitReturnsESRCH(t *testing.T) {
	helper, business := os.Getenv("HUATUO_MEMSNAP_FAULT_WORKER_BINARY"), os.Getenv("HUATUO_MEMSNAP_BUSINESS_BINARY")
	if helper == "" || business == "" {
		t.Skip("requires fault helper and Go fixture")
	}
	manager, _, _ := workerFixture(t, "ok")
	config := manager.config
	config.Executable = helper
	if err := manager.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	realManager, err := NewWorkerManager(config)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	output, err := os.Create(filepath.Join(directory, "business.log"))
	if err != nil {
		t.Fatal(err)
	}
	target := exec.Command(business, "1")
	target.Stdout = output
	target.Stderr = output
	if err := target.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Process.Kill(); _ = target.Wait(); _ = output.Close() })
	faultfile := filepath.Join(directory, "fault.json")
	spec := fmt.Sprintf(`{"pid":%d,"action":"pause","id":"exit-read"}`, target.Process.Pid)
	if err := os.WriteFile(faultfile, []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HUATUO_MEMSNAP_FAULT_FILE", faultfile)
	logfile, err := os.Create(filepath.Join(directory, "helper.log"))
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stderr
	os.Stderr = logfile
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := realManager.Close(ctx); err != nil {
			t.Error(err)
		}
		os.Stderr = previous
		_ = logfile.Close()
	})
	process, err := memsnapshot.ReadProcessInstanceID(target.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		result, err := realManager.Snapshot(t.Context(), process, Options{SnapshotTimeout: 3 * time.Second})
		if err == nil && (result == nil || result.Snapshot.Status != memsnapshot.SnapshotStatusFailed) {
			err = fmt.Errorf("dead target capture not failed: %+v", result)
		}
		done <- err
	}()
	marker := "MEMSNAP_FAULT id=exit-read action=pause"
	reached := false
	until := time.Now().Add(2 * time.Second)
	for time.Now().Before(until) {
		data, _ := os.ReadFile(logfile.Name())
		if strings.Contains(string(data), marker) {
			reached = true
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !reached {
		data, _ := os.ReadFile(logfile.Name())
		t.Fatalf("read pause not reached: %s", data)
	}
	if err := target.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = target.Wait()
	spec = fmt.Sprintf(`{"pid":%d,"action":"mark","id":"exit-read"}`, target.Process.Pid)
	if err := os.WriteFile(faultfile+".new", []byte(spec), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(faultfile+".new", faultfile); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := realManager.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(logfile.Name())
	if !strings.Contains(string(data), "MEMSNAP_READ_RESULT id=exit-read") || !strings.Contains(string(data), "err=no such process") {
		t.Fatalf("actual kernel ESRCH missing: %s", data)
	}
}

func TestWorkerProviderPanicPreservesProtocol(t *testing.T) {
	helper := os.Getenv("HUATUO_MEMSNAP_FAULT_WORKER_BINARY")
	if helper == "" {
		t.Skip("requires test-only fault worker")
	}
	manager, _, _ := workerFixture(t, "ok")
	config := manager.config
	config.Executable = helper
	if err := manager.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	faultfile := filepath.Join(t.TempDir(), "fault.json")
	fault := fmt.Sprintf(`{"pid":%d,"action":"panic","id":"protocol-panic"}`, os.Getpid())
	if err := os.WriteFile(faultfile, []byte(fault), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HUATUO_MEMSNAP_FAULT_FILE", faultfile)
	actual, err := NewWorkerManager(config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := actual.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	result, err := actual.Snapshot(t.Context(), processInstanceIDForTest(t), Options{SnapshotTimeout: 2 * time.Second})
	if err != nil || result == nil || result.Language != memsnapshot.LanguageGo || result.ProcessMemory == nil || result.Snapshot.Status != memsnapshot.SnapshotStatusFailed || !strings.Contains(result.Snapshot.StatusReason, "runtime snapshot panic: test-only runtime snapshot panic") {
		t.Fatalf("panic diagnostic corrupted worker protocol: result=%+v err=%v", result, err)
	}
}

func TestWorkerStderrFloodIsBoundedAndDrained(t *testing.T) {
	manager, _, _ := workerFixture(t, "stderr_oversized")
	output, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stderr
	os.Stderr = output
	t.Cleanup(func() { os.Stderr = previous; _ = output.Close() })
	result, err := manager.Snapshot(t.Context(), processInstanceIDForTest(t), Options{SnapshotTimeout: 2 * time.Second})
	if err != nil || result == nil || result.Snapshot.Status == memsnapshot.SnapshotStatusFailed {
		t.Fatalf("stderr flood prevented a valid reply: %+v %v", result, err)
	}
	info, err := output.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 64<<10 {
		t.Fatalf("forwarded stderr bytes = %d, want 65536", info.Size())
	}
}
