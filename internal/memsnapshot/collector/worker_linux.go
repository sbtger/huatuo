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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/ccfos/huatuo/internal/log"
	"github.com/ccfos/huatuo/internal/memsnapshot"
)

const (
	workerSlots        = 2
	workerLaunchScript = `set -eu; ulimit -n 128; printf '%s\n' "$$" > "$1"; exec "$2"`
)

// WorkerConfig selects a trusted installed helper and a dedicated cgroup subtree.
// CgroupRoot defaults to the memory-controller mount; it must not be a business cgroup.
type WorkerConfig struct {
	Executable string
	CgroupRoot string
}

type workerSetup struct {
	manager *WorkerManager
	err     error
}

var configuredWorker atomic.Pointer[workerSetup]

// UseWorker makes trigger captures use process isolation, including setup failures.
// The returned cleanup restores the previous collector only if still owned.
func UseWorker(manager *WorkerManager, setupErr error) func() {
	if manager == nil && setupErr == nil {
		setupErr = errors.New("memory snapshot worker manager is unavailable")
	}
	if setupErr != nil {
		setupErr = fmt.Errorf("memory snapshot worker unavailable: %w", setupErr)
	}
	state := &workerSetup{manager: manager, err: setupErr}
	previous := configuredWorker.Swap(state)
	return func() { configuredWorker.CompareAndSwap(state, previous) }
}

// WorkerManager retains a slot until Wait and descriptor cleanup complete.
// A timed-out or unreaped child never creates replacement capacity.
type WorkerManager struct {
	config      WorkerConfig
	directories [workerSlots]string
	lock        *os.File
	available   chan int
	notify      chan struct{}
	stop        chan struct{}
	stopped     chan struct{}
	mu          sync.Mutex
	closed      bool
	ready       [workerSlots]bool
	jobs        [workerSlots]*workerJob
	next        atomic.Uint64
}

type workerJob struct {
	mu      sync.Mutex
	process *os.Process
	output  *os.File
	stopped bool
}

func (job *workerJob) cancel() {
	job.mu.Lock()
	defer job.mu.Unlock()
	job.stopped = true
	if job.output != nil {
		_ = job.output.Close()
	}
	if job.process != nil {
		_ = job.process.Kill()
	}
}

// NewWorkerManager fails closed if helper, ownership or containment is unavailable.
func NewWorkerManager(config WorkerConfig) (*WorkerManager, error) {
	if !filepath.IsAbs(config.Executable) {
		return nil, errors.New("memory snapshot worker executable must be absolute")
	}
	info, err := os.Stat(config.Executable)
	if err != nil {
		return nil, fmt.Errorf("memory snapshot worker executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return nil, errors.New("memory snapshot worker helper is not executable")
	}
	directories, lock, err := prepareWorkerCgroups(config)
	if err != nil {
		return nil, err
	}
	manager := &WorkerManager{
		config: config, directories: directories, lock: lock,
		available: make(chan int, workerSlots), notify: make(chan struct{}, 1), stop: make(chan struct{}), stopped: make(chan struct{}),
	}
	manager.reconcile()
	go func() {
		defer func() { close(manager.stopped); manager.releaseClosedLock() }()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-manager.stop:
				return
			case <-ticker.C:
				manager.reconcile()
			}
		}
	}()
	return manager, nil
}

func (manager *WorkerManager) reconcile() {
	for slot, path := range manager.directories {
		manager.mu.Lock()
		eligible := !manager.closed && !manager.ready[slot] && manager.jobs[slot] == nil
		manager.mu.Unlock()
		if !eligible {
			continue
		}
		pids, err := workerCgroupPIDs(path)
		if err != nil || len(pids) != 0 {
			continue
		}
		manager.mu.Lock()
		if !manager.closed && !manager.ready[slot] && manager.jobs[slot] == nil {
			manager.ready[slot] = true
			manager.available <- slot
		}
		manager.mu.Unlock()
	}
}

func failedWorkerResult(process memsnapshot.ProcessInstanceID, started time.Time, err error) *Result {
	snapshot := memsnapshot.Failed("memory snapshot worker: " + err.Error())
	snapshot.DurationMS = uint64((time.Since(started) + time.Millisecond - 1) / time.Millisecond)
	_ = memsnapshot.LimitOutput(snapshot, 10)
	return &Result{Process: process, Language: memsnapshot.LanguageUnknown, SnapshotStartedAt: started.UTC(), Snapshot: snapshot}
}

// Snapshot bounds admission, startup, IPC, parsing and child completion together.
func (manager *WorkerManager) Snapshot(parent context.Context, process memsnapshot.ProcessInstanceID, options Options) (*Result, error) {
	options.setDefaults()
	if err := options.validate(); err != nil {
		return nil, err
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(parent, options.SnapshotTimeout)
	defer cancel()
	var slot int
	if options.WaitForCapture {
		select {
		case slot = <-manager.available:
		case <-manager.stop:
			return failedWorkerResult(process, started, errors.New("memory snapshot worker manager is closed")), nil
		case <-ctx.Done():
			if err := parent.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("%w: worker admission deadline exceeded", ErrCaptureBusy)
		}
	} else {
		select {
		case slot = <-manager.available:
		default:
			return nil, ErrCaptureBusy
		}
	}
	job := &workerJob{}
	manager.mu.Lock()
	manager.ready[slot] = false
	if manager.closed {
		manager.mu.Unlock()
		return failedWorkerResult(process, started, errors.New("memory snapshot worker manager is closed")), nil
	}
	manager.jobs[slot] = job
	manager.mu.Unlock()
	deadline, _ := ctx.Deadline()
	request := workerRequest{Version: workerProtocolVersion, ID: manager.next.Add(1), Deadline: deadline.UnixNano(), Request: memsnapshot.Request{
		Process: process, MaxMemoryObjectEntries: options.MaxMemoryObjectEntries, SamplingSeed: uint64(time.Now().UnixNano()),
	}}
	type outcome struct {
		response workerResponse
		err      error
	}
	done := make(chan outcome, 1)
	go func() {
		response, err := manager.run(job, slot, request)
		done <- outcome{response, err}
		manager.mu.Lock()
		manager.jobs[slot] = nil
		manager.mu.Unlock()
		select {
		case manager.notify <- struct{}{}:
		default:
		}
		manager.reconcile()
		manager.releaseClosedLock()
	}()
	select {
	case outcome := <-done:
		if err := parent.Err(); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			job.cancel()
			return failedWorkerResult(process, started, fmt.Errorf("memory snapshot worker deadline: %w", err)), nil
		}
		if outcome.err != nil {
			return failedWorkerResult(process, started, outcome.err), nil
		}
		return outcome.response.Result, nil
	case <-ctx.Done():
		job.cancel()
		if err := parent.Err(); err != nil {
			return nil, err
		}
		return failedWorkerResult(process, started, fmt.Errorf("memory snapshot worker deadline: %w", ctx.Err())), nil
	case <-manager.stop:
		job.cancel()
		return failedWorkerResult(process, started, errors.New("memory snapshot worker manager stopped")), nil
	}
}

func (manager *WorkerManager) run(job *workerJob, slot int, request workerRequest) (workerResponse, error) {
	var response workerResponse
	encoded, err := json.Marshal(request)
	if err != nil {
		return response, err
	}
	if len(encoded) > maxWorkerRequestBytes {
		return response, errors.New("memory snapshot worker request exceeds limit")
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return response, err
	}
	defer reader.Close()
	defer writer.Close()
	// Positional shell arguments avoid interpolating a path into executable code.
	// The shell joins the slot before exec starts the Go runtime.
	command := exec.Command("/bin/sh", "-c", workerLaunchScript,
		"huatuo-memsnapshot-launcher", filepath.Join(manager.directories[slot], "cgroup.procs"), manager.config.Executable)
	command.Stdin = bytes.NewReader(encoded)
	command.Stdout = writer
	command.Stderr = &workerStderr{remaining: maxWorkerStderrBytes}
	command.Env = append(os.Environ(), "GOMEMLIMIT=192MiB")
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	job.mu.Lock()
	if job.stopped {
		job.mu.Unlock()
		return response, context.Canceled
	}
	job.output = reader
	job.mu.Unlock()
	if err = command.Start(); err != nil {
		return response, fmt.Errorf("start memory snapshot worker: %w", err)
	}
	job.mu.Lock()
	job.process = command.Process
	if job.stopped {
		_ = command.Process.Kill()
	}
	job.mu.Unlock()
	_ = writer.Close()
	workerIdentity, _ := memsnapshot.ReadProcessInstanceID(command.Process.Pid)
	log.WithField("worker_pid", command.Process.Pid).WithField("worker_start_ticks", workerIdentity.StartTimeTicks).WithField("request_id", request.ID).WithField("target_pid", request.Request.Process.TGID).
		WithField("worker_slot", slot).Debug("memory snapshot worker started")
	err = decodeWorkerMessage(reader, maxWorkerReplyBytes, &response)
	if err != nil {
		job.cancel()
	}
	waitErr := command.Wait()
	log.WithField("worker_pid", command.Process.Pid).WithField("worker_start_ticks", workerIdentity.StartTimeTicks).WithField("request_id", request.ID).WithField("target_pid", request.Request.Process.TGID).
		WithField("worker_cpu_ns", command.ProcessState.UserTime().Nanoseconds()+command.ProcessState.SystemTime().Nanoseconds()).
		WithField("worker_slot", slot).Debug("memory snapshot worker reaped")
	if waitErr != nil {
		return response, fmt.Errorf("memory snapshot worker exited: %w", errors.Join(waitErr, err))
	}
	if err != nil {
		return response, fmt.Errorf("read memory snapshot worker response: %w", err)
	}
	if err = validateWorkerResponse(response, request); err != nil {
		return response, err
	}
	return response, nil
}

type workerStderr struct{ remaining int }

func (writer *workerStderr) Write(data []byte) (int, error) {
	length := len(data)
	if writer.remaining > 0 {
		n := min(len(data), writer.remaining)
		_, _ = os.Stderr.Write(data[:n])
		writer.remaining -= n
	}
	return length, nil
}

var _ io.Writer = (*workerStderr)(nil)

// Close returns by its caller deadline; populated cgroups stay reserved on restart.
func (manager *WorkerManager) Close(ctx context.Context) error {
	manager.mu.Lock()
	if !manager.closed {
		manager.closed = true
		close(manager.stop)
	}
	jobs := manager.jobs
	manager.mu.Unlock()
	for _, job := range jobs {
		if job != nil {
			job.cancel()
		}
	}
	var err error
	for {
		manager.mu.Lock()
		active := false
		for _, job := range manager.jobs {
			active = active || job != nil
		}
		manager.mu.Unlock()
		if !active {
			break
		}
		select {
		case <-manager.notify:
		case <-ctx.Done():
			err = ctx.Err()
		}
		if err != nil {
			break
		}
	}
	select {
	case <-manager.stopped:
	case <-ctx.Done():
		if err == nil {
			err = ctx.Err()
		}
	}
	manager.releaseClosedLock()
	return err
}

// IO cleanup can outlive a Close deadline even after the child has exited.
// Keep the shared lease until both the jobs and the reconciler are gone.
func (manager *WorkerManager) releaseClosedLock() {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if !manager.closed {
		return
	}
	for _, job := range manager.jobs {
		if job != nil {
			return
		}
	}
	select {
	case <-manager.stopped:
	default:
		return
	}
	if manager.lock != nil {
		_ = manager.lock.Close()
		manager.lock = nil
	}
}
