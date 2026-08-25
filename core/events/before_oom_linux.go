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
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"huatuo-bamai/internal/cgroups"
	"huatuo-bamai/internal/cgroups/paths"
	"huatuo-bamai/internal/cgroups/pids"
	"huatuo-bamai/internal/cgroups/subsystem"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/internal/memsnap"
	"huatuo-bamai/internal/memsnap/capturehelper"
	"huatuo-bamai/internal/procfs"
	"huatuo-bamai/internal/utils/parseutil"
	"huatuo-bamai/pkg/tracing"
	"huatuo-bamai/pkg/types"
)

const (
	beforeOOMTracer          = "before_oom_memory_snapshot"
	pressureArbitrationDelay = 20 * time.Millisecond
	runtimeDetectionTimeout  = time.Second
	inotifyBufferBytes       = 64 * 1024
	maxEpollEvents           = 64
)

var containerCgroupIDRegexp = regexp.MustCompile(
	`(?:cri-containerd-)?([0-9a-f]{64})(?:\.scope)?`,
)

func isBeforeOOMResourceExhaustion(err error) bool {
	return errors.Is(err, unix.EMFILE) || errors.Is(err, unix.ENFILE) ||
		errors.Is(err, unix.ENOSPC) || errors.Is(err, unix.ENOMEM)
}

func handleBeforeOOMWatchError(ctx context.Context, err error) error {
	if !isBeforeOOMResourceExhaustion(err) {
		return err
	}
	log.Errorf("before-OOM memory snapshot stopped after resource exhaustion; "+
		"increase process FD/inotify limits and restart huatuo-bamai to re-enable it: %v", err)
	// Keep Start blocked until shutdown so the generic event runner does not
	// repeatedly rebuild and rescan the whole cgroup tree.
	<-ctx.Done()
	return nil
}

type beforeOOMSnapshot struct {
	cgroup      cgroups.Cgroup
	lastSuccess time.Time
	lastFailure time.Time
}

type memcgCandidate struct {
	containerID string
	cgroupPath  string
	current     uint64
	max         uint64
	ratio       float64
}

type victimCandidate struct {
	pid         int
	comm        string
	oomScoreAdj int
	memoryBytes uint64
	score       float64
}

type beforeOOMData struct {
	CgroupPath         string            `json:"cgroup_path"`
	MemoryCurrent      uint64            `json:"memory_current"`
	MemoryMax          uint64            `json:"memory_max"`
	MemoryUsagePercent float64           `json:"memory_usage_percent"`
	VictimPID          int               `json:"victim_pid"`
	VictimProcessName  string            `json:"victim_process_name"`
	VictimOOMScoreAdj  int               `json:"victim_oom_score_adj"`
	Language           memsnap.Language  `json:"language"`
	Snapshot           *memsnap.Snapshot `json:"snapshot"`
}

func init() {
	tracing.RegisterEventTracing(beforeOOMTracer, newBeforeOOMSnapshot)
}

// The tracing registry invokes this factory only during its one-time
// initialization. Returning ErrNotSupported keeps a disabled tracer inactive;
// enabling it in a subsequently published config requires a process restart
// because the registry deliberately does not reconcile factories at runtime.
func newBeforeOOMSnapshot() (*tracing.EventTracingAttr, error) {
	if !configSnapshot().BeforeOOMMemorySnapshot.Enabled {
		return nil, types.ErrNotSupported
	}

	return &tracing.EventTracingAttr{
		TracingData: &beforeOOMSnapshot{},
		Interval:    5,
		Flag:        tracing.FlagTracing,
	}, nil
}

func (s *beforeOOMSnapshot) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return nil
	}
	cfg := configSnapshot().BeforeOOMMemorySnapshot
	if err := validateBeforeOOMConfig(&cfg); err != nil {
		return fmt.Errorf("invalid before-OOM memory snapshot config: %w", err)
	}
	if s.cgroup == nil {
		cgroup, err := cgroups.NewManager()
		if err != nil {
			return fmt.Errorf("create cgroup manager: %w", err)
		}
		s.cgroup = cgroup
	}
	return handleBeforeOOMWatchError(ctx, s.watchAndCapture(ctx, &cfg))
}

func (s *beforeOOMSnapshot) watchAndCapture(ctx context.Context,
	cfg *BeforeOOMConfig,
) error {
	watcher, err := newPressureWatcher(s.cgroup, cfg)
	if err != nil {
		return err
	}
	watchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	events, watcherDone := watcher.Run(watchCtx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-watcherDone:
			return err
		case event, ok := <-events:
			if !ok {
				return <-watcherDone
			}
			now := time.Now()
			if !s.captureAllowed(cfg, now) {
				continue
			}
			candidate, ok, err := s.bestCaptureCandidate(ctx, cfg, events, event)
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				log.Debugf("before-OOM pressure event skipped: %v", err)
				continue
			}
			if !ok {
				continue
			}
			usable, err := s.captureCandidate(ctx, cfg, &candidate)
			finished := time.Now()
			if err != nil {
				if errors.Is(err, context.Canceled) {
					return nil
				}
				s.lastFailure = finished
				log.Debugf("before-OOM memory snapshot skipped: %v", err)
				continue
			}
			if usable {
				s.lastSuccess = finished
				s.lastFailure = time.Time{}
			} else {
				s.lastFailure = finished
			}
		}
	}
}

func (s *beforeOOMSnapshot) captureAllowed(cfg *BeforeOOMConfig,
	now time.Time,
) bool {
	cooldown := time.Duration(cfg.CooldownSeconds) * time.Second
	if !s.lastSuccess.IsZero() && now.Sub(s.lastSuccess) < cooldown {
		return false
	}
	if !s.lastFailure.IsZero() && now.Sub(s.lastFailure) < cooldown {
		return false
	}
	return true
}

func (s *beforeOOMSnapshot) bestCaptureCandidate(ctx context.Context,
	cfg *BeforeOOMConfig, events <-chan memoryPressureEvent,
	first memoryPressureEvent,
) (memcgCandidate, bool, error) {
	pending := map[string]memoryPressureEvent{first.cgroupPath: first}
	timer := time.NewTimer(pressureArbitrationDelay)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return memcgCandidate{}, false, ctx.Err()
		case event, ok := <-events:
			if !ok {
				return s.highestPressureCandidate(cfg, pending)
			}
			pending[event.cgroupPath] = event
		case <-timer.C:
			return s.highestPressureCandidate(cfg, pending)
		}
	}
}

func (s *beforeOOMSnapshot) highestPressureCandidate(cfg *BeforeOOMConfig,
	events map[string]memoryPressureEvent,
) (memcgCandidate, bool, error) {
	var selected memcgCandidate
	var lastErr error
	found := false
	for _, event := range events {
		candidate, ok, err := s.pressureCandidate(event)
		if err != nil {
			lastErr = err
			continue
		}
		if !ok || candidate.containerID == "" || isUnlimitedLimit(candidate.max) {
			continue
		}
		candidate.ratio = float64(candidate.current) / float64(candidate.max)
		if candidate.ratio < float64(cfg.ThresholdPercent)/100 {
			continue
		}
		if !found || higherPressure(candidate, selected) {
			selected = candidate
			found = true
		}
	}
	if found {
		return selected, true, nil
	}
	return memcgCandidate{}, false, lastErr
}

func higherPressure(candidate, selected memcgCandidate) bool {
	if candidate.ratio != selected.ratio {
		return candidate.ratio > selected.ratio
	}
	if candidate.current != selected.current {
		return candidate.current > selected.current
	}
	return candidate.cgroupPath < selected.cgroupPath
}

func (s *beforeOOMSnapshot) pressureCandidate(
	event memoryPressureEvent,
) (memcgCandidate, bool, error) {
	usage, err := s.cgroup.MemoryUsage(event.cgroupPath)
	if err != nil {
		return memcgCandidate{}, false, fmt.Errorf("read cgroup memory usage: %w", err)
	}
	if usage == nil {
		return memcgCandidate{}, false, nil
	}
	return memcgCandidate{
		containerID: event.containerID, cgroupPath: event.cgroupPath,
		current: usage.Usage, max: usage.MaxLimited,
	}, true, nil
}

func (s *beforeOOMSnapshot) captureCandidate(ctx context.Context,
	cfg *BeforeOOMConfig, candidate *memcgCandidate,
) (bool, error) {
	victim, err := selectVictim(candidate.cgroupPath,
		candidate.max)
	if err != nil {
		return false, err
	}
	identity, err := memsnap.ReadProcessIdentity(victim.pid)
	if err != nil {
		return false, fmt.Errorf("read victim identity: %w", err)
	}

	// Detection and capture limits are soft time budgets, not hard wall-clock
	// upper bounds. The procfs, ELF, and process-memory APIs use synchronous reads
	// that cannot be interrupted after entering the kernel, and an in-flight
	// syscall may block without a time bound. While it is blocked, this serial
	// runner cannot consume later pressure events, advance cooldown, or finish
	// shutdown, and its single-slot event path may apply backpressure. After the
	// syscall returns, cancellation prevents subsequent reads. This lifecycle
	// limitation is accepted instead of adding a separately managed helper process
	// solely to enforce a hard deadline.
	detectionCtx, cancelDetection := context.WithTimeout(ctx,
		runtimeDetectionTimeout)
	language := memsnap.DetectLanguageFromPID(detectionCtx, victim.pid)
	detectionErr := detectionCtx.Err()
	cancelDetection()
	if detectionErr != nil {
		return false, fmt.Errorf("detect victim runtime: %w", detectionErr)
	}

	captureBudget := captureTimeout(cfg, language)
	captureCtx, cancelCapture := context.WithTimeout(ctx, captureBudget)
	defer cancelCapture()
	now := time.Now().UTC()
	seed := uint64(now.UnixNano())
	if seed == 0 {
		seed = 1
	}
	request := memsnap.Request{
		SamplingSeed: seed, Identity: identity, TopK: cfg.TopK,
	}
	snapshot := captureRuntime(captureCtx, language, request)
	if err := captureCtx.Err(); err != nil {
		return false, err
	}
	// Persistence follows the existing synchronous tracing.Save contract shared
	// by event tracers such as OOM and sched_tick, and is intentionally outside the
	// provider capture budget. A blocked storage backend can therefore delay later
	// before-OOM events and runner shutdown. Context-aware persistence should be
	// addressed for all tracing users rather than by adding a before-OOM-only save
	// path. The writer also resolves metadata at save time, so this best-effort
	// save may fail if the container exits.
	if err := tracing.Save(&tracing.WriteRequest{
		TracerName: beforeOOMTracer, ContainerID: candidate.containerID,
		TracerTime: now,
		TracerData: &beforeOOMData{
			CgroupPath:    candidate.cgroupPath,
			MemoryCurrent: candidate.current, MemoryMax: candidate.max,
			MemoryUsagePercent: candidate.ratio * 100,
			VictimPID:          victim.pid, VictimProcessName: victim.comm,
			VictimOOMScoreAdj: victim.oomScoreAdj, Language: language,
			Snapshot: snapshot,
		},
	}); err != nil {
		return false, err
	}
	return snapshot.Status == memsnap.StatusComplete ||
		snapshot.Status == memsnap.StatusPartial, nil
}

func captureRuntime(ctx context.Context, language memsnap.Language,
	request memsnap.Request,
) (snapshot *memsnap.Snapshot) {
	started := time.Now()
	defer func() {
		if recovered := recover(); recovered != nil {
			snapshot = memsnap.Failed(fmt.Sprintf("runtime capture panic: %v", recovered))
		}
		if snapshot == nil {
			snapshot = memsnap.Failed("runtime capture returned no result")
		}
		duration := time.Since(started)
		durationMS := uint64((duration + time.Millisecond - 1) / time.Millisecond)
		snapshot.DurationMS = durationMS
		if err := memsnap.LimitOutput(snapshot, request.TopK); err != nil {
			snapshot = memsnap.Failed("limit runtime capture output: " + err.Error())
			snapshot.DurationMS = durationMS
			// The fallback contains only bounded metadata; this second failure can
			// only come from an invalid TopK, which configuration validation rejects.
			if err := memsnap.LimitOutput(snapshot, request.TopK); err != nil {
				snapshot = memsnap.Failed("runtime capture output could not be bounded")
				snapshot.DurationMS = durationMS
			}
		}
	}()
	snapshot, err := capturehelper.Capture(ctx, language, request)
	if err != nil {
		return memsnap.Failed(err.Error())
	}
	return snapshot
}

func captureTimeout(cfg *BeforeOOMConfig,
	language memsnap.Language,
) time.Duration {
	milliseconds := cfg.GoCaptureTimeoutMilliseconds
	switch language {
	case memsnap.LanguageJava:
		milliseconds = cfg.JavaCaptureTimeoutMilliseconds
	case memsnap.LanguagePython:
		milliseconds = cfg.PythonCaptureTimeoutMilliseconds
	}
	return time.Duration(milliseconds) * time.Millisecond
}

func selectVictim(cgroupPath string,
	memoryMax uint64,
) (victimCandidate, error) {
	procs, err := memoryCgroupProcs(cgroupPath)
	if err != nil {
		return victimCandidate{}, fmt.Errorf("read cgroup processes: %w", err)
	}
	procFS, err := procfs.NewDefaultFS()
	if err != nil {
		return victimCandidate{}, fmt.Errorf("open procfs: %w", err)
	}
	var selected victimCandidate
	found := false
	for _, rawPID := range procs {
		proc, procErr := procFS.Proc(int(rawPID))
		if procErr != nil {
			continue
		}
		candidate, candidateErr := readVictimCandidate(proc, memoryMax)
		if candidateErr != nil {
			continue
		}
		if !found || candidate.score > selected.score ||
			(candidate.score == selected.score && candidate.memoryBytes > selected.memoryBytes) {
			selected = candidate
			found = true
		}
	}
	if !found {
		return victimCandidate{}, errors.New("cgroup has no OOM-killable process")
	}
	return selected, nil
}

func readVictimCandidate(proc procfs.Proc, memoryMax uint64) (victimCandidate, error) {
	status, err := proc.NewStatus()
	if err != nil {
		return victimCandidate{}, err
	}
	oomScoreAdjRaw, err := os.ReadFile(procfs.Path(strconv.Itoa(proc.PID),
		"oom_score_adj"))
	if err != nil {
		return victimCandidate{}, err
	}
	oomScoreAdj, err := strconv.Atoi(strings.TrimSpace(string(oomScoreAdjRaw)))
	if err != nil || oomScoreAdj <= -1000 {
		return victimCandidate{}, errors.New("process is not OOM-killable")
	}
	memoryBytes := oomMemoryBytes(status.VmRSS, status.VmSwap, status.VmPTE)
	score := float64(memoryBytes) + float64(oomScoreAdj)*float64(memoryMax)/1000
	if score < 0 {
		score = 0
	}
	return victimCandidate{
		pid: proc.PID, comm: status.Name, oomScoreAdj: oomScoreAdj,
		memoryBytes: memoryBytes, score: score,
	}, nil
}

func oomMemoryBytes(values ...uint64) uint64 {
	var total uint64
	for _, value := range values {
		if math.MaxUint64-total < value {
			return math.MaxUint64
		}
		total += value
	}
	return total
}

func memoryCgroupProcs(cgroupPath string) ([]int32, error) {
	switch mode := cgroups.CgroupMode(); mode {
	case cgroups.Legacy, cgroups.Hybrid:
		return pids.Tasks(paths.Path(subsystem.SubsystemMemory, cgroupPath),
			"cgroup.procs")
	case cgroups.Unified:
		return pids.Tasks(paths.Path(cgroupPath), "cgroup.procs")
	default:
		return nil, fmt.Errorf("unsupported cgroup mode %d", mode)
	}
}

type watchedCgroup struct {
	containerID  string
	cgroupPath   string
	eventFD      int
	inotifyWatch int
	eventsPath   string
	eventCount   uint64
}

type memoryPressureEvent struct {
	containerID string
	cgroupPath  string
}

type pressureWatcher struct {
	cgroup    cgroups.Cgroup
	cfg       *BeforeOOMConfig
	mode      cgroups.Mode
	root      string
	epollFD   int
	inotifyFD int
	controlFD int

	cgroups          map[string]*watchedCgroup
	pressureFDs      map[int]string
	inotifyWatches   map[int]string
	directoryWatches map[int]string
	directoryWatchFD map[string]int
}

func newPressureWatcher(cgroup cgroups.Cgroup,
	cfg *BeforeOOMConfig,
) (*pressureWatcher, error) {
	mode := cgroups.CgroupMode()
	if mode != cgroups.Legacy && mode != cgroups.Hybrid && mode != cgroups.Unified {
		return nil, fmt.Errorf("unsupported cgroup mode %d", mode)
	}
	root, err := memoryCgroupRoot(mode)
	if err != nil {
		return nil, err
	}

	epollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("create memory watcher epoll: %w", err)
	}
	inotifyFD, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		_ = unix.Close(epollFD)
		return nil, fmt.Errorf("create memory watcher inotify: %w", err)
	}
	controlFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		_ = unix.Close(inotifyFD)
		_ = unix.Close(epollFD)
		return nil, fmt.Errorf("create memory watcher control eventfd: %w", err)
	}
	for _, fd := range []int{inotifyFD, controlFD} {
		if err := unix.EpollCtl(epollFD, unix.EPOLL_CTL_ADD, fd,
			&unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
			_ = unix.Close(controlFD)
			_ = unix.Close(inotifyFD)
			_ = unix.Close(epollFD)
			return nil, fmt.Errorf("add memory watcher fd to epoll: %w", err)
		}
	}
	return &pressureWatcher{
		cgroup: cgroup, cfg: cfg, mode: mode, root: root,
		epollFD: epollFD, inotifyFD: inotifyFD, controlFD: controlFD,
		cgroups:          make(map[string]*watchedCgroup),
		pressureFDs:      make(map[int]string),
		inotifyWatches:   make(map[int]string),
		directoryWatches: make(map[int]string),
		directoryWatchFD: make(map[string]int),
	}, nil
}

func (w *pressureWatcher) Run(ctx context.Context) (
	<-chan memoryPressureEvent, <-chan error,
) {
	events := make(chan memoryPressureEvent, 1)
	done := make(chan error, 1)
	go func() {
		runCtx, cancel := context.WithCancel(ctx)
		controlDone := make(chan struct{})
		go w.forwardCancellation(runCtx, controlDone)
		runErr := w.loop(runCtx, events)
		cancel()
		<-controlDone
		w.close()
		if errors.Is(runErr, context.Canceled) {
			runErr = nil
		}
		done <- runErr
		close(done)
		close(events)
	}()
	return events, done
}

func (w *pressureWatcher) forwardCancellation(ctx context.Context,
	done chan<- struct{},
) {
	defer close(done)
	<-ctx.Done()
	signalEventFD(w.controlFD)
}

func (w *pressureWatcher) loop(ctx context.Context,
	events chan<- memoryPressureEvent,
) error {
	if err := w.refreshFromCgroupTree(ctx, events); err != nil {
		return err
	}

	epollEvents := make([]unix.EpollEvent, maxEpollEvents)
	for {
		n, err := unix.EpollWait(w.epollFD, epollEvents, -1)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("wait for cgroup memory event: %w", err)
		}
		for i := 0; i < n; i++ {
			fd := int(epollEvents[i].Fd)
			if fd == w.controlFD {
				if err := drainEventFD(fd); err != nil {
					return fmt.Errorf("drain memory watcher control eventfd: %w", err)
				}
				if err := ctx.Err(); err != nil {
					return err
				}
				continue
			}
			if fd == w.inotifyFD {
				if err := w.handleInotify(ctx, events); err != nil {
					return err
				}
				continue
			}
			cgroupPath, ok := w.pressureFDs[fd]
			if !ok {
				continue
			}
			if epollEvents[i].Events&(unix.EPOLLERR|unix.EPOLLHUP) != 0 {
				if err := w.recoverV1Watch(cgroupPath,
					fmt.Errorf("pressure eventfd closed (events=%#x)",
						epollEvents[i].Events)); err != nil {
					return err
				}
				continue
			}
			if err := drainEventFD(fd); err != nil {
				if recoverErr := w.recoverV1Watch(cgroupPath,
					fmt.Errorf("drain pressure eventfd: %w", err)); recoverErr != nil {
					return recoverErr
				}
				continue
			}
			if err := w.emitPressure(ctx, events, cgroupPath); err != nil {
				return err
			}
		}
	}
}

func (w *pressureWatcher) refreshFromCgroupTree(ctx context.Context,
	events chan<- memoryPressureEvent,
) error {
	desired := make(map[string]string)
	directories, err := w.walkCgroupTree(w.root, func(containerID,
		cgroupPath string,
	) error {
		desired[containerID] = cgroupPath
		return nil
	})
	if err != nil {
		return fmt.Errorf("discover before-OOM cgroups: %w", err)
	}
	w.reconcileDirectoryWatches(directories)
	addedPaths, err := w.reconcile(desired)
	if err != nil {
		return err
	}
	for _, cgroupPath := range addedPaths {
		if err := w.emitPressure(ctx, events, cgroupPath); err != nil {
			return err
		}
	}
	return nil
}

func (w *pressureWatcher) walkCgroupTree(start string,
	visitContainer func(containerID, cgroupPath string) error,
) (map[string]struct{}, error) {
	directories := make(map[string]struct{})
	err := filepath.WalkDir(start, func(currentPath string, entry fs.DirEntry,
		walkErr error,
	) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				if currentPath == start {
					return walkErr
				}
				return nil
			}
			return walkErr
		}
		if !entry.IsDir() {
			return nil
		}
		containerID := containerIDFromCgroupName(entry.Name())
		if containerID != "" {
			cgroupPath, err := relativeCgroupPath(w.root, currentPath)
			if err != nil {
				return err
			}
			if err := visitContainer(containerID, cgroupPath); err != nil {
				return err
			}
			return filepath.SkipDir
		}
		if err := w.addDirectoryWatch(currentPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return filepath.SkipDir
			}
			return fmt.Errorf("watch cgroup directory %q: %w", currentPath, err)
		}
		directories[currentPath] = struct{}{}
		return nil
	})
	return directories, err
}

func containerIDFromCgroupName(name string) string {
	match := containerCgroupIDRegexp.FindStringSubmatch(name)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func relativeCgroupPath(root, fullPath string) (string, error) {
	relativePath, err := filepath.Rel(root, fullPath)
	if err != nil {
		return "", err
	}
	return "/" + filepath.ToSlash(relativePath), nil
}

func (w *pressureWatcher) reconcile(desired map[string]string) ([]string, error) {
	var addedPaths []string
	for cgroupPath, entry := range w.cgroups {
		if desiredPath, ok := desired[entry.containerID]; !ok || desiredPath != cgroupPath {
			w.removeCgroup(cgroupPath)
		}
	}
	for containerID, cgroupPath := range desired {
		if containerID == "" || cgroupPath == "" {
			continue
		}
		added, err := w.watchContainer(containerID, cgroupPath)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		if added {
			addedPaths = append(addedPaths, cgroupPath)
		}
	}
	return addedPaths, nil
}

func (w *pressureWatcher) watchContainer(containerID,
	cgroupPath string,
) (bool, error) {
	if oldPath, ok := w.cgroupPathForContainer(containerID); ok {
		if oldPath == cgroupPath {
			return false, nil
		}
		w.removeCgroup(oldPath)
	}
	if entry, ok := w.cgroups[cgroupPath]; ok {
		entry.containerID = containerID
		return false, nil
	}
	return true, w.addCgroup(containerID, cgroupPath)
}

func (w *pressureWatcher) cgroupPathForContainer(containerID string) (string, bool) {
	for cgroupPath, entry := range w.cgroups {
		if entry.containerID == containerID {
			return cgroupPath, true
		}
	}
	return "", false
}

func (w *pressureWatcher) addCgroup(containerID, cgroupPath string) error {
	entry := &watchedCgroup{
		containerID: containerID, cgroupPath: cgroupPath,
		eventFD: -1, inotifyWatch: -1,
	}
	w.cgroups[cgroupPath] = entry
	var err error
	switch w.mode {
	case cgroups.Legacy, cgroups.Hybrid:
		err = w.addV1Cgroup(entry)
	case cgroups.Unified:
		err = w.addV2Cgroup(entry)
	}
	if err != nil {
		w.removeCgroup(cgroupPath)
		return fmt.Errorf("watch memory cgroup %q: %w", cgroupPath, err)
	}
	return nil
}

func (w *pressureWatcher) addV1Cgroup(entry *watchedCgroup) error {
	directory := w.memcgDir(entry.cgroupPath)
	if err := w.addInotify(entry, filepath.Join(directory,
		"memory.limit_in_bytes")); err != nil {
		return err
	}
	return w.rearmV1Threshold(entry)
}

func (w *pressureWatcher) rearmV1Threshold(entry *watchedCgroup) error {
	directory := w.memcgDir(entry.cgroupPath)
	usage, err := w.cgroup.MemoryUsage(entry.cgroupPath)
	if err != nil {
		return err
	}
	if usage == nil || isUnlimitedLimit(usage.MaxLimited) {
		w.removeEventFD(entry)
		return nil
	}
	threshold := percentOfLimit(usage.MaxLimited, w.cfg.ThresholdPercent)
	fd, err := registerV1Threshold(directory, threshold)
	if err != nil {
		return err
	}
	return w.addEventFD(entry, fd)
}

func (w *pressureWatcher) addV2Cgroup(entry *watchedCgroup) error {
	directory := w.memcgDir(entry.cgroupPath)
	eventsPath := filepath.Join(directory, "memory.events.local")
	if _, err := os.Stat(eventsPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("stat memory events %q: %w", eventsPath, err)
		}
		eventsPath = filepath.Join(directory, "memory.events")
	}
	// Cgroup v2 has no non-polling notification for an arbitrary
	// memory.current/memory.max ratio. Observe only memory.high pressure;
	// when memory.high is "max", the high counter does not increase and this
	// cgroup remains quiet until a finite memory.high is configured.
	eventCount, err := readMemoryEventCounter(eventsPath, "high")
	if err != nil {
		return err
	}
	entry.eventsPath = eventsPath
	entry.eventCount = eventCount
	return w.addInotify(entry, eventsPath)
}

func (w *pressureWatcher) addInotify(entry *watchedCgroup, filePath string) error {
	mask := uint32(unix.IN_MODIFY | unix.IN_ATTRIB | unix.IN_DELETE_SELF |
		unix.IN_MOVE_SELF)
	wd, err := unix.InotifyAddWatch(w.inotifyFD, filePath, mask)
	if err != nil {
		return err
	}
	entry.inotifyWatch = wd
	w.inotifyWatches[wd] = entry.cgroupPath
	return nil
}

func (w *pressureWatcher) addDirectoryWatch(directory string) error {
	if _, ok := w.directoryWatchFD[directory]; ok {
		return nil
	}
	mask := uint32(unix.IN_CREATE | unix.IN_DELETE | unix.IN_MOVED_FROM |
		unix.IN_MOVED_TO | unix.IN_DELETE_SELF | unix.IN_MOVE_SELF)
	wd, err := unix.InotifyAddWatch(w.inotifyFD, directory, mask)
	if err != nil {
		return err
	}
	if oldDirectory, ok := w.directoryWatches[wd]; ok {
		delete(w.directoryWatchFD, oldDirectory)
	}
	w.directoryWatches[wd] = directory
	w.directoryWatchFD[directory] = wd
	return nil
}

func (w *pressureWatcher) reconcileDirectoryWatches(desired map[string]struct{}) {
	for directory := range w.directoryWatchFD {
		if _, ok := desired[directory]; !ok {
			w.removeDirectoryWatch(directory)
		}
	}
}

func (w *pressureWatcher) removeDirectoryWatch(directory string) {
	wd, ok := w.directoryWatchFD[directory]
	if !ok {
		return
	}
	delete(w.directoryWatchFD, directory)
	delete(w.directoryWatches, wd)
	_, _ = unix.InotifyRmWatch(w.inotifyFD, uint32(wd))
}

func (w *pressureWatcher) addEventFD(entry *watchedCgroup, fd int) error {
	if err := unix.EpollCtl(w.epollFD, unix.EPOLL_CTL_ADD, fd,
		&unix.EpollEvent{Events: unix.EPOLLIN, Fd: int32(fd)}); err != nil {
		_ = unix.Close(fd)
		return err
	}
	oldFD := entry.eventFD
	entry.eventFD = fd
	w.pressureFDs[fd] = entry.cgroupPath
	if oldFD >= 0 {
		delete(w.pressureFDs, oldFD)
		_ = unix.EpollCtl(w.epollFD, unix.EPOLL_CTL_DEL, oldFD, nil)
		_ = unix.Close(oldFD)
	}
	return nil
}

func (w *pressureWatcher) removeEventFD(entry *watchedCgroup) {
	if entry.eventFD < 0 {
		return
	}
	delete(w.pressureFDs, entry.eventFD)
	_ = unix.EpollCtl(w.epollFD, unix.EPOLL_CTL_DEL, entry.eventFD, nil)
	_ = unix.Close(entry.eventFD)
	entry.eventFD = -1
}

func (w *pressureWatcher) handleInotify(ctx context.Context,
	events chan<- memoryPressureEvent,
) error {
	buffer := make([]byte, inotifyBufferBytes)
	for {
		n, err := unix.Read(w.inotifyFD, buffer)
		if err == unix.EAGAIN {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read cgroup memory inotify: %w", err)
		}
		for offset := 0; offset+unix.SizeofInotifyEvent <= n; {
			wd := int(int32(binary.NativeEndian.Uint32(buffer[offset : offset+4])))
			mask := binary.NativeEndian.Uint32(buffer[offset+4 : offset+8])
			nameLength := int(binary.NativeEndian.Uint32(buffer[offset+12 : offset+16]))
			nameStart := offset + unix.SizeofInotifyEvent
			nameEnd := nameStart + nameLength
			name := strings.TrimRight(string(buffer[nameStart:nameEnd]), "\x00")
			offset += unix.SizeofInotifyEvent + nameLength
			if mask&unix.IN_Q_OVERFLOW != 0 {
				if err := w.handleInotifyOverflow(ctx, events); err != nil {
					return err
				}
				continue
			}
			if directory, ok := w.directoryWatches[wd]; ok {
				if err := w.handleCgroupDirectoryEvent(ctx, events, directory,
					name, mask); err != nil {
					return err
				}
				continue
			}
			cgroupPath, ok := w.inotifyWatches[wd]
			if !ok {
				continue
			}
			if mask&(unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_IGNORED) != 0 {
				w.removeCgroup(cgroupPath)
				continue
			}
			emit, handleErr := w.handleMemoryChange(cgroupPath)
			if handleErr != nil {
				if errors.Is(handleErr, os.ErrNotExist) {
					w.removeCgroup(cgroupPath)
					continue
				}
				if isBeforeOOMResourceExhaustion(handleErr) {
					return handleErr
				}
				if w.mode == cgroups.Unified {
					// Keep the v2 watch and the last observed counter. A later
					// memory.events modification retries the read and catches the
					// cumulative high-counter increase.
					log.Debugf("memory pressure watch for cgroup %q retained after read error: %v",
						cgroupPath, handleErr)
					continue
				}
				if err := w.recoverV1Watch(cgroupPath, handleErr); err != nil {
					return err
				}
				continue
			}
			if emit {
				if err := w.emitPressure(ctx, events, cgroupPath); err != nil {
					return err
				}
			}
		}
	}
}

func (w *pressureWatcher) handleCgroupDirectoryEvent(ctx context.Context,
	events chan<- memoryPressureEvent, directory, name string, mask uint32,
) error {
	if mask&(unix.IN_DELETE_SELF|unix.IN_MOVE_SELF|unix.IN_IGNORED) != 0 {
		if directory == w.root {
			return fmt.Errorf("memory cgroup root %q disappeared: %w",
				directory, os.ErrNotExist)
		}
		w.removeCgroupTree(directory)
		return nil
	}
	if mask&unix.IN_ISDIR == 0 || name == "" {
		return nil
	}
	target := filepath.Join(directory, name)
	if mask&(unix.IN_DELETE|unix.IN_MOVED_FROM) != 0 {
		w.removeCgroupTree(target)
	}
	if mask&(unix.IN_CREATE|unix.IN_MOVED_TO) == 0 {
		return nil
	}
	_, err := w.walkCgroupTree(target, func(containerID, cgroupPath string) error {
		added, watchErr := w.watchContainer(containerID, cgroupPath)
		if watchErr != nil {
			if errors.Is(watchErr, os.ErrNotExist) {
				return nil
			}
			return watchErr
		}
		if added {
			return w.emitPressure(ctx, events, cgroupPath)
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (w *pressureWatcher) removeCgroupTree(directory string) {
	for cgroupPath := range w.cgroups {
		if pathWithin(directory, w.memcgDir(cgroupPath)) {
			w.removeCgroup(cgroupPath)
		}
	}
	for watchedDirectory := range w.directoryWatchFD {
		if pathWithin(directory, watchedDirectory) {
			w.removeDirectoryWatch(watchedDirectory)
		}
	}
}

func pathWithin(parent, path string) bool {
	relative, err := filepath.Rel(parent, path)
	return err == nil && relative != ".." &&
		!strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func (w *pressureWatcher) handleMemoryChange(cgroupPath string) (bool, error) {
	switch w.mode {
	case cgroups.Legacy, cgroups.Hybrid:
		entry, ok := w.cgroups[cgroupPath]
		if !ok {
			return false, nil
		}
		if err := w.rearmV1Threshold(entry); err != nil {
			return false, err
		}
		return true, nil
	case cgroups.Unified:
		return w.observeV2EventIncrease(cgroupPath)
	default:
		return false, nil
	}
}

func (w *pressureWatcher) handleInotifyOverflow(ctx context.Context,
	events chan<- memoryPressureEvent,
) error {
	w.rebuildAll()
	return w.refreshFromCgroupTree(ctx, events)
}

func (w *pressureWatcher) observeV2EventIncrease(cgroupPath string) (bool, error) {
	entry, ok := w.cgroups[cgroupPath]
	if !ok || entry.eventsPath == "" {
		return false, nil
	}
	eventCount, err := readMemoryEventCounter(entry.eventsPath, "high")
	if err != nil {
		return false, err
	}
	increased := eventCount > entry.eventCount
	entry.eventCount = eventCount
	return increased, nil
}

func (w *pressureWatcher) rebuildAll() {
	for cgroupPath := range w.cgroups {
		w.removeCgroup(cgroupPath)
	}
}

func (w *pressureWatcher) emitPressure(ctx context.Context,
	events chan<- memoryPressureEvent, cgroupPath string,
) error {
	entry, ok := w.cgroups[cgroupPath]
	if !ok || entry.containerID == "" {
		return nil
	}
	select {
	case events <- memoryPressureEvent{
		containerID: entry.containerID, cgroupPath: entry.cgroupPath,
	}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *pressureWatcher) removeCgroup(cgroupPath string) {
	entry, ok := w.cgroups[cgroupPath]
	if !ok {
		return
	}
	delete(w.cgroups, cgroupPath)
	w.removeEventFD(entry)
	if entry.inotifyWatch >= 0 {
		delete(w.inotifyWatches, entry.inotifyWatch)
		_, _ = unix.InotifyRmWatch(w.inotifyFD, uint32(entry.inotifyWatch))
	}
}

func (w *pressureWatcher) recoverV1Watch(cgroupPath string, cause error) error {
	entry, ok := w.cgroups[cgroupPath]
	if !ok {
		return nil
	}
	w.removeEventFD(entry)
	if err := w.rearmV1Threshold(entry); err == nil {
		log.Debugf("memory pressure watch for cgroup %q restored after error: %v",
			cgroupPath, cause)
		return nil
	} else {
		w.removeCgroup(cgroupPath)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("restore memory pressure watch for cgroup %q after %w: %w",
			cgroupPath, cause, err)
	}
}

func (w *pressureWatcher) close() {
	for cgroupPath := range w.cgroups {
		w.removeCgroup(cgroupPath)
	}
	for directory := range w.directoryWatchFD {
		w.removeDirectoryWatch(directory)
	}
	if w.inotifyFD >= 0 {
		_ = unix.Close(w.inotifyFD)
		w.inotifyFD = -1
	}
	if w.controlFD >= 0 {
		_ = unix.Close(w.controlFD)
		w.controlFD = -1
	}
	if w.epollFD >= 0 {
		_ = unix.Close(w.epollFD)
		w.epollFD = -1
	}
}

func drainEventFD(fd int) error {
	var buffer [8]byte
	for {
		_, err := unix.Read(fd, buffer[:])
		if err == unix.EINTR {
			continue
		}
		if err == unix.EAGAIN || err == nil {
			return nil
		}
		return err
	}
}

func signalEventFD(fd int) {
	var buffer [8]byte
	binary.NativeEndian.PutUint64(buffer[:], 1)
	for {
		_, err := unix.Write(fd, buffer[:])
		if err == unix.EINTR {
			continue
		}
		if err != nil && err != unix.EAGAIN {
			log.Debugf("signal memory watcher control eventfd: %v", err)
		}
		return
	}
}

func memoryCgroupRoot(mode cgroups.Mode) (string, error) {
	var root string
	switch mode {
	case cgroups.Legacy, cgroups.Hybrid:
		root = cgroups.RootFsFilePath(subsystem.SubsystemMemory)
	case cgroups.Unified:
		root = cgroups.RootfsDefaultPath()
	default:
		return "", fmt.Errorf("unsupported cgroup mode %d", mode)
	}
	realRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", fmt.Errorf("resolve memory cgroup root %q: %w", root, err)
	}
	return realRoot, nil
}

func (w *pressureWatcher) memcgDir(cgroupPath string) string {
	cleanPath := strings.TrimPrefix(filepath.Clean("/"+cgroupPath), "/")
	return filepath.Join(w.root, cleanPath)
}

func registerV1Threshold(directory string, threshold uint64) (int, error) {
	eventFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		return -1, err
	}
	usageFile, err := os.Open(filepath.Join(directory, "memory.usage_in_bytes"))
	if err != nil {
		_ = unix.Close(eventFD)
		return -1, err
	}
	defer usageFile.Close()
	eventControl, err := os.OpenFile(filepath.Join(directory, "cgroup.event_control"),
		os.O_WRONLY, 0)
	if err != nil {
		_ = unix.Close(eventFD)
		return -1, err
	}
	_, writeErr := fmt.Fprintf(eventControl, "%d %d %d", eventFD,
		usageFile.Fd(), threshold)
	closeErr := eventControl.Close()
	if writeErr != nil {
		_ = unix.Close(eventFD)
		return -1, writeErr
	}
	if closeErr != nil {
		_ = unix.Close(eventFD)
		return -1, closeErr
	}
	return eventFD, nil
}

func percentOfLimit(limit uint64, percent int) uint64 {
	return limit/100*uint64(percent) + limit%100*uint64(percent)/100
}

func isUnlimitedLimit(limit uint64) bool {
	return limit == 0 || limit == math.MaxUint64 ||
		limit >= uint64(math.MaxInt64)-(1<<20)
}

func readMemoryEventCounter(eventsPath, counter string) (uint64, error) {
	events, err := parseutil.RawKV(eventsPath)
	if err != nil {
		return 0, fmt.Errorf("read memory events %q: %w", eventsPath, err)
	}
	count, ok := events[counter]
	if !ok {
		return 0, fmt.Errorf("memory events %q has no %s counter", eventsPath, counter)
	}
	return count, nil
}
