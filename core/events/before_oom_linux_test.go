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
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"huatuo-bamai/internal/cgroups"
	"huatuo-bamai/internal/cgroups/stats"
	"huatuo-bamai/internal/memsnap"
	"huatuo-bamai/pkg/types"
)

func TestBeforeOOMDisabledByDefault(t *testing.T) {
	previous := configSnapshot()
	t.Cleanup(func() { Set(previous) })

	Set(&Config{})
	if attr, err := newBeforeOOMSnapshot(); attr != nil || !errors.Is(err, types.ErrNotSupported) {
		t.Fatalf("newBeforeOOMSnapshot() = (%v, %v), want (nil, ErrNotSupported)", attr, err)
	}

	Set(&Config{BeforeOOMMemorySnapshot: BeforeOOMConfig{Enabled: true}})
	attr, err := newBeforeOOMSnapshot()
	if err != nil {
		t.Fatal(err)
	}
	if attr == nil || attr.TracingData == nil {
		t.Fatalf("newBeforeOOMSnapshot() = %#v, want initialized tracing attribute", attr)
	}
}

func TestBeforeOOMStartCanceled(t *testing.T) {
	previous := configSnapshot()
	t.Cleanup(func() { Set(previous) })
	Set(&Config{BeforeOOMMemorySnapshot: BeforeOOMConfig{
		ThresholdPercent: 90, CooldownSeconds: 300,
		GoCaptureTimeoutMilliseconds: 100, JavaCaptureTimeoutMilliseconds: 2000,
		PythonCaptureTimeoutMilliseconds: 2000, TopK: 10,
	}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() {
		done <- (&beforeOOMSnapshot{}).Start(ctx)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Start did not return after cancellation")
	}
}

func TestBeforeOOMResourceExhaustionStopsUntilShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- handleBeforeOOMWatchError(ctx,
			fmt.Errorf("create inotify: %w", unix.ENOSPC))
	}()

	select {
	case err := <-done:
		t.Fatalf("resource exhaustion returned before shutdown: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("resource exhaustion did not stop after shutdown")
	}
}

func TestBeforeOOMOrdinaryWatchErrorIsRetried(t *testing.T) {
	err := fmt.Errorf("watch cgroup: %w", unix.EIO)
	if got := handleBeforeOOMWatchError(context.Background(), err); !errors.Is(got, unix.EIO) {
		t.Fatalf("watch error = %v, want EIO", got)
	}
}

func TestBeforeOOMResourceExhaustionErrors(t *testing.T) {
	for _, err := range []error{unix.EMFILE, unix.ENFILE, unix.ENOSPC, unix.ENOMEM} {
		if !isBeforeOOMResourceExhaustion(fmt.Errorf("wrapped: %w", err)) {
			t.Errorf("%v was not classified as resource exhaustion", err)
		}
	}
	if isBeforeOOMResourceExhaustion(unix.EIO) {
		t.Fatal("EIO was classified as resource exhaustion")
	}
}

func TestOOMMemoryBytes(t *testing.T) {
	if got, want := oomMemoryBytes(100*1024, 20*1024, 4*1024), uint64(124*1024); got != want {
		t.Fatalf("process OOM memory = %d, want %d", got, want)
	}
}

func TestBeforeOOMConfig(t *testing.T) {
	cfg := BeforeOOMConfig{
		ThresholdPercent: 90, CooldownSeconds: 300,
		GoCaptureTimeoutMilliseconds: 100, JavaCaptureTimeoutMilliseconds: 2000,
		PythonCaptureTimeoutMilliseconds: 2000, TopK: 10,
	}
	if err := validateBeforeOOMConfig(&cfg); err != nil {
		t.Fatal(err)
	}
	cfg.ThresholdPercent = 101
	if err := validateBeforeOOMConfig(&cfg); err == nil {
		t.Fatal("expected invalid threshold error")
	}
	cfg.ThresholdPercent = 90
	cfg.TopK = 0
	if err := validateBeforeOOMConfig(&cfg); err == nil {
		t.Fatal("expected invalid top-K error")
	}
}

func TestBeforeOOMConfigDurationBounds(t *testing.T) {
	if uint64(^uint(0)) != math.MaxUint64 {
		t.Skip("duration overflow values require a 64-bit int")
	}

	validConfig := func() BeforeOOMConfig {
		return BeforeOOMConfig{
			ThresholdPercent: 90, CooldownSeconds: 300,
			GoCaptureTimeoutMilliseconds: 100, JavaCaptureTimeoutMilliseconds: 2000,
			PythonCaptureTimeoutMilliseconds: 2000, TopK: 10,
		}
	}
	maxDuration := time.Duration(1<<63 - 1)
	tests := []struct {
		name string
		max  int
		set  func(*BeforeOOMConfig, int)
	}{
		{
			name: "cooldown seconds",
			max:  int(maxDuration / time.Second),
			set:  func(cfg *BeforeOOMConfig, value int) { cfg.CooldownSeconds = value },
		},
		{
			name: "Go capture timeout milliseconds",
			max:  int(maxDuration / time.Millisecond),
			set:  func(cfg *BeforeOOMConfig, value int) { cfg.GoCaptureTimeoutMilliseconds = value },
		},
		{
			name: "Java capture timeout milliseconds",
			max:  int(maxDuration / time.Millisecond),
			set:  func(cfg *BeforeOOMConfig, value int) { cfg.JavaCaptureTimeoutMilliseconds = value },
		},
		{
			name: "Python capture timeout milliseconds",
			max:  int(maxDuration / time.Millisecond),
			set:  func(cfg *BeforeOOMConfig, value int) { cfg.PythonCaptureTimeoutMilliseconds = value },
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			test.set(&cfg, test.max)
			if err := validateBeforeOOMConfig(&cfg); err != nil {
				t.Fatalf("maximum valid duration rejected: %v", err)
			}

			test.set(&cfg, test.max+1)
			err := validateBeforeOOMConfig(&cfg)
			if err == nil || !strings.Contains(err.Error(), test.name+" overflows time.Duration") {
				t.Fatalf("overflow validation error = %v", err)
			}
		})
	}
}

func TestPercentOfLimitOverflow(t *testing.T) {
	if got, want := percentOfLimit(math.MaxUint64-1, 90),
		uint64(16602069666338596452); got != want {
		t.Fatalf("threshold = %d, want %d", got, want)
	}
}

func TestUnlimitedLimit(t *testing.T) {
	for _, limit := range []uint64{0, math.MaxUint64, uint64(math.MaxInt64) - 4095} {
		if !isUnlimitedLimit(limit) {
			t.Fatalf("limit %d should be unlimited", limit)
		}
	}
	if isUnlimitedLimit(1 << 40) {
		t.Fatal("1 TiB should remain a finite limit")
	}
}

func TestGlobalCooldown(t *testing.T) {
	now := time.Now()
	snapshot := &beforeOOMSnapshot{lastSuccess: now}
	if snapshot.captureAllowed(&BeforeOOMConfig{
		ThresholdPercent: 90, CooldownSeconds: 300,
	}, now) {
		t.Fatal("capture should be suppressed during the global cooldown")
	}
}

func TestFailureUsesGlobalCooldown(t *testing.T) {
	now := time.Now()
	snapshot := &beforeOOMSnapshot{lastFailure: now}
	cfg := &BeforeOOMConfig{CooldownSeconds: 300}
	cooldown := time.Duration(cfg.CooldownSeconds) * time.Second
	if snapshot.captureAllowed(cfg, now.Add(cooldown-time.Millisecond)) {
		t.Fatal("failed capture should consume the global cooldown")
	}
	if !snapshot.captureAllowed(cfg, now.Add(cooldown)) {
		t.Fatal("capture should be allowed after the failure cooldown")
	}
}

func TestPressureArbitration(t *testing.T) {
	snapshot := &beforeOOMSnapshot{cgroup: &usageCgroup{usage: map[string]*stats.MemoryUsage{
		"/a": {Usage: 95, MaxLimited: 100},
		"/b": {Usage: 990, MaxLimited: 1000},
		"/c": {Usage: 89, MaxLimited: 100},
	}}}
	events := make(chan memoryPressureEvent, 2)
	events <- memoryPressureEvent{containerID: "b", cgroupPath: "/b"}
	events <- memoryPressureEvent{containerID: "c", cgroupPath: "/c"}

	got, ok, err := snapshot.bestCaptureCandidate(t.Context(),
		&BeforeOOMConfig{ThresholdPercent: 90}, events,
		memoryPressureEvent{containerID: "a", cgroupPath: "/a"})
	if err != nil {
		t.Fatal(err)
	}
	if !ok || got.cgroupPath != "/b" || got.ratio != 0.99 {
		t.Fatalf("highest pressure candidate = %+v, found=%v", got, ok)
	}
}

func TestCaptureTimeout(t *testing.T) {
	cfg := BeforeOOMConfig{
		GoCaptureTimeoutMilliseconds: 100, JavaCaptureTimeoutMilliseconds: 2000,
		PythonCaptureTimeoutMilliseconds: 3000,
	}
	tests := []struct {
		language memsnap.Language
		want     time.Duration
	}{
		{language: memsnap.LanguageGo, want: 100 * time.Millisecond},
		{language: memsnap.LanguageJava, want: 2 * time.Second},
		{language: memsnap.LanguagePython, want: 3 * time.Second},
		{language: memsnap.LanguageUnknown, want: 100 * time.Millisecond},
	}
	for _, test := range tests {
		if got := captureTimeout(&cfg, test.language); got != test.want {
			t.Fatalf("language=%s timeout=%s, want %s", test.language, got, test.want)
		}
	}
}

func TestReadMemoryEventCounter(t *testing.T) {
	eventsPath := filepath.Join(t.TempDir(), "memory.events.local")
	writeMemoryEventsForTest(t, eventsPath, "low 1\nhigh 23\nmax 4\noom 0\n")

	got, err := readMemoryEventCounter(eventsPath, "high")
	if err != nil {
		t.Fatal(err)
	}
	if got != 23 {
		t.Fatalf("high events = %d, want 23", got)
	}
	writeMemoryEventsForTest(t, eventsPath, "low 0\nmax 0\n")
	if _, err := readMemoryEventCounter(eventsPath, "high"); err == nil {
		t.Fatal("expected missing high counter error")
	}
}

func TestV2HighIncrease(t *testing.T) {
	eventsPath := filepath.Join(t.TempDir(), "memory.events.local")
	writeMemoryEventsForTest(t, eventsPath, "low 0\nhigh 2\nmax 0\n")
	watcher := &pressureWatcher{
		mode: cgroups.Unified,
		cgroups: map[string]*watchedCgroup{
			"test": {eventsPath: eventsPath, eventCount: 2},
		},
	}

	writeMemoryEventsForTest(t, eventsPath, "low 1\nhigh 2\nmax 2\n")
	emit, err := watcher.observeV2EventIncrease("test")
	if err != nil || emit {
		t.Fatalf("max increase: emit=%v, err=%v", emit, err)
	}

	writeMemoryEventsForTest(t, eventsPath, "low 1\nhigh 3\nmax 2\n")
	emit, err = watcher.observeV2EventIncrease("test")
	if err != nil || !emit {
		t.Fatalf("high increase: emit=%v, err=%v", emit, err)
	}
}

func TestV2ReadErrorRetainsWatchAndCounter(t *testing.T) {
	root := t.TempDir()
	cgroupPath := "/container"
	directory := filepath.Join(root, "container")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	eventsPath := filepath.Join(directory, "memory.events.local")
	writeMemoryEventsForTest(t, eventsPath, "low 0\nhigh 2\nmax 0\n")

	inotifyFD, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	watcher := newTestPressureWatcher(root, cgroups.Unified, inotifyFD)
	t.Cleanup(watcher.close)
	if err := watcher.addCgroup("container-id", cgroupPath); err != nil {
		t.Fatal(err)
	}

	events := make(chan memoryPressureEvent, 1)
	writeMemoryEventsForTest(t, eventsPath, "low 0\nmax 0\n")
	if err := watcher.handleInotify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	entry, ok := watcher.cgroups[cgroupPath]
	if !ok {
		t.Fatal("v2 cgroup watch was removed after a read error")
	}
	if entry.eventCount != 2 {
		t.Fatalf("high event count = %d after read error, want 2", entry.eventCount)
	}

	writeMemoryEventsForTest(t, eventsPath, "low 0\nhigh 3\nmax 0\n")
	if err := watcher.handleInotify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	select {
	case event := <-events:
		if event.cgroupPath != cgroupPath {
			t.Fatalf("pressure event path = %q, want %q", event.cgroupPath, cgroupPath)
		}
	default:
		t.Fatal("later high-counter increase was not emitted")
	}
}

func TestPressureWatcherCgroupNodeCreateDelete(t *testing.T) {
	root := t.TempDir()
	parent := filepath.Join(root, "kubepods.slice")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	containerID := strings.Repeat("b", 64)
	knodeName := "cri-containerd-" + containerID + ".scope"
	directory := filepath.Join(parent, knodeName)

	inotifyFD, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	watcher := newTestPressureWatcher(root, cgroups.Unified, inotifyFD)
	t.Cleanup(watcher.close)
	events := make(chan memoryPressureEvent, 1)
	if err := watcher.refreshFromCgroupTree(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	writeMemoryEventsForTest(t, filepath.Join(directory, "memory.events"),
		"high 0\nmax 0\n")
	if err := watcher.handleInotify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	cgroupPath := "/kubepods.slice/" + knodeName
	if _, ok := watcher.cgroups[cgroupPath]; !ok {
		t.Fatalf("created cgroup %q was not watched", cgroupPath)
	}
	if got := <-events; got.containerID != containerID || got.cgroupPath != cgroupPath {
		t.Fatalf("create event = %+v", got)
	}

	if err := os.RemoveAll(directory); err != nil {
		t.Fatal(err)
	}
	if err := watcher.handleInotify(context.Background(), events); err != nil {
		t.Fatal(err)
	}
	if len(watcher.cgroups) != 0 {
		t.Fatalf("deleted cgroup remained watched: %+v", watcher.cgroups)
	}
}

func TestWalkCgroupTreeReturnsDirectoryWatchError(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "child"), 0o755); err != nil {
		t.Fatal(err)
	}
	watcher := &pressureWatcher{
		root: root, inotifyFD: -1,
		directoryWatches: map[int]string{1: root},
		directoryWatchFD: map[string]int{root: 1},
	}
	_, err := watcher.walkCgroupTree(root, func(string, string) error { return nil })
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("walk error = %v, want EBADF", err)
	}
}

func TestReconcileReturnsContainerWatchError(t *testing.T) {
	root := t.TempDir()
	containerID := strings.Repeat("c", 64)
	name := "cri-containerd-" + containerID + ".scope"
	directory := filepath.Join(root, name)
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	writeMemoryEventsForTest(t, filepath.Join(directory, "memory.events"),
		"high 0\nmax 0\n")
	watcher := newTestPressureWatcher(root, cgroups.Unified, -1)
	_, err := watcher.reconcile(map[string]string{containerID: "/" + name})
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("reconcile error = %v, want EBADF", err)
	}
}

func TestReconcileSkipsDeletedContainer(t *testing.T) {
	watcher := newTestPressureWatcher(t.TempDir(), cgroups.Unified, -1)
	containerID := strings.Repeat("f", 64)
	added, err := watcher.reconcile(map[string]string{
		containerID: "/cri-containerd-" + containerID + ".scope",
	})
	if err != nil || len(added) != 0 || len(watcher.cgroups) != 0 {
		t.Fatalf("reconcile deleted cgroup: added=%v cgroups=%v err=%v",
			added, watcher.cgroups, err)
	}
}

func TestDirectoryEventReturnsContainerWatchError(t *testing.T) {
	root := t.TempDir()
	containerID := strings.Repeat("d", 64)
	name := "cri-containerd-" + containerID + ".scope"
	directory := filepath.Join(root, name)
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	writeMemoryEventsForTest(t, filepath.Join(directory, "memory.events"),
		"high 0\nmax 0\n")
	watcher := newTestPressureWatcher(root, cgroups.Unified, -1)
	err := watcher.handleCgroupDirectoryEvent(context.Background(),
		make(chan memoryPressureEvent, 1), root, name,
		unix.IN_CREATE|unix.IN_ISDIR)
	if !errors.Is(err, unix.EBADF) {
		t.Fatalf("directory event error = %v, want EBADF", err)
	}
	if len(watcher.cgroups) != 0 {
		t.Fatalf("failed cgroup remained watched: %+v", watcher.cgroups)
	}
}

func TestRecoverV1Watch(t *testing.T) {
	backend := &usageCgroup{usage: map[string]*stats.MemoryUsage{"/container": nil}}
	watcher := newTestPressureWatcher("", cgroups.Legacy, -1)
	watcher.cgroup = backend
	watcher.cfg = &BeforeOOMConfig{ThresholdPercent: 90}
	watcher.cgroups["/container"] = &watchedCgroup{
		containerID: "container-id", cgroupPath: "/container",
		eventFD: -1, inotifyWatch: -1,
	}

	if err := watcher.recoverV1Watch("/container", unix.EIO); err != nil {
		t.Fatal(err)
	}
	if _, ok := watcher.cgroups["/container"]; !ok {
		t.Fatal("cgroup watch was not restored")
	}

	backend.err = unix.EIO
	if err := watcher.recoverV1Watch("/container", unix.EIO); !errors.Is(err, unix.EIO) {
		t.Fatalf("recover error = %v, want EIO", err)
	}
	if _, ok := watcher.cgroups["/container"]; ok {
		t.Fatal("failed replacement left stale cgroup state")
	}
}

func TestWalkCgroupTreeReturnsMissingRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "missing")
	watcher := &pressureWatcher{
		root: root, inotifyFD: -1,
		directoryWatches: make(map[int]string),
		directoryWatchFD: make(map[string]int),
	}
	_, err := watcher.walkCgroupTree(root, func(string, string) error { return nil })
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("walk error = %v, want os.ErrNotExist", err)
	}
}

func TestRootDirectoryRemovalIsTerminal(t *testing.T) {
	root := t.TempDir()
	watcher := &pressureWatcher{root: root}
	err := watcher.handleCgroupDirectoryEvent(context.Background(),
		make(chan memoryPressureEvent, 1), root, "", unix.IN_DELETE_SELF)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("root removal error = %v, want os.ErrNotExist", err)
	}
}

func TestPressureWatcherReportsTerminalError(t *testing.T) {
	root := t.TempDir()
	watcher := newTestPressureWatcher(root, cgroups.Unified, -1)
	events, done := watcher.Run(context.Background())
	select {
	case err := <-done:
		if !errors.Is(err, unix.EBADF) {
			t.Fatalf("watcher error = %v, want EBADF", err)
		}
	case _, ok := <-events:
		if ok {
			t.Fatal("unexpected pressure event")
		}
		err := <-done
		if !errors.Is(err, unix.EBADF) {
			t.Fatalf("watcher error = %v, want EBADF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("pressure watcher did not report its terminal error")
	}
}

func TestReplaceV1ThresholdEventFDPreservesInotifyWatch(t *testing.T) {
	epollFD, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(epollFD)
	watcher := &pressureWatcher{
		epollFD:     epollFD,
		pressureFDs: make(map[int]string),
	}
	entry := &watchedCgroup{
		cgroupPath: "test", eventFD: -1, inotifyWatch: 42,
	}
	oldFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.addEventFD(entry, oldFD); err != nil {
		t.Fatal(err)
	}
	newFD, err := unix.Eventfd(0, unix.EFD_CLOEXEC|unix.EFD_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.addEventFD(entry, newFD); err != nil {
		t.Fatal(err)
	}
	defer watcher.removeEventFD(entry)

	if entry.eventFD != newFD {
		t.Fatalf("event fd = %d, want %d", entry.eventFD, newFD)
	}
	if entry.inotifyWatch != 42 {
		t.Fatalf("inotify watch = %d, want 42", entry.inotifyWatch)
	}
	if _, ok := watcher.pressureFDs[oldFD]; ok {
		t.Fatalf("old event fd %d remained registered", oldFD)
	}
	if got := watcher.pressureFDs[newFD]; got != "test" {
		t.Fatalf("new event fd path = %q, want test", got)
	}
	if _, err := unix.FcntlInt(uintptr(oldFD), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("old event fd remains open: %v", err)
	}
}

func newTestPressureWatcher(root string, mode cgroups.Mode,
	inotifyFD int,
) *pressureWatcher {
	return &pressureWatcher{
		mode: mode, root: root,
		epollFD: -1, inotifyFD: inotifyFD, controlFD: -1,
		cgroups:          make(map[string]*watchedCgroup),
		pressureFDs:      make(map[int]string),
		inotifyWatches:   make(map[int]string),
		directoryWatches: make(map[int]string),
		directoryWatchFD: make(map[string]int),
	}
}

func writeMemoryEventsForTest(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

type usageCgroup struct {
	cgroups.Cgroup
	usage map[string]*stats.MemoryUsage
	err   error
}

func (c *usageCgroup) MemoryUsage(path string) (*stats.MemoryUsage, error) {
	return c.usage[path], c.err
}
