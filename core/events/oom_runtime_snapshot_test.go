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
	"testing"
	"time"

	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/bpf/abi"
	"huatuo-bamai/internal/memsnap"
)

func validOOMRuntimeSnapshotConfig() OOMRuntimeSnapshotConfig {
	return OOMRuntimeSnapshotConfig{
		Enabled:                 true,
		GateTimeoutMilliseconds: 50, CaptureCooldownMilliseconds: 30000,
		FailureCooldownMilliseconds:    60000,
		MaxFailureCooldownMilliseconds: 300000,
		MaxConcurrentGates:             1, MaxOutputBytes: 8192,
		MaxObjects: 10, MaxStacks: 10, MaxStackDepth: 10,
	}
}

func TestOOMRuntimeSnapshotConfigValidation(t *testing.T) {
	config := validOOMRuntimeSnapshotConfig()
	if err := config.Validate(); err != nil {
		t.Fatal(err)
	}
	config.MaxConcurrentGates = 2
	if err := config.Validate(); err == nil {
		t.Fatal("queued OOM Runtime snapshots accepted")
	}
	config = validOOMRuntimeSnapshotConfig()
	config.GateTimeoutMilliseconds = 51
	if err := config.Validate(); err == nil {
		t.Fatal("gate timeout above the 50 ms hard limit accepted")
	}
	config = validOOMRuntimeSnapshotConfig()
	config.MaxFailureCooldownMilliseconds = 1000
	if err := config.Validate(); err == nil {
		t.Fatal("failure cooldown cap below initial cooldown accepted")
	}
	config = validOOMRuntimeSnapshotConfig()
	config.Enabled = false
	config.GateTimeoutMilliseconds = 999
	if err := config.Validate(); err == nil {
		t.Fatal("disabled configuration with an invalid gate timeout accepted")
	}
}

func TestOOMRuntimeSnapshotRequiresTwoSchedulableCPUs(t *testing.T) {
	for _, count := range []int{0, 1} {
		if err := validateOOMRuntimeSnapshotCPUCount(count); err == nil {
			t.Fatalf("CPU count %d accepted", count)
		}
	}
	if err := validateOOMRuntimeSnapshotCPUCount(2); err != nil {
		t.Fatal(err)
	}
}

func TestOOMRuntimeSnapshotConfigUpdatesWithoutRestart(t *testing.T) {
	previous := configSnapshot()
	defer Set(previous)

	initial := &Config{}
	initial.OOMRuntimeSnapshot = validOOMRuntimeSnapshotConfig()
	Set(initial)
	service := &oomRuntimeSnapshotService{}
	service.useLiveConfig()
	if got := service.gateTimeoutMilliseconds(); got != 50 {
		t.Fatalf("initial gate timeout = %d ms, want 50 ms", got)
	}

	updated := &Config{}
	updated.OOMRuntimeSnapshot = validOOMRuntimeSnapshotConfig()
	updated.OOMRuntimeSnapshot.GateTimeoutMilliseconds = 40
	updated.OOMRuntimeSnapshot.CaptureCooldownMilliseconds = 1000
	Set(updated)
	if got := service.gateTimeoutMilliseconds(); got != 40 {
		t.Fatalf("updated gate timeout = %d ms, want 40 ms", got)
	}
	if got := service.captureCooldownMilliseconds(); got != 1000 {
		t.Fatalf("updated capture cooldown = %d ms, want 1000 ms", got)
	}
}

func TestBusyAndCooldownEventsNeverInspectVictim(t *testing.T) {
	service := &oomRuntimeSnapshotService{
		identities: panicIdentityReader{},
		clock:      &snapshotTestClock{now: time.Now().UTC(), monotonic: 100},
	}
	for _, state := range []uint8{
		memsnap.OOMSnapshotGateBusy,
		memsnap.OOMSnapshotGateCooldown,
	} {
		key := oomRuntimeSnapshotKey{victimTGID: 42, oomMonotonicNS: uint64(state)}
		service.submit(context.Background(), nil, &abi.OOMEvent{
			VictimPID: 42, Timestamp: key.oomMonotonicNS,
			SnapshotGateState: state,
		})
		snapshot, ok := runtimeSnapshotBridge.wait(context.Background(), key, 0)
		if !ok || snapshot == nil {
			t.Fatalf("state %d did not publish a terminal snapshot", state)
		}
	}
	if service.metrics.skippedBusy.Load() != 1 ||
		service.metrics.skippedCooldown.Load() != 1 {
		t.Fatalf("busy=%d cooldown=%d", service.metrics.skippedBusy.Load(),
			service.metrics.skippedCooldown.Load())
	}
}

func TestDisabledGateEventPublishesTerminalSnapshot(t *testing.T) {
	service := &oomRuntimeSnapshotService{
		identities: panicIdentityReader{},
		clock:      &snapshotTestClock{now: time.Now().UTC(), monotonic: 100},
	}
	key := oomRuntimeSnapshotKey{victimTGID: 42, oomMonotonicNS: 7}
	service.submit(context.Background(), nil, &abi.OOMEvent{
		VictimPID: 42, Timestamp: key.oomMonotonicNS,
		SnapshotGateState: memsnap.OOMSnapshotGateDisabled,
	})
	snapshot, ok := runtimeSnapshotBridge.wait(context.Background(), key, 0)
	if !ok || snapshot == nil {
		t.Fatal("disabled gate did not publish a terminal snapshot")
	}
	if snapshot.Status != memsnap.StatusSkippedDisabled {
		t.Fatalf("status=%q, want %q", snapshot.Status,
			memsnap.StatusSkippedDisabled)
	}
}

func TestWaitBudgetCoversAdmissionWindow(t *testing.T) {
	const base = uint64(1_000_000_000)
	service := &oomRuntimeSnapshotService{
		clock:                   &snapshotTestClock{now: time.Now().UTC(), monotonic: base},
		gateTimeoutMilliseconds: func() int64 { return 50 },
	}
	eventTime := time.Now()

	// Without an admission deadline the budget falls back to one gate
	// timeout plus the finalization grace after the event.
	if got := service.waitBudget(eventTime, 0); got <= 0 ||
		got > 50*time.Millisecond+oomRuntimeSnapshotFinalizeGrace {
		t.Fatalf("fallback budget=%s", got)
	}

	// MonotonicNS increments on each call, so waitBudget observes base+1.
	// An admission deadline 800 ms out must extend the wait by the remaining
	// admission window plus one capture budget.
	deadline := base + 1 + uint64(800*time.Millisecond)
	want := 800*time.Millisecond + 50*time.Millisecond + oomRuntimeSnapshotFinalizeGrace
	if got := service.waitBudget(eventTime, deadline); got != want {
		t.Fatalf("admission-aware budget=%s, want %s", got, want)
	}

	// An already expired admission deadline must not extend the wait.
	if got := service.waitBudget(eventTime, base+1); got <= 0 ||
		got > 50*time.Millisecond+oomRuntimeSnapshotFinalizeGrace {
		t.Fatalf("expired-deadline budget=%s", got)
	}
}

func TestWaitForGateFreezeRejectsMismatchedCookie(t *testing.T) {
	service := &oomRuntimeSnapshotService{
		clock: &snapshotTestClock{now: time.Now().UTC(), monotonic: 100},
	}
	program := newFakeOOMSnapshotBPF()
	program.setGateTID(123)
	program.setActive(9) // active gate belongs to a different cookie

	tid, deadline, ok := service.waitForGateFreeze(context.Background(), program,
		&abi.OOMEvent{VictimPID: 42, SnapshotCookie: 7})
	if ok || tid != 0 || deadline != 0 {
		t.Fatalf("waitForGateFreeze = (%d, %d, %v), want (0, 0, false) for a stale gate",
			tid, deadline, ok)
	}
}

func TestWriteBPFConfigDisablesKernelGate(t *testing.T) {
	previous := configSnapshot()
	defer Set(previous)

	enabled := &Config{}
	enabled.OOMRuntimeSnapshot = validOOMRuntimeSnapshotConfig()
	Set(enabled)
	service := &oomRuntimeSnapshotService{}
	service.useLiveConfig()

	program := newFakeOOMSnapshotBPF()
	if err := service.writeBPFConfig(program); err != nil {
		t.Fatal(err)
	}
	if got := binary.NativeEndian.Uint64(
		program.value(oomSnapshotConfigMapName)[0:8]); got != 50_000_000 {
		t.Fatalf("enabled gate timeout = %d ns, want 50 ms", got)
	}

	disabled := &Config{}
	disabled.OOMRuntimeSnapshot = validOOMRuntimeSnapshotConfig()
	disabled.OOMRuntimeSnapshot.Enabled = false
	disabled.OOMRuntimeSnapshot.GateTimeoutMilliseconds = 40
	Set(disabled)
	if err := service.writeBPFConfig(program); err != nil {
		t.Fatal(err)
	}
	if got := binary.NativeEndian.Uint64(
		program.value(oomSnapshotConfigMapName)[0:8]); got != 0 {
		t.Fatalf("disabled gate timeout = %d ns, want 0 (kernel gate off)", got)
	}
}

func TestRefreshBPFConfigReconcilesExitMMReleaseProbe(t *testing.T) {
	previous := configSnapshot()
	defer Set(previous)

	program := newFakeOOMSnapshotBPF()
	service := &oomRuntimeSnapshotService{bpf: program}
	service.useLiveConfig()

	disabled := &Config{}
	disabled.OOMRuntimeSnapshot = validOOMRuntimeSnapshotConfig()
	disabled.OOMRuntimeSnapshot.Enabled = false

	enabled := &Config{}
	enabled.OOMRuntimeSnapshot = validOOMRuntimeSnapshotConfig()

	// Disabled: the probe must stay detached (idempotent no-op).
	Set(disabled)
	service.refreshBPFConfig()
	if program.attached[oomRuntimeSnapshotExitMMReleaseProgram] {
		t.Fatal("disabled config left exit_mm_release attached")
	}

	// Enabled: reconcile attaches the probe.
	Set(enabled)
	service.refreshBPFConfig()
	if !program.attached[oomRuntimeSnapshotExitMMReleaseProgram] {
		t.Fatal("enabled config did not attach exit_mm_release")
	}

	// Repeated enabled refresh stays attached.
	service.refreshBPFConfig()
	if !program.attached[oomRuntimeSnapshotExitMMReleaseProgram] {
		t.Fatal("repeated enabled refresh detached exit_mm_release")
	}

	// Disabled again: reconcile detaches the probe.
	Set(disabled)
	service.refreshBPFConfig()
	if program.attached[oomRuntimeSnapshotExitMMReleaseProgram] {
		t.Fatal("re-disabled config left exit_mm_release attached")
	}
}

func TestSnapshotACKRequiresKernelACKReleaseRecord(t *testing.T) {
	clock := &snapshotTestClock{now: time.Now().UTC(), monotonic: 100}
	service := &oomRuntimeSnapshotService{clock: clock}
	program := newFakeOOMSnapshotBPF()
	program.setActive(9)
	if err := service.ack(program, 9, memsnap.StatusComplete); err != nil {
		t.Fatal(err)
	}
	if program.releaseValue(9) != nil {
		t.Fatal("validated ACK release record was not consumed")
	}
}

func TestSnapshotACKRejectsDeadlineAndWorkLimitRelease(t *testing.T) {
	clock := &snapshotTestClock{now: time.Now().UTC(), monotonic: 100}
	service := &oomRuntimeSnapshotService{clock: clock}
	for _, reason := range []uint32{
		memsnap.OOMSnapshotReleaseDeadline,
		memsnap.OOMSnapshotReleaseWorkLimit,
		memsnap.OOMSnapshotReleasePerfOutputFailed,
	} {
		program := newFakeOOMSnapshotBPF()
		program.releaseReason = reason
		program.setActive(9)
		if err := service.ack(program, 9, memsnap.StatusComplete); err == nil {
			t.Fatalf("release reason %d was accepted as ACK", reason)
		}
	}
}

func TestSnapshotReleaseRecordsAreIsolatedByCookie(t *testing.T) {
	program := newFakeOOMSnapshotBPF()
	for _, cookie := range []uint64{9, 10} {
		release := make([]byte, 24)
		binary.NativeEndian.PutUint64(release[0:8], cookie)
		binary.NativeEndian.PutUint64(release[8:16], 100+cookie)
		binary.NativeEndian.PutUint32(release[16:20], memsnap.OOMSnapshotReleaseACK)
		program.releases[cookie] = release
	}
	reason, releaseNS, err := readOOMSnapshotRelease(program, 9)
	if err != nil || reason != memsnap.OOMSnapshotReleaseACK || releaseNS != 109 {
		t.Fatalf("reason=%d release_ns=%d err=%v", reason, releaseNS, err)
	}
	if program.releaseValue(9) != nil || program.releaseValue(10) == nil {
		t.Fatal("reading one release record removed or overwrote another cookie")
	}
}

func TestSnapshotAckRejectsExpiredActiveDeadline(t *testing.T) {
	clock := &snapshotTestClock{now: time.Now().UTC(), monotonic: 100}
	service := &oomRuntimeSnapshotService{clock: clock}
	program := newFakeOOMSnapshotBPF()
	program.setActiveWithDeadline(9, clock.monotonic)
	if err := service.ack(program, 9, memsnap.StatusComplete); err == nil {
		t.Fatal("expired snapshot ACK was accepted")
	}
}

func TestSnapshotACKRejectsWrongCookie(t *testing.T) {
	clock := &snapshotTestClock{now: time.Now().UTC(), monotonic: 100}
	service := &oomRuntimeSnapshotService{clock: clock}
	program := newFakeOOMSnapshotBPF()
	program.setActive(9)
	if err := service.ack(program, 10, memsnap.StatusComplete); err == nil {
		t.Fatal("ACK for a different gate cookie was accepted")
	}
	if _, ok := program.values[program.mapIDs[oomSnapshotActiveMapName]]; !ok {
		t.Fatal("wrong-cookie ACK released the active gate")
	}
}

func TestSnapshotAckRequiresGateRelease(t *testing.T) {
	clock := &snapshotTestClock{now: time.Now().UTC(), monotonic: 100}
	service := &oomRuntimeSnapshotService{
		clock:                       clock,
		captureCooldownMilliseconds: func() int64 { return 30000 },
		failureCooldownMilliseconds: func() int64 { return 60000 },
		maxFailureCooldownMillis:    func() int64 { return 300000 },
	}
	program := newFakeOOMSnapshotBPF()
	program.releaseOnACK = false
	program.setActiveWithDeadline(9, clock.monotonic+2)
	if err := service.ack(program, 9, memsnap.StatusComplete); err == nil {
		t.Fatal("snapshot ACK was accepted before BPF released the gate")
	}
}

func TestTerminalSnapshotIsPersistable(t *testing.T) {
	clock := &snapshotTestClock{now: time.Now().UTC(), monotonic: 100}
	request := memsnap.Request{
		SnapshotID: "snapshot", OOMRequestCookie: 10, OOMMonotonicNS: 80,
		GateDeadlineMonotonicNS: 200,
		Identity: memsnap.ProcessIdentity{
			TGID: 42, StartTimeTicks: 7, BootID: "boot",
		},
	}
	result := terminalSnapshot(request, memsnap.LanguagePython,
		memsnap.StatusFiltered, "filtered", clock)
	if err := result.Manifest.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestAckMissPublishesCapturedPrefix(t *testing.T) {
	previousBridge := runtimeSnapshotBridge
	runtimeSnapshotBridge = newOOMRuntimeSnapshotBridge(time.Second)
	defer func() { runtimeSnapshotBridge = previousBridge }()

	key := oomRuntimeSnapshotKey{victimTGID: 42, oomMonotonicNS: 80}
	result := &memsnap.Result{
		Manifest: memsnap.Manifest{
			SchemaVersion: memsnap.SchemaVersion,
			Status:        memsnap.StatusPartialDeadline,
			Truncated:     true,
			TruncationReasons: []string{
				"deadline reached after a useful prefix was copied",
			},
			Coverage: memsnap.Coverage{
				Consistency: "bounded", SizeSemantics: "sampled",
				KnownGaps: []string{"deadline"},
			},
		},
		Objects: []memsnap.ObjectAggregate{{
			TypeName: "service.Payload", Count: 7, ShallowBytes: 896,
		}},
	}
	service := &oomRuntimeSnapshotService{}
	service.publishAfterAck(key, 10, result, result.Manifest.Status, 0,
		errors.New("gate deadline expired"), "")
	snapshot, ok := runtimeSnapshotBridge.wait(context.Background(), key, 0)
	if !ok || snapshot.Status != memsnap.StatusPartialDeadline ||
		snapshot.GateRelease != "timeout_or_ack_missed" ||
		len(snapshot.Entries) != 1 || snapshot.Entries[0].Name != "service.Payload" {
		t.Fatalf("snapshot=%+v", snapshot)
	}
}

func TestStatusToAck(t *testing.T) {
	if got := memsnap.OOMSnapshotStatusToAck(memsnap.StatusComplete); got != memsnap.OOMSnapshotAckCaptured {
		t.Fatalf("complete ACK=%d", got)
	}
	if got := memsnap.OOMSnapshotStatusToAck(memsnap.StatusPartialDeadline); got != memsnap.OOMSnapshotAckPartial {
		t.Fatalf("partial ACK=%d", got)
	}
	if got := memsnap.OOMSnapshotStatusToAck(memsnap.StatusProviderUnavailable); got != memsnap.OOMSnapshotAckUnavailable {
		t.Fatalf("unavailable ACK=%d", got)
	}
}

func TestRuntimeSnapshotServiceHasNoIdleTargetControlPlane(t *testing.T) {
	config := validOOMRuntimeSnapshotConfig()
	service, err := buildOOMRuntimeSnapshotService(&config)
	if err != nil {
		t.Fatal(err)
	}
	metrics := service.Update()
	if len(metrics) == 0 || service.metrics.requests.Load() != 0 {
		t.Fatalf("metrics=%d requests=%d", len(metrics), service.metrics.requests.Load())
	}
}

type panicIdentityReader struct{}

func (panicIdentityReader) Read(int) (memsnap.ProcessIdentity, error) {
	panic("busy/cooldown events must not inspect the victim")
}

type fakeOOMSnapshotBPF struct {
	mapIDs        map[string]uint32
	values        map[uint32][]byte
	releases      map[uint64][]byte
	releaseOnACK  bool
	releaseReason uint32
	attached      map[string]bool
}

func newFakeOOMSnapshotBPF() *fakeOOMSnapshotBPF {
	program := &fakeOOMSnapshotBPF{
		mapIDs: map[string]uint32{
			oomSnapshotConfigMapName:  1,
			oomSnapshotActiveMapName:  2,
			oomSnapshotStateMapName:   3,
			oomSnapshotAckMapName:     4,
			oomSnapshotReleaseMapName: 5,
			oomSnapshotGateTidMapName: 6,
		},
		values:        make(map[uint32][]byte),
		releases:      make(map[uint64][]byte),
		releaseOnACK:  true,
		releaseReason: memsnap.OOMSnapshotReleaseACK,
		attached:      make(map[string]bool),
	}
	program.values[program.mapIDs[oomSnapshotStateMapName]] = make([]byte, 16)
	return program
}

func (f *fakeOOMSnapshotBPF) setActive(cookie uint64) {
	f.setActiveWithDeadline(cookie, ^uint64(0))
}

func (f *fakeOOMSnapshotBPF) setGateTID(tid uint32) {
	value := make([]byte, 4)
	binary.NativeEndian.PutUint32(value, tid)
	f.values[f.mapIDs[oomSnapshotGateTidMapName]] = value
}

func (f *fakeOOMSnapshotBPF) setActiveWithDeadline(cookie, deadline uint64) {
	value := make([]byte, 24)
	binary.NativeEndian.PutUint64(value[:8], cookie)
	binary.NativeEndian.PutUint64(value[8:16], deadline)
	f.values[f.mapIDs[oomSnapshotActiveMapName]] = value
}

func (f *fakeOOMSnapshotBPF) value(name string) []byte {
	return f.values[f.mapIDs[name]]
}

func (f *fakeOOMSnapshotBPF) releaseValue(cookie uint64) []byte {
	return f.releases[cookie]
}

func (f *fakeOOMSnapshotBPF) Name() string { return "fake" }
func (f *fakeOOMSnapshotBPF) MapIDByName(name string) uint32 {
	return f.mapIDs[name]
}
func (f *fakeOOMSnapshotBPF) ProgramIDByName(string) uint32 { return 0 }
func (f *fakeOOMSnapshotBPF) String() string                { return "fake" }
func (f *fakeOOMSnapshotBPF) Info() (*bpf.Info, error)      { return nil, nil }
func (f *fakeOOMSnapshotBPF) Close() error                  { return nil }
func (f *fakeOOMSnapshotBPF) AttachWithOptions([]bpf.AttachOption) error {
	return nil
}
func (f *fakeOOMSnapshotBPF) Attach() error { return nil }
func (f *fakeOOMSnapshotBPF) Detach() error { return nil }
func (f *fakeOOMSnapshotBPF) SetAttachSkip(names ...string) {
	for _, name := range names {
		delete(f.attached, name)
	}
}
func (f *fakeOOMSnapshotBPF) AttachProgram(name string) error {
	f.attached[name] = true
	return nil
}
func (f *fakeOOMSnapshotBPF) DetachProgram(name string) error {
	delete(f.attached, name)
	return nil
}
func (f *fakeOOMSnapshotBPF) IsLoaded() (bool, error) {
	return true, nil
}

func (f *fakeOOMSnapshotBPF) EventPipe(context.Context, uint32, uint32) (
	bpf.PerfEventReader, error,
) {
	return nil, errors.New("unused")
}

func (f *fakeOOMSnapshotBPF) EventPipeByName(context.Context, string, uint32) (
	bpf.PerfEventReader, error,
) {
	return nil, errors.New("unused")
}

func (f *fakeOOMSnapshotBPF) AttachAndEventPipe(context.Context, string, uint32) (
	bpf.PerfEventReader, error,
) {
	return nil, errors.New("unused")
}

func (f *fakeOOMSnapshotBPF) ReadMap(mapID uint32, key []byte) ([]byte, error) {
	if mapID == f.mapIDs[oomSnapshotReleaseMapName] {
		if len(key) < 8 {
			return nil, bpf.ErrMapKeyNotFound
		}
		value, ok := f.releases[binary.NativeEndian.Uint64(key)]
		if !ok {
			return nil, bpf.ErrMapKeyNotFound
		}
		return value, nil
	}
	value, ok := f.values[mapID]
	if !ok && mapID == f.mapIDs[oomSnapshotActiveMapName] {
		return nil, bpf.ErrMapKeyNotFound
	}
	return value, nil
}

func (f *fakeOOMSnapshotBPF) WriteMapItems(mapID uint32, items []bpf.MapItem) error {
	for _, item := range items {
		f.values[mapID] = append([]byte(nil), item.Value...)
		if mapID == f.mapIDs[oomSnapshotAckMapName] && f.releaseOnACK {
			cookie := binary.NativeEndian.Uint64(item.Value[0:8])
			release := make([]byte, 24)
			binary.NativeEndian.PutUint64(release[0:8], cookie)
			binary.NativeEndian.PutUint64(release[8:16], 101)
			binary.NativeEndian.PutUint32(release[16:20], f.releaseReason)
			binary.NativeEndian.PutUint32(release[20:24],
				binary.NativeEndian.Uint32(item.Value[8:12]))
			f.releases[cookie] = release
			delete(f.values, f.mapIDs[oomSnapshotActiveMapName])
		}
	}
	return nil
}
func (f *fakeOOMSnapshotBPF) DeleteMapItems(mapID uint32, keys [][]byte) error {
	if mapID == f.mapIDs[oomSnapshotReleaseMapName] {
		for _, key := range keys {
			if len(key) >= 8 {
				delete(f.releases, binary.NativeEndian.Uint64(key))
			}
		}
	}
	return nil
}
func (f *fakeOOMSnapshotBPF) DumpMap(uint32) ([]bpf.MapItem, error) { return nil, nil }
func (f *fakeOOMSnapshotBPF) DumpMapByName(string) ([]bpf.MapItem, error) {
	return nil, nil
}
func (f *fakeOOMSnapshotBPF) DetachOnContextDone(context.Context, context.CancelFunc) {}

type snapshotTestClock struct {
	now       time.Time
	monotonic uint64
}

func (c *snapshotTestClock) Now() time.Time { return c.now }
func (c *snapshotTestClock) MonotonicNS() uint64 {
	c.monotonic++
	return c.monotonic
}
