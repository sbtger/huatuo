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
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"huatuo-bamai/internal/bpf"
	"huatuo-bamai/internal/bpf/abi"
	"huatuo-bamai/internal/log"
	"huatuo-bamai/internal/memsnap"
	golangprovider "huatuo-bamai/internal/memsnap/providers/golang"
	javaprovider "huatuo-bamai/internal/memsnap/providers/java"
	pythonprovider "huatuo-bamai/internal/memsnap/providers/python"
	"huatuo-bamai/pkg/metric"
)

const (
	oomSnapshotConfigMapName  = "oom_snapshot_config"
	oomSnapshotActiveMapName  = "oom_snapshot_active"
	oomSnapshotStateMapName   = "oom_snapshot_state"
	oomSnapshotAckMapName     = "oom_snapshot_acks"
	oomSnapshotReleaseMapName = "oom_snapshot_release"
	oomSnapshotGateTidMapName = "oom_snapshot_gate_tid"

	// oomRuntimeSnapshotExitMMReleaseProgram is the kprobe that freezes the
	// victim and starts its capture budget. It only exists for the runtime
	// snapshot path, so it is attached on demand (AttachProgram) instead of
	// firing on every process exit while the feature is disabled.
	oomRuntimeSnapshotExitMMReleaseProgram = "exit_mm_release"
)

type oomRuntimeSnapshotService struct {
	config                      OOMRuntimeSnapshotConfig
	gateTimeoutMilliseconds     func() int64
	captureCooldownMilliseconds func() int64
	failureCooldownMilliseconds func() int64
	maxFailureCooldownMillis    func() int64
	clock                       memsnap.Clock
	identities                  memsnap.IdentityReader
	coordinator                 *memsnap.Coordinator
	included                    []*regexp.Regexp
	excluded                    []*regexp.Regexp

	bpfMu sync.RWMutex
	bpf   bpf.BPF
	wg    sync.WaitGroup

	metrics oomRuntimeSnapshotMetrics
}

type oomRuntimeSnapshotMetrics struct {
	requests        atomic.Uint64
	acked           atomic.Uint64
	ackFailed       atomic.Uint64
	completed       atomic.Uint64
	partial         atomic.Uint64
	unavailable     atomic.Uint64
	failed          atomic.Uint64
	payloadBytes    atomic.Uint64
	published       atomic.Uint64
	gateWaitNSTotal atomic.Uint64
	skippedBusy     atomic.Uint64
	skippedCooldown atomic.Uint64
}

var activeOOMRuntimeSnapshot atomic.Pointer[oomRuntimeSnapshotService]

func validateOOMRuntimeSnapshotCPUCapacity() error {
	var affinity unix.CPUSet
	if err := unix.SchedGetaffinity(0, &affinity); err != nil {
		return fmt.Errorf("read current CPU affinity: %w", err)
	}
	return validateOOMRuntimeSnapshotCPUCount(affinity.Count())
}

func validateOOMRuntimeSnapshotCPUCount(count int) error {
	if count < 2 {
		return fmt.Errorf("synchronous OOM Runtime snapshot requires at least two schedulable CPUs in the current affinity mask, got %d", count)
	}
	return nil
}

func buildOOMRuntimeSnapshotService(config *OOMRuntimeSnapshotConfig) (
	*oomRuntimeSnapshotService, error,
) {
	clock := memsnap.SystemClock{}
	identities := memsnap.ProcIdentityReader{}
	providers := memsnap.NewRegistry()
	goProvider, err := golangprovider.NewProvider(golangprovider.NewExternalReader("/proc"))
	if err != nil {
		return nil, err
	}
	pythonProvider, err := pythonprovider.NewProvider(pythonprovider.RuntimeExecutor{
		ProcRoot: "/proc",
	})
	if err != nil {
		return nil, err
	}
	javaProvider, err := javaprovider.NewProvider(javaprovider.NewExternalReader("/proc"))
	if err != nil {
		return nil, err
	}
	for _, provider := range []memsnap.Provider{goProvider, javaProvider, pythonProvider} {
		if err := providers.Register(provider); err != nil {
			return nil, err
		}
	}
	coordinator, err := memsnap.NewCoordinator(providers, identities, clock, 1)
	if err != nil {
		return nil, err
	}
	included, err := compileSnapshotFilters(config.Filter.Included)
	if err != nil {
		return nil, fmt.Errorf("compile included OOM snapshot filter: %w", err)
	}
	excluded, err := compileSnapshotFilters(config.Filter.Excluded)
	if err != nil {
		return nil, fmt.Errorf("compile excluded OOM snapshot filter: %w", err)
	}
	return &oomRuntimeSnapshotService{
		config: *config,
		gateTimeoutMilliseconds: func() int64 {
			return config.GateTimeoutMilliseconds
		},
		captureCooldownMilliseconds: func() int64 {
			return config.CaptureCooldownMilliseconds
		},
		failureCooldownMilliseconds: func() int64 {
			return config.FailureCooldownMilliseconds
		},
		maxFailureCooldownMillis: func() int64 {
			return config.MaxFailureCooldownMilliseconds
		},
		clock: clock, identities: identities, coordinator: coordinator,
		included: included, excluded: excluded,
	}, nil
}

func (s *oomRuntimeSnapshotService) useLiveConfig() {
	s.gateTimeoutMilliseconds = currentOOMRuntimeSnapshotGateTimeoutMilliseconds
	s.captureCooldownMilliseconds = currentOOMRuntimeSnapshotCaptureCooldownMilliseconds
	s.failureCooldownMilliseconds = currentOOMRuntimeSnapshotFailureCooldownMilliseconds
	s.maxFailureCooldownMillis = currentOOMRuntimeSnapshotMaxFailureCooldownMilliseconds
}

func (s *oomRuntimeSnapshotService) attachBPF(program bpf.BPF) error {
	if program == nil {
		return errors.New("OOM Runtime snapshot requires a loaded BPF object")
	}
	s.bpfMu.Lock()
	defer s.bpfMu.Unlock()
	if err := s.writeBPFConfig(program); err != nil {
		return err
	}
	for _, entry := range []struct {
		name string
		size int
	}{
		{oomSnapshotStateMapName, 16},
		{oomSnapshotAckMapName, 16},
	} {
		if err := writeOOMSnapshotMap(program, entry.name, make([]byte, entry.size)); err != nil {
			return err
		}
	}
	s.bpf = program
	activeOOMRuntimeSnapshot.Store(s)
	return nil
}

func (s *oomRuntimeSnapshotService) detachBPF() {
	activeOOMRuntimeSnapshot.CompareAndSwap(s, nil)
	s.bpfMu.Lock()
	s.bpf = nil
	s.bpfMu.Unlock()
	s.wg.Wait()
}

func (s *oomRuntimeSnapshotService) refreshBPFConfig() {
	s.bpfMu.RLock()
	defer s.bpfMu.RUnlock()
	if s.bpf == nil {
		return
	}
	if err := s.writeBPFConfig(s.bpf); err != nil {
		log.Warnf("update OOM Runtime snapshot BPF config: %v", err)
	}
	// Reconcile the capture-freeze probe with the enable flag. When the feature
	// was disabled at startup the probe was attach-skipped; an enable must
	// attach it, and a disable must detach it again. AttachProgram/DetachProgram
	// are idempotent on the already-attached/detached states.
	if configSnapshot().OOMRuntimeSnapshot.Enabled {
		if err := s.bpf.AttachProgram(oomRuntimeSnapshotExitMMReleaseProgram); err != nil {
			log.Warnf("attach OOM Runtime snapshot %s probe: %v",
				oomRuntimeSnapshotExitMMReleaseProgram, err)
		}
	} else {
		if err := s.bpf.DetachProgram(oomRuntimeSnapshotExitMMReleaseProgram); err != nil {
			log.Warnf("detach OOM Runtime snapshot %s probe: %v",
				oomRuntimeSnapshotExitMMReleaseProgram, err)
		}
	}
}

func (s *oomRuntimeSnapshotService) writeBPFConfig(program bpf.BPF) error {
	// A zero timeout disables the kernel gate (see oom_snapshot_config in
	// bpf/oom.c). Publish it when snapshots are disabled so a PUT /config
	// disable takes effect without restarting Huatuo; validation guarantees
	// the enabled timeout never exceeds the 50 ms hard limit.
	var gateTimeoutNS uint64
	if configSnapshot().OOMRuntimeSnapshot.Enabled {
		gateTimeoutNS = millisecondsToNanoseconds(s.gateTimeoutMilliseconds())
	}
	value := make([]byte, 32)
	binary.NativeEndian.PutUint64(value[0:8], gateTimeoutNS)
	binary.NativeEndian.PutUint64(value[8:16], millisecondsToNanoseconds(
		s.captureCooldownMilliseconds()))
	binary.NativeEndian.PutUint64(value[16:24], millisecondsToNanoseconds(
		s.failureCooldownMilliseconds()))
	binary.NativeEndian.PutUint64(value[24:32], millisecondsToNanoseconds(
		s.maxFailureCooldownMillis()))
	return writeOOMSnapshotMap(program, oomSnapshotConfigMapName, value)
}

func writeOOMSnapshotMap(program bpf.BPF, name string, value []byte) error {
	mapID := program.MapIDByName(name)
	if mapID == 0 {
		return fmt.Errorf("OOM Runtime snapshot BPF map %q is unavailable", name)
	}
	key := make([]byte, 4)
	if err := program.WriteMapItems(mapID, []bpf.MapItem{{Key: key, Value: value}}); err != nil {
		return fmt.Errorf("write OOM Runtime snapshot BPF map %q: %w", name, err)
	}
	return nil
}

func millisecondsToNanoseconds(value int64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value) * uint64(time.Millisecond)
}

// waitBudget bounds how long the OOM event collector waits for an admitted
// event's runtime snapshot. The kernel admits the victim to the gate at any
// time up to SnapshotAdmissionDeadlineNS and starts the capture budget only
// when the victim actually freezes, so the wait must cover the remaining
// admission window plus one capture budget. Waiting only for the gate timeout
// after the perf event would mislabel late-but-legitimate snapshots as gate
// timeouts and drop them.
func (s *oomRuntimeSnapshotService) waitBudget(eventTime time.Time,
	admissionDeadlineNS uint64,
) time.Duration {
	gateTimeout := time.Duration(s.gateTimeoutMilliseconds()) * time.Millisecond
	budget := oomRuntimeSnapshotWaitBudget(eventTime, gateTimeout, time.Now())
	if admissionDeadlineNS == 0 {
		return budget
	}
	nowMono := s.clock.MonotonicNS()
	if nowMono >= admissionDeadlineNS {
		return budget
	}
	admission := time.Duration(admissionDeadlineNS-nowMono) +
		gateTimeout + oomRuntimeSnapshotFinalizeGrace
	if admission > budget {
		return admission
	}
	return budget
}

func (s *oomRuntimeSnapshotService) submit(ctx context.Context, program bpf.BPF,
	event *abi.OOMEvent,
) {
	if event == nil {
		return
	}
	key := oomRuntimeSnapshotKey{
		victimTGID: event.VictimPID, oomMonotonicNS: event.Timestamp,
	}
	switch event.SnapshotGateState {
	case memsnap.OOMSnapshotGateDisabled:
		// The kernel gate is off (zero configured timeout), so no snapshot
		// will ever arrive for this event. Publish a terminal status right
		// away to keep the OOM event from waiting out the gate budget.
		s.publishStatus(key, memsnap.StatusSkippedDisabled,
			"OOM Runtime snapshot gate is disabled")
	case memsnap.OOMSnapshotGateBusy:
		s.metrics.skippedBusy.Add(1)
		s.publishStatus(key, memsnap.StatusSkippedBusy,
			"another OOM Runtime snapshot is active")
	case memsnap.OOMSnapshotGateCooldown:
		s.metrics.skippedCooldown.Add(1)
		s.publishStatus(key, memsnap.StatusSkippedCooldown,
			"host OOM Runtime snapshot cooldown is active")
	case memsnap.OOMSnapshotGateAdmitted:
		s.metrics.requests.Add(1)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.capture(ctx, program, event)
		}()
	}
}

func (s *oomRuntimeSnapshotService) buildOOMRequest(event *abi.OOMEvent,
	identity memsnap.ProcessIdentity, accessTID int, deadlineNS uint64,
) memsnap.Request {
	nowMono := s.clock.MonotonicNS()
	// Read limits from the live config snapshot so PUT /config changes to the
	// capture limits apply without restarting, matching the gate timeout and
	// cooldown values already published live.
	limits := configSnapshot().OOMRuntimeSnapshot
	return memsnap.Request{
		SnapshotID:              fmt.Sprintf("oom-%016x", event.SnapshotCookie),
		OOMRequestCookie:        event.SnapshotCookie,
		OOMMonotonicNS:          event.Timestamp,
		GateDeadlineMonotonicNS: deadlineNS,
		GateDeadline:            s.clock.Now().Add(time.Duration(deadlineNS - nowMono)),
		Identity:                identity,
		AccessTID:               accessTID,
		Trigger:                 memsnap.TriggerOOMVictim,
		MaxOutputBytes:          limits.MaxOutputBytes,
		MaxObjects:              limits.MaxObjects,
		MaxStacks:               limits.MaxStacks,
		MaxStackDepth:           limits.MaxStackDepth,
	}
}

// waitForGateFreeze blocks until the victim reaches exit_mm_release and a
// thread is frozen by the kernel gate. It returns the frozen thread's TID and
// the capture deadline the kernel installed when it froze that thread. It stops
// early when ctx is cancelled so daemon shutdown does not wait out the whole
// admission window for a victim that never freezes.
func (s *oomRuntimeSnapshotService) waitForGateFreeze(ctx context.Context,
	program bpf.BPF, event *abi.OOMEvent,
) (int, uint64, bool) {
	gateTidMapID := program.MapIDByName(oomSnapshotGateTidMapName)
	activeMapID := program.MapIDByName(oomSnapshotActiveMapName)
	if gateTidMapID == 0 || activeMapID == 0 {
		return 0, 0, false
	}
	key := make([]byte, 4)
	admissionDeadline := event.SnapshotAdmissionDeadlineNS
	for {
		if err := ctx.Err(); err != nil {
			return 0, 0, false
		}
		now := s.clock.MonotonicNS()
		if admissionDeadline != 0 && now >= admissionDeadline {
			return 0, 0, false
		}
		value, err := program.ReadMap(gateTidMapID, key)
		if err != nil || len(value) < 4 {
			time.Sleep(100 * time.Microsecond)
			continue
		}
		tid := binary.NativeEndian.Uint32(value[:4])
		if tid == 0 {
			time.Sleep(100 * time.Microsecond)
			continue
		}
		active, err := program.ReadMap(activeMapID, key)
		if err != nil || len(active) < 16 {
			time.Sleep(100 * time.Microsecond)
			continue
		}
		// The active gate slot can be released and reused by a later OOM while
		// this capture goroutine is waiting. Without this check a stale waiter
		// could pair this event with the next victim's frozen TID and attribute
		// that victim's heap to this OOM event.
		if cookie := binary.NativeEndian.Uint64(active[:8]); cookie != event.SnapshotCookie {
			return 0, 0, false
		}
		return int(tid), binary.NativeEndian.Uint64(active[8:16]), true
	}
}

func (s *oomRuntimeSnapshotService) capture(ctx context.Context, program bpf.BPF,
	event *abi.OOMEvent,
) {
	startedMono := s.clock.MonotonicNS()
	key := oomRuntimeSnapshotKey{
		victimTGID: event.VictimPID, oomMonotonicNS: event.Timestamp,
	}

	// Freeze the victim first. Everything after this must address the frozen
	// thread (accessTID), not the thread-group leader whose mm/fs can already
	// be torn down once the other threads proceed through do_exit.
	accessTID, captureDeadlineNS, ok := s.waitForGateFreeze(ctx, program, event)
	if !ok {
		s.metrics.gateWaitNSTotal.Add(s.clock.MonotonicNS() - startedMono)
		s.finish(program, event, key, nil, memsnap.StatusGateTimeout,
			"victim did not reach the OOM snapshot gate before the admission deadline")
		return
	}
	nowMono := s.clock.MonotonicNS()
	if captureDeadlineNS <= nowMono {
		s.metrics.gateWaitNSTotal.Add(s.clock.MonotonicNS() - startedMono)
		s.finish(program, event, key, nil, memsnap.StatusGateTimeout,
			"BPF gate deadline expired before capture")
		return
	}

	identity, err := s.identities.Read(int(event.VictimPID))
	if err != nil {
		s.finish(program, event, key, nil, memsnap.StatusIdentityUnavailable,
			fmt.Sprintf("victim identity is unavailable: %v", err))
		return
	}

	metadata, filtered := s.filterMetadata(accessTID)
	language := memsnap.LanguageUnknown
	if filtered {
		request := s.buildOOMRequest(event, identity, accessTID, captureDeadlineNS)
		result := terminalSnapshot(request, language, memsnap.StatusFiltered,
			"victim metadata matched the configured filter", s.clock)
		s.metrics.gateWaitNSTotal.Add(s.clock.MonotonicNS() - startedMono)
		s.finish(program, event, key, result, result.Manifest.Status, "")
		return
	}

	language = s.detectLanguage(identity, event.VictimComm, metadata, accessTID)
	request := s.buildOOMRequest(event, identity, accessTID, captureDeadlineNS)
	prepared := s.coordinator.PrepareVerified(ctx, language, request)
	status := prepared.Status()
	ackErr := s.ack(program, event.SnapshotCookie, status)
	ackMono := s.clock.MonotonicNS()
	s.metrics.gateWaitNSTotal.Add(ackMono - startedMono)
	result := s.coordinator.Finalize(prepared)
	s.publishAfterAck(key, event.SnapshotCookie, result, status, ackMono, ackErr,
		"Runtime snapshot did not produce a local result")
}

func (s *oomRuntimeSnapshotService) publishAfterAck(key oomRuntimeSnapshotKey,
	cookie uint64, result *memsnap.Result, status memsnap.CompletionStatus,
	ackMono uint64, ackErr error, reason string,
) {
	if ackErr != nil {
		if result != nil {
			result.Manifest.GateRelease = "timeout_or_ack_missed"
		}
		s.metrics.ackFailed.Add(1)
		log.Warnf("ack OOM Runtime snapshot cookie %d: %v", cookie, ackErr)
	} else {
		s.metrics.acked.Add(1)
		if result != nil {
			result.Manifest.GateRelease = "ack"
			result.Manifest.GateAckMonotonicNS = ackMono
		}
	}
	if result == nil {
		if ackErr != nil {
			status = memsnap.StatusGateTimeout
			reason = "BPF rejected or timed out the Runtime snapshot ACK"
		}
		snapshot := runtimeSnapshotStatus(key, status, reason)
		runtimeSnapshotBridge.publish(key, snapshot)
		s.recordStatus(status)
		s.metrics.published.Add(1)
		return
	}
	// ACK failure no longer discards a useful captured prefix. A zero
	// GateAckMonotonicNS records that the gate outcome was not observed.
	s.metrics.payloadBytes.Add(uint64(result.Manifest.PayloadBytes))
	s.recordStatus(result.Manifest.Status)
	runtimeSnapshotBridge.publish(key, runtimeSnapshotFromResult(result))
	s.metrics.published.Add(1)
}

func (s *oomRuntimeSnapshotService) finish(program bpf.BPF, event *abi.OOMEvent,
	key oomRuntimeSnapshotKey, result *memsnap.Result,
	status memsnap.CompletionStatus, reason string,
) {
	ackErr := s.ack(program, event.SnapshotCookie, status)
	s.publishAfterAck(key, event.SnapshotCookie, result, status,
		s.clock.MonotonicNS(), ackErr, reason)
}

func (s *oomRuntimeSnapshotService) ack(program bpf.BPF, cookie uint64,
	status memsnap.CompletionStatus,
) error {
	if cookie == 0 {
		return errors.New("OOM Runtime snapshot ACK cookie is zero")
	}
	activeMapID := program.MapIDByName(oomSnapshotActiveMapName)
	if activeMapID == 0 {
		return errors.New("OOM Runtime snapshot active map is unavailable")
	}
	active, err := program.ReadMap(activeMapID, make([]byte, 4))
	if err != nil || len(active) < 16 ||
		binary.NativeEndian.Uint64(active[:8]) != cookie {
		return s.gateReleaseError(program, cookie,
			"OOM Runtime snapshot gate expired before ACK")
	}
	now := s.clock.MonotonicNS()
	if now >= binary.NativeEndian.Uint64(active[8:16]) {
		return s.gateReleaseError(program, cookie,
			"OOM Runtime snapshot ACK missed its deadline")
	}
	ack := make([]byte, 16)
	binary.NativeEndian.PutUint64(ack[0:8], cookie)
	binary.NativeEndian.PutUint32(ack[8:12], memsnap.OOMSnapshotStatusToAck(status))
	if err := writeOOMSnapshotMap(program, oomSnapshotAckMapName, ack); err != nil {
		return err
	}
	return s.waitForGateRelease(program, cookie,
		binary.NativeEndian.Uint64(active[8:16]))
}

func (s *oomRuntimeSnapshotService) waitForGateRelease(program bpf.BPF,
	cookie, deadline uint64,
) error {
	for {
		now := s.clock.MonotonicNS()
		reason, releaseNS, err := readOOMSnapshotRelease(program, cookie)
		if err == nil {
			if reason != memsnap.OOMSnapshotReleaseACK {
				return fmt.Errorf("BPF released OOM Runtime snapshot gate via %s at %d",
					memsnap.OOMSnapshotReleaseReasonName(reason), releaseNS)
			}
			return nil
		}
		if !errors.Is(err, bpf.ErrMapKeyNotFound) {
			return fmt.Errorf("observe OOM Runtime snapshot gate release: %w", err)
		}
		if now >= deadline {
			return errors.New("BPF did not release the OOM gate after its ACK")
		}
		time.Sleep(10 * time.Microsecond)
	}
}

func (s *oomRuntimeSnapshotService) gateReleaseError(program bpf.BPF,
	cookie uint64, fallback string,
) error {
	reason, releaseNS, err := readOOMSnapshotRelease(program, cookie)
	if err != nil {
		return errors.New(fallback)
	}
	return fmt.Errorf("BPF released OOM Runtime snapshot gate via %s at %d",
		memsnap.OOMSnapshotReleaseReasonName(reason), releaseNS)
}

func readOOMSnapshotRelease(program bpf.BPF, cookie uint64) (uint32, uint64, error) {
	mapID := program.MapIDByName(oomSnapshotReleaseMapName)
	if mapID == 0 {
		return 0, 0, errors.New("OOM Runtime snapshot release map is unavailable")
	}
	key := make([]byte, 8)
	binary.NativeEndian.PutUint64(key, cookie)
	value, err := program.ReadMap(mapID, key)
	if err != nil {
		return 0, 0, err
	}
	if len(value) < 20 {
		return 0, 0, bpf.ErrMapKeyNotFound
	}
	if binary.NativeEndian.Uint64(value[0:8]) != cookie {
		return 0, 0, errors.New("OOM Runtime snapshot release record is unavailable")
	}
	_ = program.DeleteMapItems(mapID, [][]byte{key})
	return binary.NativeEndian.Uint32(value[16:20]),
		binary.NativeEndian.Uint64(value[8:16]), nil
}

func (s *oomRuntimeSnapshotService) publishStatus(key oomRuntimeSnapshotKey,
	status memsnap.CompletionStatus, reason string,
) {
	runtimeSnapshotBridge.publish(key, runtimeSnapshotStatus(key, status, reason))
	s.metrics.published.Add(1)
}

func (s *oomRuntimeSnapshotService) recordStatus(status memsnap.CompletionStatus) {
	switch {
	case status == memsnap.StatusComplete:
		s.metrics.completed.Add(1)
	case status.IsPartial():
		s.metrics.partial.Add(1)
	case status == memsnap.StatusProviderUnavailable ||
		status == memsnap.StatusIdentityUnavailable:
		s.metrics.unavailable.Add(1)
	default:
		s.metrics.failed.Add(1)
	}
}

func (s *oomRuntimeSnapshotService) Update() []*metric.Data {
	counters := []struct {
		name  string
		help  string
		value uint64
	}{
		{"runtime_snapshot_gate_requests_total", "admitted OOM Runtime snapshots", s.metrics.requests.Load()},
		{"runtime_snapshot_gate_acked_total", "acknowledged OOM Runtime snapshots", s.metrics.acked.Load()},
		{"runtime_snapshot_gate_ack_failed_total", "failed OOM Runtime snapshot ACKs", s.metrics.ackFailed.Load()},
		{"runtime_snapshot_completed_total", "complete Runtime FAST snapshots", s.metrics.completed.Load()},
		{"runtime_snapshot_partial_total", "partial Runtime FAST snapshots", s.metrics.partial.Load()},
		{"runtime_snapshot_provider_unavailable_total", "victims without a Runtime provider", s.metrics.unavailable.Load()},
		{"runtime_snapshot_failed_total", "failed Runtime FAST snapshots", s.metrics.failed.Load()},
		{"runtime_snapshot_payload_bytes_total", "Runtime snapshot payload bytes copied", s.metrics.payloadBytes.Load()},
		{"runtime_snapshot_published_total", "Runtime snapshots merged with OOM events", s.metrics.published.Load()},
		{"runtime_snapshot_gate_wait_nanoseconds_total", "total admitted Runtime capture time", s.metrics.gateWaitNSTotal.Load()},
		{"runtime_snapshot_skipped_busy_total", "OOM snapshots skipped while another capture was active", s.metrics.skippedBusy.Load()},
		{"runtime_snapshot_skipped_cooldown_total", "OOM snapshots skipped during cooldown", s.metrics.skippedCooldown.Load()},
	}
	data := make([]*metric.Data, 0, len(counters)+4)
	for _, counter := range counters {
		data = append(data, metric.NewCounterData(counter.name,
			float64(counter.value), counter.help, nil))
	}
	data = append(data,
		metric.NewGaugeData("runtime_snapshot_gate_timeout_milliseconds",
			float64(s.gateTimeoutMilliseconds()), "live BPF OOM gate timeout", nil),
		metric.NewGaugeData("runtime_snapshot_capture_cooldown_milliseconds",
			float64(s.captureCooldownMilliseconds()), "successful capture cooldown", nil),
		metric.NewGaugeData("runtime_snapshot_failure_cooldown_milliseconds",
			float64(s.failureCooldownMilliseconds()), "initial failed capture cooldown", nil),
		metric.NewGaugeData("runtime_snapshot_failure_streak",
			float64(s.readBPFFailureStreak()), "consecutive Runtime capture failures", nil))
	return data
}

func (s *oomRuntimeSnapshotService) readBPFFailureStreak() uint32 {
	s.bpfMu.RLock()
	defer s.bpfMu.RUnlock()
	if s.bpf == nil {
		return 0
	}
	mapID := s.bpf.MapIDByName(oomSnapshotStateMapName)
	if mapID == 0 {
		return 0
	}
	value, err := s.bpf.ReadMap(mapID, make([]byte, 4))
	if err != nil || len(value) < 12 {
		return 0
	}
	return binary.NativeEndian.Uint32(value[8:12])
}

// detectLanguage resolves the victim runtime. identity.TGID is the thread-group
// leader; accessTID is the tid of the thread frozen at the OOM gate (zero when
// unknown, in which case the leader TGID is used). Metadata detection avoids ELF
// parsing on the OOM critical path; the /proc fallback reads /proc/<pid>/exe
// and is needed mostly for Go binaries.
func (s *oomRuntimeSnapshotService) detectLanguage(identity memsnap.ProcessIdentity,
	comm [16]uint8, cmdline string, accessTID int,
) memsnap.Language {
	// Java, Python and Node are identifiable from comm/cmdline and skip ELF
	// parsing on the OOM critical path. Go binaries typically carry an
	// arbitrary comm, so they fall through to DetectLanguageFromPID, which
	// reads /proc/<pid>/exe to recover Go build information.
	metadataLanguage := memsnap.DetectLanguageFromMetadata(
		strings.TrimRight(string(comm[:]), "\x00"), cmdline)
	if metadataLanguage != memsnap.LanguageUnknown {
		return metadataLanguage
	}
	if accessTID > 0 {
		return memsnap.DetectLanguageFromPID(accessTID)
	}
	return memsnap.DetectLanguageFromPID(identity.TGID)
}

// filterMetadata reads /proc/<tid>/cmdline through the frozen gate thread TID
// (accessTID), whose fs is still alive while the thread-group leader's may have
// been torn down.
func (s *oomRuntimeSnapshotService) filterMetadata(accessTID int) (string, bool) {
	if len(s.included) == 0 && len(s.excluded) == 0 {
		return "", false
	}
	raw, _ := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", accessTID))
	metadata := strings.ReplaceAll(string(raw), "\x00", " ")
	if len(s.included) > 0 && !matchesAny(s.included, metadata) {
		return metadata, true
	}
	return metadata, matchesAny(s.excluded, metadata)
}

//nolint:gocritic // Terminal results retain the immutable request values.
func terminalSnapshot(request memsnap.Request, language memsnap.Language,
	status memsnap.CompletionStatus, reason string, clock memsnap.Clock,
) *memsnap.Result {
	now := clock.Now()
	mono := clock.MonotonicNS()
	return memsnap.TerminalResult(request, language, status, reason,
		now, now, mono, mono)
}

func compileSnapshotFilters(values []string) ([]*regexp.Regexp, error) {
	filters := make([]*regexp.Regexp, 0, len(values))
	for _, value := range values {
		filter, err := regexp.Compile(value)
		if err != nil {
			return nil, err
		}
		filters = append(filters, filter)
	}
	return filters, nil
}

func matchesAny(filters []*regexp.Regexp, value string) bool {
	for _, filter := range filters {
		if filter.MatchString(value) {
			return true
		}
	}
	return false
}
