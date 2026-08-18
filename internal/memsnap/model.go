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
	"time"
)

const (
	SchemaVersion           = 2
	ScopeRuntimeManagedHeap = "runtime_managed_heap"
	ModeFast                = "fast"
	TriggerOOMVictim        = "oom_victim"
)

// CompletionStatus describes the useful result, not whether the victim is
// allowed to exit. The kernel gate must always continue after ACK or timeout.
type CompletionStatus string

const (
	StatusComplete              CompletionStatus = "COMPLETE"
	StatusPartialOutputLimit    CompletionStatus = "PARTIAL_OUTPUT_LIMIT"
	StatusPartialObjectLimit    CompletionStatus = "PARTIAL_OBJECT_LIMIT"
	StatusPartialRecordLimit    CompletionStatus = "PARTIAL_RECORD_LIMIT"
	StatusPartialDeadline       CompletionStatus = "PARTIAL_DEADLINE"
	StatusPartialMemoryPressure CompletionStatus = "PARTIAL_MEMORY_PRESSURE"
	StatusRuntimeBusy           CompletionStatus = "RUNTIME_BUSY"
	StatusProcessExited         CompletionStatus = "PROCESS_EXITED"
	StatusProviderUnavailable   CompletionStatus = "PROVIDER_UNAVAILABLE"
	StatusFiltered              CompletionStatus = "FILTERED"
	StatusSkippedBusy           CompletionStatus = "SKIPPED_BUSY"
	StatusSkippedCooldown       CompletionStatus = "SKIPPED_COOLDOWN"
	StatusSkippedDisabled       CompletionStatus = "SKIPPED_DISABLED"
	StatusIdentityUnavailable   CompletionStatus = "IDENTITY_UNAVAILABLE"
	StatusGateTimeout           CompletionStatus = "GATE_TIMEOUT"
	StatusCaptureFailed         CompletionStatus = "CAPTURE_FAILED"
)

func (s CompletionStatus) IsPartial() bool {
	switch s {
	case StatusPartialOutputLimit, StatusPartialObjectLimit,
		StatusPartialRecordLimit, StatusPartialDeadline,
		StatusPartialMemoryPressure:
		return true
	default:
		return false
	}
}

type ProcessIdentity struct {
	// TGID is the OOM victim's thread-group leader ID. /proc/<TGID> is named by
	// this value, and the start-time identity is read from /proc/<TGID>/stat.
	TGID           int    `json:"tgid"`
	StartTimeTicks uint64 `json:"starttime_ticks"`
	BootID         string `json:"boot_id"`
}

func (p ProcessIdentity) Validate() error {
	if p.TGID <= 0 {
		return errors.New("tgid must be greater than zero")
	}
	if p.StartTimeTicks == 0 {
		return errors.New("process starttime must be greater than zero")
	}
	if p.BootID == "" {
		return errors.New("boot ID is required")
	}
	return nil
}

type Request struct {
	SnapshotID              string          `json:"snapshot_id"`
	OOMRequestCookie        uint64          `json:"oom_request_cookie"`
	OOMMonotonicNS          uint64          `json:"oom_monotonic_ns"`
	GateDeadlineMonotonicNS uint64          `json:"gate_deadline_monotonic_ns"`
	GateDeadline            time.Time       `json:"gate_deadline"`
	Identity                ProcessIdentity `json:"identity"`
	// AccessTID is the kernel thread ID (tid) of the thread frozen at the OOM
	// gate. Providers must read victim memory and /proc entries through this TID
	// rather than Identity.TGID (the thread-group leader), whose mm/fs may
	// already be torn down once the other threads proceed through do_exit. Zero
	// means fall back to Identity.TGID.
	AccessTID      int    `json:"access_tid,omitempty"`
	Trigger        string `json:"trigger"`
	MaxOutputBytes int64  `json:"max_output_bytes"`
	MaxObjects     int    `json:"max_objects"`
	MaxStacks      int    `json:"max_stacks"`
	MaxStackDepth  int    `json:"max_stack_depth"`
}

// ReadPID returns the value providers should use to read victim memory and
// /proc entries: the frozen gate thread TID (AccessTID) when known, otherwise
// the thread-group leader TGID (Identity.TGID).
func (r Request) ReadPID() int {
	if r.AccessTID > 0 {
		return r.AccessTID
	}
	return r.Identity.TGID
}

func (r *Request) Validate(now time.Time) error {
	if r.SnapshotID == "" {
		return errors.New("snapshot ID is required")
	}
	if r.OOMRequestCookie == 0 {
		return errors.New("OOM request cookie must be non-zero")
	}
	if r.Trigger != TriggerOOMVictim {
		return fmt.Errorf("unsupported snapshot trigger %q", r.Trigger)
	}
	if err := r.Identity.Validate(); err != nil {
		return fmt.Errorf("invalid process identity: %w", err)
	}
	if r.GateDeadline.IsZero() || !r.GateDeadline.After(now) {
		return errors.New("gate deadline must be in the future")
	}
	if r.MaxOutputBytes <= 0 || r.MaxObjects <= 0 ||
		r.MaxStacks <= 0 || r.MaxStackDepth <= 0 {
		return errors.New("all snapshot limits must be greater than zero")
	}
	return nil
}

type Coverage struct {
	Consistency          string                    `json:"consistency"`
	SizeSemantics        string                    `json:"size_semantics"`
	Impact               string                    `json:"impact,omitempty"`
	ObjectType           string                    `json:"object_type,omitempty"`
	ClassLoaderIdentity  string                    `json:"classloader_identity,omitempty"`
	SampleRateAssumption string                    `json:"sample_rate_assumption,omitempty"`
	ScannedBytes         uint64                    `json:"scanned_bytes,omitempty"`
	HeapUsedBytes        uint64                    `json:"heap_used_bytes,omitempty"`
	ScannedRegions       uint64                    `json:"scanned_regions,omitempty"`
	TotalRegions         uint64                    `json:"total_regions,omitempty"`
	ClassifiedBytes      uint64                    `json:"classified_bytes,omitempty"`
	RawCoverage          float64                   `json:"raw_coverage,omitempty"`
	Estimated            bool                      `json:"estimated,omitempty"`
	EstimationMethod     string                    `json:"estimation_method,omitempty"`
	SamplingSeed         uint64                    `json:"sampling_seed,omitempty"`
	PlannedRegions       uint64                    `json:"planned_regions,omitempty"`
	CompletedRegions     uint64                    `json:"completed_regions,omitempty"`
	SamplingStrata       []SamplingStratumCoverage `json:"sampling_strata,omitempty"`
	KnownGaps            []string                  `json:"known_gaps"`
}

type SamplingStratumCoverage struct {
	Name             string `json:"name"`
	TotalRegions     uint64 `json:"total_regions"`
	PlannedRegions   uint64 `json:"planned_regions"`
	CompletedRegions uint64 `json:"completed_regions"`
	TotalUsedBytes   uint64 `json:"total_used_bytes"`
	ClassifiedBytes  uint64 `json:"classified_bytes"`
}

func (c *Coverage) Validate() error {
	if c.Consistency == "" || c.SizeSemantics == "" || len(c.KnownGaps) == 0 {
		return errors.New("consistency, size semantics, and known gaps are required")
	}
	return nil
}

type ShapeBucket struct {
	Name  string `json:"name"`
	Count uint64 `json:"count"`
}

type FieldShape struct {
	Name                    string        `json:"name"`
	ReferencedType          string        `json:"referenced_type"`
	ReferenceCount          uint64        `json:"reference_count"`
	UniqueReferencedObjects uint64        `json:"unique_referenced_objects"`
	ReferencedShallowBytes  uint64        `json:"referenced_shallow_bytes"`
	AverageReferencedBytes  float64       `json:"average_referenced_bytes"`
	TotalReferencedLength   uint64        `json:"total_referenced_length,omitempty"`
	AverageReferencedLength float64       `json:"average_referenced_length,omitempty"`
	LengthBuckets           []ShapeBucket `json:"length_buckets,omitempty"`
}

type ObjectAggregate struct {
	TypeName           string        `json:"type_name"`
	RawTypeName        string        `json:"raw_type_name,omitempty"`
	ModuleSuffix       string        `json:"module_suffix,omitempty"`
	Count              uint64        `json:"count"`
	ShallowBytes       uint64        `json:"shallow_bytes"`
	AverageBytes       float64       `json:"average_bytes"`
	SampledBytes       uint64        `json:"sampled_bytes,omitempty"`
	SampledCount       uint64        `json:"sampled_count,omitempty"`
	Estimated          bool          `json:"estimated,omitempty"`
	EstimateRSE        float64       `json:"estimate_rse,omitempty"`
	EstimateLowerBytes uint64        `json:"estimate_lower_bytes,omitempty"`
	EstimateUpperBytes uint64        `json:"estimate_upper_bytes,omitempty"`
	EstimateConfidence string        `json:"estimate_confidence,omitempty"`
	SampledRegions     uint64        `json:"sampled_regions,omitempty"`
	LengthBuckets      []ShapeBucket `json:"length_buckets,omitempty"`
	Fields             []FieldShape  `json:"fields,omitempty"`
}

type AllocationSample struct {
	Stack        []string `json:"stack"`
	SampledBytes int64    `json:"sampled_bytes"`
	SampledCount int64    `json:"sampled_count"`
	InuseBytes   int64    `json:"inuse_bytes"`
	InuseObjects int64    `json:"inuse_objects"`
}

type EntryKind string

const (
	EntryKindObjectType     EntryKind = "object_type"
	EntryKindAllocationSite EntryKind = "allocation_site"
)

// Entry is the common wire representation for every supported Runtime. The
// in-use fields always describe the current managed-heap contribution. Runtime
// capabilities that do not exist for a language are omitted from JSON instead
// of being emitted as empty placeholders.
type Entry struct {
	Kind               EntryKind     `json:"kind"`
	Name               string        `json:"name"`
	InuseBytes         uint64        `json:"inuse_bytes"`
	InuseObjects       uint64        `json:"inuse_objects"`
	AverageBytes       float64       `json:"average_bytes"`
	RawTypeName        string        `json:"raw_type_name,omitempty"`
	ModuleSuffix       string        `json:"module_suffix,omitempty"`
	AllocationStack    []string      `json:"allocation_stack,omitempty"`
	SampledBytes       uint64        `json:"sampled_bytes,omitempty"`
	SampledCount       uint64        `json:"sampled_count,omitempty"`
	Estimated          bool          `json:"estimated,omitempty"`
	EstimateRSE        float64       `json:"estimate_rse,omitempty"`
	EstimateLowerBytes uint64        `json:"estimate_lower_bytes,omitempty"`
	EstimateUpperBytes uint64        `json:"estimate_upper_bytes,omitempty"`
	EstimateConfidence string        `json:"estimate_confidence,omitempty"`
	SampledRegions     uint64        `json:"sampled_regions,omitempty"`
	LengthBuckets      []ShapeBucket `json:"length_buckets,omitempty"`
	Fields             []FieldShape  `json:"fields,omitempty"`
}

type Manifest struct {
	SchemaVersion               int              `json:"schema_version"`
	SnapshotID                  string           `json:"snapshot_id"`
	OOMRequestCookie            uint64           `json:"oom_request_cookie"`
	OOMMonotonicNS              uint64           `json:"oom_monotonic_ns"`
	GateDeadlineMonotonicNS     uint64           `json:"gate_deadline_monotonic_ns"`
	GateAckMonotonicNS          uint64           `json:"gate_ack_monotonic_ns,omitempty"`
	Identity                    ProcessIdentity  `json:"identity"`
	Language                    Language         `json:"language"`
	RuntimeVersion              string           `json:"runtime_version,omitempty"`
	Scope                       string           `json:"scope"`
	Mode                        string           `json:"mode"`
	Trigger                     string           `json:"trigger"`
	Status                      CompletionStatus `json:"status"`
	GateRelease                 string           `json:"gate_release,omitempty"`
	Truncated                   bool             `json:"truncated"`
	TruncationReasons           []string         `json:"truncation_reasons,omitempty"`
	Coverage                    Coverage         `json:"coverage"`
	CaptureStartedWallTime      time.Time        `json:"capture_started_wall_time"`
	CaptureCompletedWallTime    time.Time        `json:"capture_completed_wall_time"`
	CaptureStartedMonotonicNS   uint64           `json:"capture_started_monotonic_ns"`
	CaptureCompletedMonotonicNS uint64           `json:"capture_completed_monotonic_ns"`
	PayloadBytes                int64            `json:"payload_bytes"`
	EntryCount                  int              `json:"entry_count"`
	ObjectCount                 int              `json:"-"`
	StackCount                  int              `json:"-"`
	ExpiresAt                   time.Time        `json:"expires_at,omitempty"`
}

func (m *Manifest) Validate() error {
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema version %d", m.SchemaVersion)
	}
	if m.SnapshotID == "" || m.OOMRequestCookie == 0 {
		return errors.New("snapshot ID and OOM request cookie are required")
	}
	if err := m.Identity.Validate(); err != nil {
		return fmt.Errorf("invalid process identity: %w", err)
	}
	if m.Language == LanguageUnknown {
		return errors.New("runtime language is required")
	}
	if m.Scope != ScopeRuntimeManagedHeap || m.Mode != ModeFast ||
		m.Trigger != TriggerOOMVictim {
		return errors.New("manifest scope, mode, or trigger is invalid")
	}
	if err := m.Coverage.Validate(); err != nil {
		return fmt.Errorf("invalid coverage: %w", err)
	}
	if m.Status == StatusComplete && m.Truncated {
		return errors.New("complete snapshot cannot be truncated")
	}
	if m.Status.IsPartial() && !m.Truncated {
		return errors.New("partial snapshot must be marked truncated")
	}
	if m.Truncated && len(m.TruncationReasons) == 0 {
		return errors.New("truncated snapshot requires a reason")
	}
	if m.CaptureStartedWallTime.IsZero() ||
		m.CaptureCompletedWallTime.Before(m.CaptureStartedWallTime) {
		return errors.New("capture wall-clock interval is invalid")
	}
	if m.CaptureCompletedMonotonicNS < m.CaptureStartedMonotonicNS {
		return errors.New("capture monotonic interval is invalid")
	}
	if m.PayloadBytes < 0 || m.EntryCount < 0 ||
		m.ObjectCount < 0 || m.StackCount < 0 {
		return errors.New("payload counters cannot be negative")
	}
	return nil
}

type Result struct {
	Manifest    Manifest           `json:"manifest"`
	Objects     []ObjectAggregate  `json:"-"`
	Allocations []AllocationSample `json:"-"`
	// FinalizeLocal completes provider work using only memory already owned by
	// Huatuo. The coordinator invokes it after the OOM gate is released.
	FinalizeLocal func() error `json:"-"`
}

// RuntimeSnapshotPayload is the compact public payload embedded directly into
// the original OOM event. Correlation, gate and process-identity fields remain
// in Manifest for internal safety but are deliberately excluded here because
// the enclosing OOM document already identifies the event and victim.
type RuntimeSnapshotPayload struct {
	SchemaVersion               int              `json:"schema_version"`
	RuntimeVersion              string           `json:"runtime_version,omitempty"`
	Status                      CompletionStatus `json:"status"`
	GateRelease                 string           `json:"gate_release,omitempty"`
	Truncated                   bool             `json:"truncated"`
	TruncationReasons           []string         `json:"truncation_reasons,omitempty"`
	CaptureDurationMilliseconds uint64           `json:"capture_duration_ms"`
	Coverage                    Coverage         `json:"coverage"`
	PayloadBytes                int64            `json:"payload_bytes"`
	EntryCount                  int              `json:"entry_count"`
	Entries                     []Entry          `json:"entries,omitempty"`
}

func RuntimePayloadFromResult(result *Result) *RuntimeSnapshotPayload {
	if result == nil {
		return nil
	}
	entries := make([]Entry, 0, len(result.Objects)+len(result.Allocations))
	for _, object := range result.Objects {
		entries = append(entries, Entry{
			Kind: EntryKindObjectType, Name: object.TypeName,
			InuseBytes: object.ShallowBytes, InuseObjects: object.Count,
			AverageBytes: object.AverageBytes, RawTypeName: object.RawTypeName,
			ModuleSuffix:       object.ModuleSuffix,
			SampledBytes:       object.SampledBytes,
			SampledCount:       object.SampledCount,
			Estimated:          object.Estimated,
			EstimateRSE:        object.EstimateRSE,
			EstimateLowerBytes: object.EstimateLowerBytes,
			EstimateUpperBytes: object.EstimateUpperBytes,
			EstimateConfidence: object.EstimateConfidence,
			SampledRegions:     object.SampledRegions,
			LengthBuckets:      append([]ShapeBucket(nil), object.LengthBuckets...),
			Fields:             append([]FieldShape(nil), object.Fields...),
		})
	}
	for _, allocation := range result.Allocations {
		name := "unknown"
		if len(allocation.Stack) != 0 {
			// Go runtime.MemProfileRecord stores the allocation site first.
			name = allocation.Stack[0]
		}
		inuseBytes := nonNegativeUint64(allocation.InuseBytes)
		inuseObjects := nonNegativeUint64(allocation.InuseObjects)
		averageBytes := float64(0)
		if inuseObjects != 0 {
			averageBytes = float64(inuseBytes) / float64(inuseObjects)
		}
		entries = append(entries, Entry{
			Kind: EntryKindAllocationSite, Name: name,
			InuseBytes: inuseBytes, InuseObjects: inuseObjects,
			AverageBytes:    averageBytes,
			AllocationStack: append([]string(nil), allocation.Stack...),
			SampledBytes:    nonNegativeUint64(allocation.SampledBytes),
			SampledCount:    nonNegativeUint64(allocation.SampledCount),
		})
	}
	return &RuntimeSnapshotPayload{
		SchemaVersion:  result.Manifest.SchemaVersion,
		RuntimeVersion: result.Manifest.RuntimeVersion,
		Status:         result.Manifest.Status,
		GateRelease:    result.Manifest.GateRelease,
		Truncated:      result.Manifest.Truncated,
		TruncationReasons: append([]string(nil),
			result.Manifest.TruncationReasons...),
		CaptureDurationMilliseconds: captureDurationMilliseconds(&result.Manifest),
		Coverage:                    result.Manifest.Coverage,
		PayloadBytes:                result.Manifest.PayloadBytes,
		EntryCount:                  len(entries),
		Entries:                     entries,
	}
}

func captureDurationMilliseconds(manifest *Manifest) uint64 {
	if manifest.CaptureCompletedMonotonicNS >=
		manifest.CaptureStartedMonotonicNS &&
		manifest.CaptureStartedMonotonicNS != 0 {
		return roundedUpMilliseconds(manifest.CaptureCompletedMonotonicNS -
			manifest.CaptureStartedMonotonicNS)
	}
	if manifest.CaptureStartedWallTime.IsZero() ||
		manifest.CaptureCompletedWallTime.Before(manifest.CaptureStartedWallTime) {
		return 0
	}
	return roundedUpMilliseconds(uint64(manifest.CaptureCompletedWallTime.
		Sub(manifest.CaptureStartedWallTime)))
}

func roundedUpMilliseconds(nanoseconds uint64) uint64 {
	const nanosecondsPerMillisecond = uint64(time.Millisecond)
	if nanoseconds == 0 {
		return 0
	}
	return 1 + (nanoseconds-1)/nanosecondsPerMillisecond
}

func nonNegativeUint64(value int64) uint64 {
	if value <= 0 {
		return 0
	}
	return uint64(value)
}
