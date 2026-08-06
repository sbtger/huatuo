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
	"testing"
	"time"

	"huatuo-bamai/internal/javastack"
	"huatuo-bamai/internal/profiler"
	"huatuo-bamai/pkg/tracing"

	"github.com/stretchr/testify/require"
)

func testOOMJavaStackProfiler() (*oomJavaStackProfiler, *[]*tracing.WriteRequest) {
	writes := make([]*tracing.WriteRequest, 0, 1)
	p := &oomJavaStackProfiler{
		pending:    make(map[oomJavaStackKey]*pendingOOMJavaStack),
		pendingTTL: time.Second, maxPending: 2, now: time.Now,
		resolve: func(*javastack.Snapshot) javastack.Resolution {
			return javastack.Resolution{
				Frames:         []javastack.Frame{{PC: 0x1234, Name: "com.example.Work.run()V", Kind: "java"}},
				ResolvedFrames: 1, DirectAvailable: true,
			}
		},
		save: func(request *tracing.WriteRequest) error {
			writes = append(writes, request)
			return nil
		},
	}
	return p, &writes
}

func testJavaSnapshot() *javastack.Snapshot {
	return &javastack.Snapshot{
		Target:       javastack.Target{Identity: javastack.Identity{PID: 42, StartTimeTicks: 99}},
		OOMTimestamp: 100, CaptureTimestamp: 125, CaptureDurationNS: 500, CgroupID: 7,
		VictimTID: 43, StackSize: 8, Flags: javastack.CaptureFlagCaptured,
		PCs: []uint64{0x1234},
	}
}

func TestOOMJavaStackProfilerPairsAndStoresSingleSample(t *testing.T) {
	p, writes := testOOMJavaStackProfiler()
	eventTime := time.Unix(10, 20)
	require.NoError(t, p.HandleSnapshot(testJavaSnapshot()))
	require.Empty(t, *writes)
	require.NoError(t, p.ObserveOOM(42, 100, "oom-id", "container-id", eventTime))
	require.Len(t, *writes, 1)
	write := (*writes)[0]
	require.Equal(t, oomJavaStackTracerName, write.TracerName)
	require.Equal(t, "oom-id", write.TracerID)
	require.Equal(t, "container-id", write.ContainerID)
	data, ok := write.TracerData.(*oomJavaStackProfileData)
	require.True(t, ok)
	require.Equal(t, profiler.ProfileTypeEventSample, data.FlameData.ProfileType)
	require.Equal(t, uint64(25), data.Correlation.SignalDelayNS)
	require.Equal(t, uint64(500), data.Capture.BPFCaptureDurationNS)
	require.Equal(t, "current_signal_thread", data.Capture.SnapshotSemantics)
	require.False(t, data.Capture.Complete)
	require.Equal(t, "com.example.Work.run()V", data.Frames[0].Name)
}

func TestOOMJavaStackProfilerPersistsCaptureFailure(t *testing.T) {
	p, writes := testOOMJavaStackProfiler()
	p.resolve = func(*javastack.Snapshot) javastack.Resolution { return javastack.Resolution{} }
	snapshot := testJavaSnapshot()
	snapshot.StackSize = -14
	snapshot.PCs = nil
	require.NoError(t, p.ObserveOOM(42, 100, "oom-id", "", time.Now()))
	require.NoError(t, p.HandleSnapshot(snapshot))
	require.Len(t, *writes, 1)
	data := (*writes)[0].TracerData.(*oomJavaStackProfileData)
	require.Equal(t, int32(-14), data.Capture.StackError)
}

func TestOOMJavaStackProfilerMarksSelectedThreadGroupMember(t *testing.T) {
	p, writes := testOOMJavaStackProfiler()
	snapshot := testJavaSnapshot()
	snapshot.Flags |= javastack.CaptureFlagHotspotUnwound |
		javastack.CaptureFlagThreadScanned
	require.NoError(t, p.ObserveOOM(42, 100, "oom-id", "", time.Now()))
	require.NoError(t, p.HandleSnapshot(snapshot))
	require.Len(t, *writes, 1)
	data := (*writes)[0].TracerData.(*oomJavaStackProfileData)
	require.True(t, data.Capture.HotspotUnwound)
	require.True(t, data.Capture.ThreadGroupScanned)
	require.Equal(t, "selected_thread_group_member", data.Capture.SnapshotSemantics)
}

func TestOOMJavaStackProfilerRejectsInvalidSnapshot(t *testing.T) {
	p, _ := testOOMJavaStackProfiler()
	require.EqualError(t, p.HandleSnapshot(nil), "oom Java stack: nil snapshot")
	require.EqualError(t, p.HandleSnapshot(&javastack.Snapshot{}),
		"oom Java stack: snapshot has no correlation key")
}
