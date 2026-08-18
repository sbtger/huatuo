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

package golang

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"huatuo-bamai/internal/memsnap"
)

func TestExternalReaderCapturesCurrentGoProcessOnDemand(t *testing.T) {
	payloads := make([][]byte, 8)
	for index := range payloads {
		payloads[index] = make([]byte, 2<<20)
		payloads[index][0] = byte(index)
	}
	runtime.GC()
	identity, err := (memsnap.ProcIdentityReader{}).Read(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	snapshot, err := NewExternalReader("/proc").Capture(ctx, identity, 0, 4096, 64)
	runtime.KeepAlive(payloads)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.RuntimeVersion == "" || snapshot.VisitedBuckets == 0 ||
		len(snapshot.Allocations) == 0 {
		t.Fatalf("incomplete external snapshot: %+v", snapshot)
	}
}

// TestExternalReaderAgainstVersionedFixture exercises the real cross-process
// reader against a fixture compiled by the Go toolchain selected by the VM
// matrix runner. Keeping the reader test in this package makes the matrix use
// exactly the production discovery, layout and process_vm_readv paths.
func TestExternalReaderAgainstVersionedFixture(t *testing.T) {
	fixture := os.Getenv("HUATUO_TEST_GO_FIXTURE")
	if fixture == "" {
		t.Skip("HUATUO_TEST_GO_FIXTURE is unset")
	}
	command := exec.Command(fixture)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	if scanner := bufio.NewScanner(stdout); !scanner.Scan() ||
		!strings.HasPrefix(scanner.Text(), "READY ") {
		t.Fatal("Go fixture did not become ready")
	}
	identity, err := (memsnap.ProcIdentityReader{}).Read(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	started := time.Now()
	snapshot, err := NewExternalReader("/proc").Capture(ctx, identity, 0, 4096, 64)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("runtime=%s elapsed=%s complete=%t visited=%d allocations=%d reason=%q",
		snapshot.RuntimeVersion, elapsed, snapshot.Complete,
		snapshot.VisitedBuckets, len(snapshot.Allocations), snapshot.PartialReason)
	if elapsed > 750*time.Millisecond {
		t.Fatalf("Go capture exceeded bounded return budget: %s", elapsed)
	}
	if !strings.HasPrefix(snapshot.RuntimeVersion, "go1.") ||
		snapshot.VisitedBuckets == 0 || len(snapshot.Allocations) == 0 {
		t.Fatalf("incomplete versioned Go snapshot: %+v", snapshot)
	}
	for _, function := range []string{"main.allocateSmall", "main.allocateLarge"} {
		if !rawSnapshotContainsFunction(snapshot, function) {
			t.Fatalf("Go snapshot does not contain %s: %+v", function,
				snapshot.Allocations)
		}
	}
}

func rawSnapshotContainsFunction(snapshot *RawSnapshot, function string) bool {
	for _, allocation := range snapshot.Allocations {
		for _, frame := range allocation.Stack {
			if strings.Contains(frame, function) {
				return true
			}
		}
	}
	return false
}

func TestCapturePhaseDeadlinesReserveFinalizationTime(t *testing.T) {
	hardDeadline := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), hardDeadline)
	defer cancel()
	scanDeadline, ok := memsnap.OOMSnapshotDeadlineWithReserve(
		ctx, scanFinishReserve)
	if !ok || hardDeadline.Sub(scanDeadline) != scanFinishReserve {
		t.Fatalf("scan deadline=%v ok=%t", scanDeadline, ok)
	}
	stackDeadline, ok := memsnap.OOMSnapshotDeadlineWithReserve(
		ctx, resultBuildReserve)
	if !ok || hardDeadline.Sub(stackDeadline) != resultBuildReserve {
		t.Fatalf("stack deadline=%v ok=%t", stackDeadline, ok)
	}
}
