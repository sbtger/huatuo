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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ccfos/huatuo/internal/memsnapshot"
)

func processInstanceIDForTest(t *testing.T) memsnapshot.ProcessInstanceID {
	t.Helper()
	process, err := memsnapshot.ReadProcessInstanceID(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	return process
}

func TestSnapshotRejectsInvalidOptions(t *testing.T) {
	process := processInstanceIDForTest(t)
	for _, options := range []Options{
		{MaxMemoryObjectEntries: -1},
		{MaxMemoryObjectEntries: memsnapshot.MaxMemoryObjectEntries + 1},
		{SnapshotTimeout: -time.Second},
	} {
		result, err := Snapshot(t.Context(), process, options)
		if err == nil || result != nil {
			t.Fatalf("invalid options %+v accepted: result=%+v err=%v", options, result, err)
		}
	}
}

// A valid prefix must not hide oversized, unknown or trailing protocol data.
func TestWorkerProtocolRejectsInvalidReplies(t *testing.T) {
	for _, input := range []string{
		`{`, `{"version":1,"extra":true}`, `{"version":1} {}`,
		strings.Repeat(" ", (1<<20)+1),
	} {
		var response workerResponse
		if err := decodeWorkerMessage(strings.NewReader(input), 1<<20, &response); err == nil {
			t.Fatalf("invalid worker reply accepted: %.80q", input)
		}
	}
}

func TestWorkerRejectsOrdinaryFilesystemContainment(t *testing.T) {
	_, err := NewWorkerManager(WorkerConfig{Executable: "/bin/sh", CgroupRoot: filepath.Join(t.TempDir(), "huatuo-memsnapshot-worker-test")})
	if err == nil {
		t.Fatal("ordinary filesystem accepted as hard memory containment")
	}
}
