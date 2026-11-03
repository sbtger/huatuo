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

// Test-only persistent driver of the unchanged production collector/worker path.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ccfos/huatuo/internal/memsnapshot"
	"github.com/ccfos/huatuo/internal/memsnapshot/collector"
)

type command struct {
	ID         int    `json:"id"`
	PID        int    `json:"pid"`
	StartTicks uint64 `json:"start_ticks"`
}

func main() {
	control := flag.String("control", "", "owned JSON command file")
	worker := flag.String("worker", "", "production worker executable")
	cgroup := flag.String("cgroup-root", "", "dedicated worker cgroup")
	timeout := flag.Duration("timeout", 3*time.Second, "production snapshot timeout")
	outputDir := flag.String("output-dir", "", "owned bounded snapshot result directory")
	topK := flag.Int("top-k", 7, "production histogram limit")
	flag.Parse()
	if *control == "" || *worker == "" || *cgroup == "" {
		panic("control, worker and cgroup-root required")
	}
	manager, err := collector.NewWorkerManager(collector.WorkerConfig{Executable: *worker, CgroupRoot: *cgroup})
	if err != nil {
		panic(err)
	}
	restore := collector.UseWorker(manager, nil)
	defer restore()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := manager.Close(ctx); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(map[string]any{"ready": true, "pid": os.Getpid(), "route": "production collector.Snapshot with WorkerManager"}); err != nil {
		panic(err)
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	seen := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			data, err := os.ReadFile(*control)
			if err != nil {
				panic(err)
			}
			var c command
			if err = json.Unmarshal(data, &c); err != nil {
				panic(err)
			}
			if c.ID <= seen {
				continue
			}
			seen = c.ID
			identity := memsnapshot.ProcessInstanceID{TGID: c.PID, StartTimeTicks: c.StartTicks}
			started := time.Now()
			if err = memsnapshot.ValidateProcessInstanceID(identity); err != nil {
				panic(err)
			}
			result, captureErr := collector.Snapshot(ctx, identity, collector.Options{MaxMemoryObjectEntries: *topK, SnapshotTimeout: *timeout})
			outputBytes, serializationError := json.Marshal(result)
			if serializationError == nil && *outputDir != "" {
				path := filepath.Join(*outputDir, fmt.Sprintf("capture-%04d.json", c.ID))
				var output *os.File
				output, serializationError = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
				if serializationError == nil {
					_, serializationError = output.Write(outputBytes)
					if serializationError == nil {
						serializationError = output.Sync()
					}
					closeErr := output.Close()
					if serializationError == nil {
						serializationError = closeErr
					}
				}
			}
			detail := map[string]any{"id": c.ID, "pid": c.PID, "start_ticks": c.StartTicks, "started": started.UTC(), "ended": time.Now().UTC(), "wall_ms": float64(time.Since(started).Microseconds()) / 1000, "result": result, "output_bytes": len(outputBytes), "output_scope": "bounded result JSON serialization plus test-owned disk write and fsync"}
			if serializationError != nil {
				detail["output_error"] = serializationError.Error()
			}
			if captureErr != nil {
				detail["error"] = captureErr.Error()
			}
			if err = encoder.Encode(detail); err != nil {
				panic(err)
			}
		}
	}
}
