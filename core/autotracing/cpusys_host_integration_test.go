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

//go:build integration && linux

package autotracing

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	internalconfig "huatuo-bamai/internal/config"
	"huatuo-bamai/internal/storage"
	"huatuo-bamai/internal/storage/driver"
	_ "huatuo-bamai/internal/storage/sqlite"
	"huatuo-bamai/pkg/tracing"
)

func cpuHostTestStore(t *testing.T) *storage.Store[*tracing.Document] {
	t.Helper()
	store, err := storage.NewFromConfig(context.Background(), &driver.Config{
		Driver: "sqlite", SQLiteDSN: filepath.Join(t.TempDir(), "cpu.db"),
	}, tracing.DocumentCollection, tracing.DocumentStoreMapper{})
	if err != nil {
		t.Fatal(err)
	}
	tracing.SetTracingStore([]*storage.Store[*tracing.Document]{store}, tracing.DocumentOptions{})
	t.Cleanup(func() {
		tracing.SetTracingStore(nil, tracing.DocumentOptions{})
		if err := store.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	return store
}

func TestCPUHostPersistence(t *testing.T) {
	store := cpuHostTestStore(t)
	c := cpuSysTracing{
		enableUser: true, enableTotal: true,
		userThreshold:  cpuSysThreshold{usage: 75, delta: 45},
		totalThreshold: cpuSysThreshold{usage: 90, delta: 55},
		threshold:      cpuSysThreshold{usage: 45, delta: 20},
	}
	state := cpuSysState{userPercent: 80, userPercentDelta: 60, totalPercent: 95, totalPercentDelta: 65}
	if err := c.saveCPUSysTrace(time.Now(), &state, []byte("[]")); err != nil {
		t.Fatal(err)
	}
	docs, err := store.Query(context.Background(), driver.Query{})
	if err != nil || len(docs) != 1 {
		t.Fatalf("documents=%d error=%v", len(docs), err)
	}
	data := docs[0].TracerData.(map[string]any)
	if docs[0].ContainerID != "" || docs[0].TracerName != "cpusys" ||
		data["user_percent"] != float64(80) || data["total_percent"] != float64(95) ||
		len(data["trigger_reasons"].([]any)) != 2 {
		t.Fatalf("unexpected CPU document: %+v", docs[0])
	}
}

func TestCPUHostLiveTrigger(t *testing.T) {
	dir := os.Getenv("HUATUO_CPU_LIVE_DIR")
	if dir == "" {
		t.Skip("set HUATUO_CPU_LIVE_DIR to a test VM directory with perf and perf.o")
	}
	previousBin, previousBPF := tracing.TaskBinDir, internalconfig.CoreBpfDir
	tracing.TaskBinDir, internalconfig.CoreBpfDir = dir, dir
	defer func() { tracing.TaskBinDir, internalconfig.CoreBpfDir = previousBin, previousBPF }()
	store := cpuHostTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	worker := exec.CommandContext(ctx, "/bin/sh", "-c", "sleep 3; while :; do :; done")
	if err := worker.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); _ = worker.Wait() }()
	c := cpuSysTracing{
		interval: time.Second, minTraceInterval: time.Minute, perfDuration: time.Second,
		enableUser: true, enableTotal: true,
		userThreshold:  cpuSysThreshold{usage: 1, delta: 1},
		totalThreshold: cpuSysThreshold{usage: 1, delta: 1},
		threshold:      cpuSysThreshold{usage: 100, delta: 100},
	}
	done := make(chan struct{})
	var runErr error
	go func() { runErr = c.Start(ctx); close(done) }()
	defer func() { cancel(); <-done }()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			t.Fatalf("CPU tracer stopped before persistence: %v", runErr)
		case <-ctx.Done():
			t.Fatal("no persisted CPU trigger before timeout")
		case <-ticker.C:
			docs, err := store.Query(ctx, driver.Query{})
			if err != nil {
				t.Fatal(err)
			}
			if len(docs) == 0 {
				continue
			}
			if len(docs) != 1 {
				t.Fatalf("duplicate CPU captures: %d", len(docs))
			}
			doc := docs[0]
			data := doc.TracerData.(map[string]any)
			reasons := data["trigger_reasons"].([]any)
			if doc.TracerName != "cpusys" || doc.ContainerID != "" ||
				!slices.Contains(reasons, any("user")) || !slices.Contains(reasons, any("total")) ||
				len(data["flamedata"].([]any)) == 0 {
				t.Fatalf("unexpected live CPU trace: %+v", doc)
			}
			t.Logf("real /proc/stat -> user+total trigger -> perf -> SQLite: user=%v total=%v flame roots=%d",
				data["user_percent"], data["total_percent"], len(data["flamedata"].([]any)))
			return
		}
	}
}
