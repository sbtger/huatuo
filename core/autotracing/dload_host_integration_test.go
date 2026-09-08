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
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"huatuo-bamai/internal/bpf"
	cgroupV2 "huatuo-bamai/internal/cgroups/v2"
	"huatuo-bamai/internal/storage"
	"huatuo-bamai/internal/storage/driver"
	_ "huatuo-bamai/internal/storage/sqlite"
	"huatuo-bamai/pkg/tracing"
)

func initDloadLiveBPF(t *testing.T) {
	t.Helper()
	dir := os.Getenv("HUATUO_TRIGGER_BPF_DIR")
	if dir == "" {
		t.Skip("set HUATUO_TRIGGER_BPF_DIR on a test VM")
	}
	if err := bpf.Init(nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(bpf.Shutdown)
	previous := bpf.DefaultObjDir
	bpf.DefaultObjDir = dir
	t.Cleanup(func() { bpf.DefaultObjDir = previous })
	t.Cleanup(func() {
		if err := cgroupV2.CloseLoadStats(); err != nil {
			t.Error(err)
		}
	})
}

func dloadLiveStore(t *testing.T) *storage.Store[*tracing.Document] {
	t.Helper()
	store, err := storage.NewFromConfig(context.Background(), &driver.Config{
		Driver: "sqlite", SQLiteDSN: filepath.Join(t.TempDir(), "traces.db"),
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

func TestDloadHostLiveCapture(t *testing.T) {
	initDloadLiveBPF(t)
	store := dloadLiveStore(t)
	cfg := &Config{}
	cfg.Dload.Interval = 10
	cfg.Dload.IntervalTracing = 30
	cfg.Dload.EnableHost = true
	cfg.Dload.EnableDebug = true
	d, err := newDloadTracing(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.v2LoadStats(nil); err != nil {
		t.Fatal(err)
	}
	if d.hostStats == nil || d.hostStats.NrSleeping == 0 {
		t.Fatal("missing whole-host snapshot")
	}
	stack, err := dumpUninterruptibleTaskStack(taskScopeHost, "", true)
	if err != nil || stack == "" {
		t.Fatal("missing host debug stacks", err)
	}
	now := time.Now()
	d.traceHost(now, &dloadStackCapture{dump: dumpUninterruptibleTaskStack})
	if !d.host.lastTraceAt.Equal(now) {
		t.Fatal("host did not complete independent trace")
	}
	documents, err := store.Query(context.Background(), driver.Query{})
	if err != nil || len(documents) != 1 {
		t.Fatalf("persisted debug traces: %d, error: %v", len(documents), err)
	}
}

// The caller supplies a bounded D-state worker in a disposable VM. Debug mode
// must stay off: this exercises the normal sampling, threshold and save path.
func TestDloadHostLiveTrigger(t *testing.T) {
	pid, err := strconv.Atoi(os.Getenv("HUATUO_DLOAD_WORKER_PID"))
	if err != nil || pid <= 1 {
		t.Skip("set HUATUO_DLOAD_WORKER_PID to a bounded D-state test worker")
	}
	initDloadLiveBPF(t)
	store := dloadLiveStore(t)
	cfg := &Config{}
	cfg.Dload.EnableHost = true
	cfg.Dload.Interval = 1
	cfg.Dload.IntervalTracing = 30
	d, err := newDloadTracing(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	done := make(chan error, 1)
	go func() { done <- d.Start(ctx) }()
	defer func() {
		cancel()
		<-done
	}()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			t.Fatal("no persisted host trace before timeout")
		case <-ticker.C:
			documents, err := store.Query(ctx, driver.Query{})
			if err != nil {
				t.Fatal(err)
			}
			if len(documents) == 0 {
				continue
			}
			if len(documents) != 1 {
				t.Fatalf("expected one trace, got %d", len(documents))
			}
			doc := documents[0]
			data := doc.TracerData.(map[string]any)
			if doc.TracerName != "dload" || doc.ContainerID != "" ||
				doc.TracerRunType != tracing.TracerRunTypeAutotracing ||
				data["nr_uninterruptible"].(float64) < 1 ||
				data["dload_avg"].(float64) <= 0 ||
				!strings.Contains(data["stack"].(string), fmt.Sprintf("Pid: %d\n", pid)) {
				t.Fatalf("unexpected persisted trace: %+v", doc)
			}
			t.Logf("persisted normal host trigger: D=%v, dload=%v, worker=%d",
				data["nr_uninterruptible"], data["dload_avg"], pid)
			return
		}
	}
}
