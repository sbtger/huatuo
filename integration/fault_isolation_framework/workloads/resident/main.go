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

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"sync"
	"time"
)

type record struct {
	Key      int
	Value    []byte
	Labels   map[string]any
	Children []any
}

var (
	mu          sync.Mutex
	records     []*record
	churn       [64]*record
	datasetHash = sha256.New()
	counts      = map[string]uint64{"GET": 0, "SET": 0, "DELETE": 0}
)

// Distinct callsites exercise normal mbucket size/stack diversity.
//
//go:noinline
func smallA(n int) []byte { return make([]byte, n) }

//go:noinline
func smallB(n int) []byte { return make([]byte, n) }

//go:noinline
func largeA(n int) []byte { return make([]byte, n) }

//go:noinline
func largeB(n int) []byte { return make([]byte, n) }

func makeRecord(key int) *record {
	n := 1024
	if key%10 == 0 {
		n = 65536
	}
	var value []byte
	switch {
	case n == 65536 && key%20 == 0:
		value = largeA(n)
	case n == 65536:
		value = largeB(n)
	case key%2 == 0:
		value = smallA(n)
	default:
		value = smallB(n)
	}
	for i := range value {
		value[i] = byte(97 + key%26)
	}
	return &record{Key: key, Value: value, Labels: map[string]any{"kind": key % 10, "key": key}, Children: []any{[]int{key, key + 1}, map[string]int{"owner": key}}}
}

func stats() map[string]any {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	profiles, _ := runtime.MemProfile(nil, false)
	return map[string]any{"records": len(records), "churn_slots": len(churn), "operations": counts, "runtime": runtime.Version(), "profile_rate": runtime.MemProfileRate, "published_profile_records": profiles, "gc": map[string]any{"cycles": m.NumGC, "pause_total_ns": m.PauseTotalNs, "gc_cpu_fraction_lifetime": m.GCCPUFraction, "heap_alloc_bytes": m.HeapAlloc, "heap_inuse_bytes": m.HeapInuse, "heap_sys_bytes": m.HeapSys}, "small_bytes": 1024, "large_bytes": 65536, "large_every": 10, "dataset_sha256": fmt.Sprintf("%x", datasetHash.Sum(nil))}
}

func main() {
	// Keep the production default sampling rate; never rate=1 for this benchmark.
	runtime.MemProfileRate = 512 * 1024
	port := os.Getenv("HUATUO_TEST_PORT")
	if port == "" {
		port = "30000"
	}
	for i := range churn {
		churn[i] = makeRecord(i)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/fill", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		n, err := strconv.Atoi(r.URL.Query().Get("records"))
		if r.Method != http.MethodPost || err != nil || n < len(records) || n > 1000000 {
			http.Error(w, "bounded grow-only FILL required", http.StatusBadRequest)
			return
		}
		for len(records) < n {
			value := makeRecord(len(records))
			fmt.Fprintf(datasetHash, "%d:%d:%x\n", value.Key, len(value.Value), sha256.Sum256(value.Value))
			records = append(records, value)
		}
		if err := json.NewEncoder(w).Encode(stats()); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if err := json.NewEncoder(w).Encode(stats()); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	})
	mux.HandleFunc("/op", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		ordinal, e1 := strconv.ParseUint(r.URL.Query().Get("ordinal"), 10, 64)
		seed, e2 := strconv.ParseUint(r.URL.Query().Get("seed"), 10, 64)
		if e1 != nil || e2 != nil || len(records) < 1024 {
			http.Error(w, "invalid ordinal/seed or unfilled store", http.StatusBadRequest)
			return
		}
		mixed := ((ordinal+seed)*1103515245 + 12345) & 0x7fffffff
		kind := "GET"
		key := int(mixed % uint64(min(len(records), 1024)))
		value := records[key]
		if mixed%10 >= 6 {
			key = int(mixed % 64)
			kind = "SET"
			if mixed%10 >= 9 {
				kind = "DELETE"
				churn[key] = nil
			}
			churn[key] = makeRecord(key)
			value = churn[key]
		}
		counts[kind]++
		fmt.Fprintf(w, "%d|%s|%d|%x\n", ordinal, kind, key, sha256.Sum256(value.Value))
	})
	fmt.Printf("{\"pid\":%d,\"url\":\"http://127.0.0.1:%s\",\"language\":\"go\",\"profile_rate\":%d}\n", os.Getpid(), port, runtime.MemProfileRate)
	server := &http.Server{Addr: "0.0.0.0:" + port, Handler: mux, ReadHeaderTimeout: 2 * time.Second, IdleTimeout: 10 * time.Second}
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
