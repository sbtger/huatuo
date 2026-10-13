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
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	// Keep heap profiling linked. The server uses service, not DefaultServeMux.
	_ "net/http/pprof" //nolint:gosec // The test server does not expose registered pprof handlers.
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const expectedBody = "feb1e4409d009e0ec502eaabe321f86b5197a881e9b765252ec8a75d6957596d\n"

var retained [][]byte

type service struct {
	phase      atomic.Value
	completed  atomic.Uint64
	ticks      atomic.Uint64
	mu         sync.Mutex
	seq, total uint64
}

func newService() *service { s := &service{}; s.phase.Store("warmup"); return s }
func (s *service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/state", "/txn":
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.URL.Path == "/txn" {
			n, err := strconv.ParseUint(r.URL.Query().Get("seq"), 10, 64)
			if r.Method != http.MethodPost || err != nil || n != s.seq+1 {
				http.Error(w, "sequence conflict", http.StatusConflict)
				return
			}
			s.seq = n
			s.total += n * 13
		}
		writeJSON(w, map[string]any{"seq": s.seq, "total": s.total, "ticks": s.ticks.Load(), "completed": s.completed.Load()})
	case "/work":
		w.Header().Set("X-Test-Phase", s.phase.Load().(string))
		// Vary allocation sizes so a realistic profile contains multiple read batches.
		data := make([]byte, (128<<10)+int(s.completed.Load()%64)*8192)
		payload := data[:128<<10]
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		for i := len(payload); i < len(data); i += 4096 {
			data[i] = 1
		}
		var digest [32]byte
		for i := 0; i < 4; i++ {
			digest = sha256.Sum256(payload)
		}
		fmt.Fprintf(w, "%x\n", digest)
		s.completed.Add(1)
	case "/phase":
		if r.Method != http.MethodPost {
			http.Error(w, "POST required", http.StatusMethodNotAllowed)
			return
		}
		b, err := io.ReadAll(io.LimitReader(r.Body, 129))
		if err != nil || len(b) == 0 || len(b) > 128 {
			http.Error(w, "invalid phase", http.StatusBadRequest)
			return
		}
		s.phase.Store(string(b))
		w.WriteHeader(http.StatusNoContent)
	case "/stats":
		writeJSON(w, map[string]any{"completed": s.completed.Load(), "phase": s.phase.Load(), "profile_rate": runtime.MemProfileRate})
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, value any) {
	if err := json.NewEncoder(w).Encode(value); err != nil {
		fmt.Fprintln(os.Stderr, "write business response:", err)
	}
}

func main() {
	heap := 32
	if len(os.Args) > 1 {
		v, err := strconv.Atoi(os.Args[1])
		if err != nil || v < 1 || v > 256 {
			fmt.Fprintln(os.Stderr, "heap MiB must be 1..256")
			os.Exit(2)
		}
		heap = v
	}
	// Preserve normal runtime sampling and GC; this target is a business load.
	for i := 0; i < heap*2; i++ {
		data := make([]byte, 512<<10)
		for p := 0; p < len(data); p += 4096 {
			data[p] = byte(i + 1)
		}
		retained = append(retained, data)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	s := newService()
	go func() {
		var chunks [][]byte
		for {
			b, err := os.ReadFile("/control/target_mb")
			target := 0
			if err == nil {
				target, _ = strconv.Atoi(string(b))
			}
			for len(chunks) < target {
				chunk, err := syscall.Mmap(-1, 0, 1<<20, syscall.PROT_READ|syscall.PROT_WRITE, syscall.MAP_PRIVATE|syscall.MAP_ANON)
				if err != nil {
					panic(err)
				}
				for p := 0; p < len(chunk); p += 4096 {
					chunk[p] = 1
				}
				chunks = append(chunks, chunk)
			}
			for len(chunks) > target {
				if err := syscall.Munmap(chunks[len(chunks)-1]); err != nil {
					panic(err)
				}
				chunks = chunks[:len(chunks)-1]
			}
			s.ticks.Add(1)
			time.Sleep(100 * time.Millisecond)
		}
	}()
	server := &http.Server{Handler: s, ReadHeaderTimeout: time.Second, IdleTimeout: 30 * time.Second}
	if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"url": "http://" + listener.Addr().String(), "pid": os.Getpid(), "expected_body": expectedBody, "runtime": runtime.Version(), "profile_rate": runtime.MemProfileRate, "heap_mib": heap}); err != nil {
		fmt.Fprintln(os.Stderr, "write business readiness:", err)
		os.Exit(1)
	}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	<-ctx.Done()
	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(closeCtx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	runtime.KeepAlive(retained)
}
