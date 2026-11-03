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
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"syscall"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type row struct {
	Ordinal           int      `json:"ordinal"`
	Operation         string   `json:"operation"`
	Key               int      `json:"key"`
	Scheduled         float64  `json:"scheduled"`
	Sent              *float64 `json:"sent"`
	Ended             float64  `json:"ended"`
	DispatchLag       float64  `json:"dispatch_lag"`
	OK                bool     `json:"ok"`
	Error             string   `json:"error,omitempty"`
	ErrorKind         string   `json:"error_kind,omitempty"`
	DiagnosticDelayMs int      `json:"diagnostic_delay_ms,omitempty"`
}
type metric struct {
	Count      int64            `json:"count"`
	Errors     int64            `json:"errors"`
	ErrorKinds map[string]int64 `json:"error_kinds"`
	Latency    map[int64]int64  `json:"latency_us"`
	Lag        map[int64]int64  `json:"lag_us"`
}

func mono() float64 {
	var t unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &t); err != nil {
		panic(err)
	}
	return float64(t.Sec) + float64(t.Nsec)/1e9
}

func body(key int) []byte {
	n := 1024
	if key%10 == 0 {
		n = 65536
	}
	return bytes.Repeat([]byte{byte(97 + key%26)}, n)
}

func recipe(ordinal, seed, records int) (string, int) {
	m := ((int64(ordinal)+int64(seed))*1103515245 + 12345) & 0x7fffffff
	op := "GET"
	if m%100 >= 70 {
		op = "PUT"
	}
	hot := int(math.Ceil(float64(records) * .2))
	draw := (m * 48271) % 2147483647
	if (m/100)%100 < 80 {
		return op, int(draw % int64(hot))
	}
	return op, hot + int(draw%int64(records-hot))
}

func bucket(v float64) int64 {
	n := int64(math.Max(0, v) * 1e6)
	step := int64(1)
	for n/step >= 1000 {
		step *= 10
	}
	return n/step*step + step - 1
}

func main() {
	diagnostic := flag.Bool("diagnostic", false, "DIAGNOSTIC ONLY actual20ms client delay on5%transactions")
	fillFrom := flag.Int("fill-from", 0, "grow only existing prefix count")
	endpoint := flag.String("endpoint", "", "allowed endpoint")
	mode := flag.String("mode", "load", "fill/verify/load")
	records := flag.Int("records", 1024, "retained keys")
	rate := flag.Int("rate", 100, "logical transactions/s")
	duration := flag.Float64("duration", 60, "bounded duration")
	start := flag.Float64("start", 0, "CLOCK_MONOTONIC seconds")
	workers := flag.Int("workers", 32, "bounded RPC workers")
	pending := flag.Int("pending", 256, "arrival queue")
	seed := flag.Int("seed", 923, "recipe seed")
	out := flag.String("output", "", "owned output directory")
	warmup := flag.Float64("warmup", 10, "warmup seconds")
	baseline := flag.Float64("baseline", 60, "baseline phase seconds")
	hold := flag.Float64("hold", 60, "capture phase seconds")
	traceStart := flag.Float64("trace-start", 0, "monotonic trace start")
	traceEnd := flag.Float64("trace-end", 0, "monotonic trace end")
	flag.Parse()
	if *endpoint == "" || *records < 1024 || *records > 1000000 || *workers < 1 || *workers > 128 || *pending < 1 || *pending > 2048 || *rate < 1 || *rate > 50000 || *duration <= 0 || *duration > 600 {
		panic("etcd SDK load budget invalid")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	config := clientv3.Config{Endpoints: []string{*endpoint}, DialTimeout: 5 * time.Second, MaxUnaryRetries: 1, DialOptions: []grpc.DialOption{grpc.WithDisableRetry()}}
	policy := map[string]any{"max_unary_attempts": config.MaxUnaryRetries, "configured_grpc_retry_disabled": true, "transparent_transport_retries_possible": true, "wire_attempts_measured": nil, "scope": "one logical SDK invocation, not guaranteed one wire attempt; pinned SDK loops attempt<MaxUnaryRetries"}
	if *mode == "config" {
		if e := json.NewEncoder(os.Stdout).Encode(policy); e != nil {
			panic(e)
		}
		return
	}
	client, err := clientv3.New(config)
	if err != nil {
		panic(err)
	}
	defer client.Close()
	if *mode == "status" {
		status, e := client.Status(ctx, *endpoint)
		if e != nil {
			panic(e)
		}
		count, e := client.Get(ctx, "/application/", clientv3.WithPrefix(), clientv3.WithCountOnly())
		if e != nil {
			panic(e)
		}
		json.NewEncoder(os.Stdout).Encode(map[string]any{"db_bytes": status.DbSize, "db_inuse_bytes": status.DbSizeInUse, "revision": status.Header.Revision, "records": count.Count})
		return
	}
	if *mode == "fill" || *mode == "verify" {
		if *fillFrom < 0 || *fillFrom > *records {
			panic("fill-from outside grow-only range")
		}
		digest := sha256.New()
		if *mode == "fill" {
			for first := *fillFrom; first < *records; first += 100 {
				ops := []clientv3.Op{}
				for key := first; key < *records && key < first+100; key++ {
					ops = append(ops, clientv3.OpPut(fmt.Sprintf("/application/%08d", key), string(body(key))))
				}
				rpc, c := context.WithTimeout(ctx, 5*time.Second)
				_, e := client.Txn(rpc).Then(ops...).Commit()
				c()
				if e != nil {
					panic(e)
				}
			}
		} else {
			count, e := client.Get(ctx, "/application/", clientv3.WithPrefix(), clientv3.WithCountOnly())
			if e != nil || count.Count != int64(*records) {
				panic("retained etcd key count differs")
			}
			key := 0
			for key < *records {
				rpc, c := context.WithTimeout(ctx, 5*time.Second)
				response, e := client.Get(rpc, fmt.Sprintf("/application/%08d", key), clientv3.WithRange(clientv3.GetPrefixRangeEnd("/application/")), clientv3.WithLimit(100))
				c()
				if e != nil {
					panic(e)
				}
				if len(response.Kvs) == 0 {
					panic("readback page missing")
				}
				for _, kv := range response.Kvs {
					if key >= *records || string(kv.Key) != fmt.Sprintf("/application/%08d", key) || !bytes.Equal(kv.Value, body(key)) {
						panic("actual paginated etcd payload differs")
					}
					fmt.Fprintf(digest, "%d:%d:%x\n", key, len(kv.Value), sha256.Sum256(kv.Value))
					key++
				}
			}
		}
		if *mode == "fill" {
			for key := 0; key < *records; key++ {
				wanted := body(key)
				fmt.Fprintf(digest, "%d:%d:%x\n", key, len(wanted), sha256.Sum256(wanted))
			}
		}
		fmt.Printf("{\"records\":%d,\"dataset_sha256\":\"%x\",\"sdk\":\"clientv3-3.6.5\"}\n", *records, digest.Sum(nil))
		return
	}
	if *mode != "load" || *out == "" {
		panic("mode/output invalid")
	}
	runtime.GOMAXPROCS(4)
	file, err := os.OpenFile(filepath.Join(*out, "trace-sdk.jsonl.gz"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		panic(err)
	}
	gzipWriter, err := gzip.NewWriterLevel(file, gzip.BestSpeed)
	if err != nil {
		panic(err)
	}
	encoder := json.NewEncoder(gzipWriter)
	jobs := make(chan row, *pending)
	results := make(chan row, *pending+*workers)
	var group sync.WaitGroup
	for i := 0; i < *workers; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for r := range jobs {
				sent := mono()
				r.Sent = &sent
				r.DispatchLag = sent - r.Scheduled
				if *diagnostic && (r.Ordinal+1)%20 == 0 {
					r.DiagnosticDelayMs = 20
					time.Sleep(20 * time.Millisecond)
				}
				name := fmt.Sprintf("/application/%08d", r.Key)
				wanted := body(r.Key)
				rpc, c := context.WithTimeout(ctx, 2*time.Second)
				var e error
				if r.Operation == "PUT" {
					var response *clientv3.PutResponse
					response, e = client.Put(rpc, name, string(wanted))
					if e == nil && response.Header.Revision <= 0 {
						e = fmt.Errorf("PUT acknowledgement revision missing")
						r.ErrorKind = "protocol_errors"
					}
				}
				if r.Operation == "GET" {
					response, readErr := client.Get(rpc, name)
					e = readErr
					if e == nil && (len(response.Kvs) != 1 || !bytes.Equal(response.Kvs[0].Value, wanted)) {
						e = fmt.Errorf("full payload readback mismatch")
						r.ErrorKind = "body_errors"
					}
				}
				c()
				r.Ended = mono()
				r.OK = e == nil
				if e != nil {
					if r.ErrorKind == "" {
						switch {
						case errors.Is(e, context.DeadlineExceeded) || status.Code(e) == codes.DeadlineExceeded:
							r.ErrorKind = "timeouts"
						case errors.Is(e, context.Canceled) || status.Code(e) == codes.Canceled:
							r.ErrorKind = "cancelled"
						default:
							r.ErrorKind = "rpc_errors"
						}
					}
					r.Error = e.Error()
					if len(r.Error) > 300 {
						r.Error = r.Error[:300]
					}
				}
				results <- r
			}
		}()
	}
	done := make(chan struct{})
	summary := map[string]*metric{}
	counters := map[string]int64{"requests": 0, "timeouts": 0, "body_errors": 0, "queue_full": 0, "rpc_errors": 0, "protocol_errors": 0, "cancelled": 0}
	var rawBytes int64
	overflow := false
	go func() {
		defer close(done)
		for r := range results {
			counters["requests"]++
			if !r.OK {
				counters[r.ErrorKind]++
			}
			elapsed := r.Scheduled - *start
			phase := 0
			if elapsed >= *warmup {
				phase = 1
			}
			if elapsed >= *warmup+*baseline {
				phase = 2
			}
			if elapsed >= *warmup+*baseline+*hold {
				phase = 3
			}
			keys := []string{strconv.Itoa(phase) + ":" + r.Operation, "window:" + strconv.Itoa(int(math.Max(0, elapsed)/5))}
			for _, key := range keys {
				m := summary[key]
				if m == nil {
					m = &metric{ErrorKinds: map[string]int64{}, Latency: map[int64]int64{}, Lag: map[int64]int64{}}
					summary[key] = m
				}
				m.Count++
				if !r.OK {
					m.Errors++
					m.ErrorKinds[r.ErrorKind]++
				}
				m.Latency[bucket(r.Ended-r.Scheduled)]++
				m.Lag[bucket(r.DispatchLag)]++
			}
			if !r.OK || (r.Scheduled >= *traceStart && r.Scheduled <= *traceEnd) {
				if rawBytes > 256<<20 {
					overflow = true
					continue
				}
				data, e := json.Marshal(r)
				if e != nil {
					panic(e)
				}
				rawBytes += int64(len(data) + 1)
				if e = encoder.Encode(r); e != nil {
					panic(e)
				}
			}
		}
	}()
	maintenance := []map[string]any{}
	maintenanceStop := make(chan struct{})
	maintenanceDone := make(chan struct{})
	go func() {
		defer close(maintenanceDone)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var compacted int64
		for {
			select {
			case <-maintenanceStop:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				begin := mono()
				entry := map[string]any{"begin": begin, "cpu_seconds": nil, "cpu_scope": "included in whole SDK tool CPU; per-maintenance CPU not measured"}
				rpc, c := context.WithTimeout(ctx, 2*time.Second)
				status, e := client.Status(rpc, *endpoint)
				c()
				if e == nil {
					entry["db_bytes"] = status.DbSize
					entry["db_inuse_bytes"] = status.DbSizeInUse
					entry["revision"] = status.Header.Revision
					revision := status.Header.Revision - 1000
					if revision > compacted {
						rpc, c = context.WithTimeout(ctx, 2*time.Second)
						_, e = client.Compact(rpc, revision)
						c()
						if e == nil {
							compacted = revision
						}
						entry["compacted_revision"] = revision
					}
				}
				if e != nil {
					entry["error"] = e.Error()
				}
				entry["end"] = mono()
				maintenance = append(maintenance, entry)
			}
		}
	}()
	total := int(math.Ceil(*duration * float64(*rate)))
	cancelled := false
	for ordinal := 0; ordinal < total; ordinal++ {
		due := *start + float64(ordinal)/float64(*rate)
		delay := time.Duration(math.Max(0, due-mono()) * 1e9)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			cancelled = true
		case <-timer.C:
		}
		if cancelled {
			break
		}
		op, key := recipe(ordinal+1, *seed, *records)
		r := row{Ordinal: ordinal, Operation: op, Key: key, Scheduled: due}
		select {
		case jobs <- r:
		default:
			r.Ended = mono()
			r.Error = "bounded arrival queue full"
			r.ErrorKind = "queue_full"
			results <- r
		}
	}
	close(jobs)
	group.Wait()
	close(results)
	<-done
	close(maintenanceStop)
	<-maintenanceDone
	if err = gzipWriter.Close(); err != nil {
		panic(err)
	}
	if err = file.Close(); err != nil {
		panic(err)
	}
	result := map[string]any{"sdk": "official clientv3-3.6.5", "maintenance": maintenance, "recipe": "70%native GET full value /30%native PUT acknowledgement revision; paginated full readback outside timed windows", "client_policy": policy, "rpc_scope": "one SDK invocation per logical GET/PUT; transparent transport retries possible, wire attempts unmeasured", "driver": "custom bounded fixed-arrival native gRPC", "diagnostic_client_delay": *diagnostic, "scheduled": total, "cancelled": cancelled, "trace_overflow": overflow, "metrics": summary, "counters": counters, "counter_scope": "real deadline/body/queue/RPC classes, one terminal outcome per intended arrival; HTTP socket taxonomy unsupported", "trace_scope": "all errors and complete records only in configured capture window; no synthesized rows", "histogram": "all transactions, upper-bound decimal3-significant-digit microsecond bins"}
	resultFile, err := os.Create(filepath.Join(*out, "sdk-result.json"))
	if err != nil {
		panic(err)
	}
	if err = json.NewEncoder(resultFile).Encode(result); err != nil {
		panic(err)
	}
	if err = resultFile.Close(); err != nil {
		panic(err)
	}
}
