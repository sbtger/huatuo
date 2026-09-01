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

// test_before_oom_heap serves as a tiny kubelet HTTPS stub, a controllable Go
// heap workload, or an event validator. Keeping these roles in one binary
// avoids extra integration-test dependencies.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"
)

var liveHeap [][]byte

func main() {
	if len(os.Args) < 2 {
		log.Fatal("usage: test_before_oom_heap <kubelet|workload>")
	}
	switch os.Args[1] {
	case "kubelet":
		serveKubelet(os.Args[2:])
	case "runtime":
		serveRuntime(os.Args[2:])
	case "workload":
		runWorkload()
	case "validate":
		validateEvent(os.Args[2:])
	default:
		log.Fatalf("unknown mode %q", os.Args[1])
	}
}

func serveRuntime(args []string) {
	flags := flag.NewFlagSet("runtime", flag.ExitOnError)
	socket := flags.String("socket", "", "Docker-compatible Unix socket")
	root := flags.String("root", "", "fake Docker root directory")
	_ = flags.Parse(args)
	if *socket == "" || *root == "" {
		log.Fatal("runtime mode requires --socket and --root")
	}

	listener, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || !strings.HasSuffix(request.URL.Path, "/info") {
			http.NotFound(writer, request)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(map[string]string{"DockerRootDir": *root})
	})
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 2 * time.Second}
	log.Fatal(server.Serve(listener))
}

func serveKubelet(args []string) {
	flags := flag.NewFlagSet("kubelet", flag.ExitOnError)
	listen := flags.String("listen", "", "HTTPS listen address")
	certPath := flags.String("cert", "", "path for generated client certificate")
	keyPath := flags.String("key", "", "path for generated client key")
	pods := flags.String("pods", "", "PodList JSON file")
	_ = flags.Parse(args)
	if *listen == "" || *certPath == "" || *keyPath == "" || *pods == "" {
		log.Fatal("kubelet mode requires --listen, --cert, --key, and --pods")
	}
	certificate, certificatePEM, keyPEM := newSelfSignedCertificate()
	if err := os.WriteFile(*certPath, certificatePEM, 0o600); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*keyPath, keyPEM, 0o600); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/pods", func(writer http.ResponseWriter, _ *http.Request) {
		data, err := os.ReadFile(*pods)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusInternalServerError)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write(data)
	})
	mux.HandleFunc("/configz", func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"kubeletconfig":{"cgroupDriver":"systemd","containerRuntimeEndpoint":"unix:///var/run/docker.sock"}}`))
	})
	server := &http.Server{
		Addr:              *listen,
		Handler:           mux,
		ReadHeaderTimeout: 2 * time.Second,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		},
	}
	listener, err := tls.Listen("tcp", *listen, server.TLSConfig)
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(server.Serve(listener))
}

func newSelfSignedCertificate() (tls.Certificate, []byte, []byte) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		log.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		log.Fatal(err)
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certificatePEM, keyPEM)
	if err != nil {
		log.Fatal(err)
	}
	return certificate, certificatePEM, keyPEM
}

type eventDocument struct {
	ContainerID            string `json:"container_id"`
	ContainerHostname      string `json:"container_hostname"`
	ContainerHostNamespace string `json:"container_host_namespace"`
	ContainerType          string `json:"container_type"`
	ContainerQoS           string `json:"container_qos"`
	TracerName             string `json:"tracer_name"`
	TracerData             struct {
		CgroupPath         string  `json:"cgroup_path"`
		MemoryMax          int64   `json:"memory_max"`
		MemoryUsagePercent float64 `json:"memory_usage_percent"`
		VictimPID          int     `json:"victim_pid"`
		VictimOOMScoreAdj  int     `json:"victim_oom_score_adj"`
		Language           string  `json:"language"`
		Snapshot           struct {
			Status  string `json:"status"`
			Entries []struct {
				Kind string `json:"kind"`
			} `json:"entries"`
		} `json:"snapshot"`
	} `json:"tracer_data"`
}

func validateEvent(args []string) {
	flags := flag.NewFlagSet("validate", flag.ExitOnError)
	events := flags.String("events", "", "newline-delimited event file")
	containerID := flags.String("container-id", "", "expected container ID")
	cgroupPath := flags.String("cgroup", "", "expected cgroup path")
	memoryMax := flags.Int64("memory-max", 0, "expected memory limit")
	victimPID := flags.Int("pid", 0, "expected victim PID")
	threshold := flags.Float64("threshold", 0, "minimum memory usage percentage")
	_ = flags.Parse(args)

	file, err := os.Open(*events)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	documents := make([]eventDocument, 0, 1)
	for {
		var document eventDocument
		if err := decoder.Decode(&document); err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("decode event: %v", err)
		}
		documents = append(documents, document)
	}
	if len(documents) != 1 {
		log.Fatalf("event count = %d, want 1", len(documents))
	}
	document := documents[0]
	entries := document.TracerData.Snapshot.Entries
	validStatus := document.TracerData.Snapshot.Status == "complete" ||
		document.TracerData.Snapshot.Status == "partial"
	validEntries := len(entries) >= 1 && len(entries) <= 3
	for _, entry := range entries {
		validEntries = validEntries && entry.Kind == "allocation_site"
	}
	if document.ContainerID != *containerID ||
		document.ContainerHostname != "before-oom-e2e" ||
		document.ContainerHostNamespace != "before-oom-e2e" ||
		document.ContainerType != "normal" ||
		document.ContainerQoS != "guaranteed" ||
		document.TracerName != "before_oom_memory_snapshot" ||
		document.TracerData.CgroupPath != *cgroupPath ||
		document.TracerData.MemoryMax != *memoryMax ||
		document.TracerData.MemoryUsagePercent < *threshold ||
		document.TracerData.VictimPID != *victimPID ||
		document.TracerData.VictimOOMScoreAdj != 900 ||
		document.TracerData.Language != "go" || !validStatus || !validEntries {
		log.Fatal("persisted before-OOM snapshot failed content validation")
	}
}

func runWorkload() {
	// A denser sampling rate makes a small heap sufficient for stable TopK
	// validation while preserving the real external Go heap reader path.
	runtime.MemProfileRate = 64 << 10
	fmt.Println("ready")

	totalMiB := 0
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		command := scanner.Text()
		if command == "reset" {
			liveHeap = nil
			totalMiB = 0
			runtime.GC()
			debug.FreeOSMemory()
			fmt.Println("allocated_mib=0")
			continue
		}
		incrementMiB, err := strconv.Atoi(command)
		if err != nil || incrementMiB <= 0 || incrementMiB > 64 {
			log.Fatalf("invalid allocation increment %q", command)
		}
		for index := 0; index < incrementMiB; index++ {
			switch (totalMiB + index) % 3 {
			case 0:
				liveHeap = append(liveHeap, allocatePrimary())
			case 1:
				liveHeap = append(liveHeap, allocateSecondary())
			default:
				liveHeap = append(liveHeap, allocateTertiary())
			}
		}
		totalMiB += incrementMiB
		runtime.GC()
		fmt.Printf("allocated_mib=%d\n", totalMiB)
	}
	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}
	runtime.KeepAlive(liveHeap)
}

//go:noinline
func allocatePrimary() []byte {
	return touchedMiB(1)
}

//go:noinline
func allocateSecondary() []byte {
	return touchedMiB(2)
}

//go:noinline
func allocateTertiary() []byte {
	return touchedMiB(3)
}

//go:noinline
func touchedMiB(marker byte) []byte {
	block := make([]byte, 1<<20)
	for offset := 0; offset < len(block); offset += os.Getpagesize() {
		block[offset] = marker
	}
	return block
}
