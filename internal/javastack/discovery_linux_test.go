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

package javastack

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestProcDiscovererFindsJavaArgv0(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "42")
	if err := os.Mkdir(proc, 0o700); err != nil {
		t.Fatal(err)
	}
	fields := "S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 4242 20"
	if err := os.WriteFile(filepath.Join(proc, "stat"), []byte("42 (Java worker) "+fields), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "cmdline"), []byte("/opt/jdk/bin/java\x00-Xmx1g"), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := NewProcDiscoverer(root).Discover(context.Background())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(targets) != 1 || targets[0].PID != 42 || targets[0].StartTimeTicks != 4242 {
		t.Fatalf("targets = %+v", targets)
	}
}

func TestProcDiscovererRejectsNonJava(t *testing.T) {
	root := t.TempDir()
	proc := filepath.Join(root, "7")
	if err := os.Mkdir(proc, 0o700); err != nil {
		t.Fatal(err)
	}
	fields := "S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 77 20"
	if err := os.WriteFile(filepath.Join(proc, "stat"), []byte("7 (worker) "+fields), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proc, "cmdline"), []byte("python\x00app.py"), 0o600); err != nil {
		t.Fatal(err)
	}
	targets, err := NewProcDiscoverer(root).Discover(context.Background())
	if err != nil || len(targets) != 0 {
		t.Fatalf("targets=%+v err=%v", targets, err)
	}
}
