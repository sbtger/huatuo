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

package memsnap

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestParseStartTime(t *testing.T) {
	stat := []byte("42 (worker (oom)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 999 20")
	got, err := ParseProcStatStartTime(stat)
	if err != nil {
		t.Fatal(err)
	}
	if got != 999 {
		t.Fatalf("starttime=%d, want 999", got)
	}
}

func TestMalformedStartTime(t *testing.T) {
	if _, err := ParseProcStatStartTime([]byte("42 worker S")); err == nil {
		t.Fatal("malformed stat accepted")
	}
}

func TestProcessIdentity(t *testing.T) {
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "42")
	if err := os.Mkdir(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stat := []byte("42 (worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 999")
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), stat, 0o600); err != nil {
		t.Fatal(err)
	}
	identity := ProcessIdentity{TGID: 42, StartTimeTicks: 999}
	if err := ValidateProcessIdentity(procRoot, identity); err != nil {
		t.Fatal(err)
	}
	identity.StartTimeTicks++
	if err := ValidateProcessIdentity(procRoot, identity); err == nil {
		t.Fatal("changed process identity was accepted")
	}
}

func TestProcMapsLoadBias(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maps")
	maps := "malformed\n" +
		"400000-401000 r--p 00000000 00:00 111 /not/the executable\n" +
		"7f001000-7f002000 r--p 00001000 00:00 222 /target (deleted)\n"
	if err := os.WriteFile(path, []byte(maps), 0o600); err != nil {
		t.Fatal(err)
	}
	mappings, err := ReadProcMaps(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(mappings) != 2 || mappings[1].Perms != "r--p" ||
		mappings[1].Path != "/target (deleted)" {
		t.Fatalf("mappings=%+v", mappings)
	}
	bias, err := FindLoadBias(mappings, 222, 0x1000, 0)
	if err != nil || bias != 0x7f001000 {
		t.Fatalf("load bias=%#x err=%v", bias, err)
	}
}

func TestReadProcMapsContextHonorsBounds(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maps")
	maps := "400000-401000 r--p 00000000 00:00 1 /first\n" +
		"500000-501000 r--p 00000000 00:00 2 /second\n"
	if err := os.WriteFile(path, []byte(maps), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadProcMapsContext(context.Background(), path, 1); err == nil {
		t.Fatal("entry limit was not enforced")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadProcMapsContext(ctx, path, 2); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled read error = %v, want context.Canceled", err)
	}
}
