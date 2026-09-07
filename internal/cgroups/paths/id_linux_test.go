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

package paths

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestKernfsHandleID(t *testing.T) {
	data := make([]byte, 8)
	const want uint64 = 7<<32 | 42
	binary.NativeEndian.PutUint64(data, want)
	for _, kind := range []int32{0xfe, 1} {
		id, err := kernfsHandleID(unix.NewFileHandle(kind, data))
		if err != nil || id != want {
			t.Fatalf("type=%d ID=%d, err=%v", kind, id, err)
		}
	}
	for _, handle := range []unix.FileHandle{unix.NewFileHandle(2, data), unix.NewFileHandle(0xfe, data[:4]), unix.NewFileHandle(1, data[:4])} {
		if _, err := kernfsHandleID(handle); err == nil {
			t.Fatal("accepted non-kernfs or truncated handle")
		}
	}
}

func TestKernfsIDMissing(t *testing.T) {
	if _, err := KernfsID(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing path: %v", err)
	}
}

func TestKernfsIDSymlink(t *testing.T) {
	root := os.Getenv("HUATUO_KERNFS_TEST_PATH")
	if root == "" {
		t.Skip("set HUATUO_KERNFS_TEST_PATH to a cgroup directory")
	}
	want, err := KernfsID(root)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "cgroup")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	got, err := KernfsID(alias)
	if err != nil || got != want || got == 0 {
		t.Fatalf("ID=%d, want %d, err=%v", got, want, err)
	}
}
