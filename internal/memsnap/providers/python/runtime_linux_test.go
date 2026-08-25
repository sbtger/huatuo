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

package python

import (
	"errors"
	"testing"

	"huatuo-bamai/internal/memsnap"
)

func TestRuntimeModules(t *testing.T) {
	mappings := []memsnap.ProcMap{
		{Start: 0x1000, End: 0x2000, Inode: 10, Path: "/usr/bin/service"},
		{Start: 0x2000, End: 0x3000, Inode: 20, Path: "/usr/lib/libpython3.12.so.1.0"},
		{Start: 0x3000, End: 0x4000, Inode: 20, Path: "/opt/lib/libpython3.11.so.1.0"},
		{Start: 0x4000, End: 0x5000, Inode: 30, Path: "/usr/lib/python_plugin.so"},
	}

	modules, warning := runtimeModules(t.TempDir(), 42, mappings)
	if warning != "" {
		t.Fatal(warning)
	}
	if len(modules) != 3 {
		t.Fatalf("modules=%+v, want executable plus two libpython mappings", modules)
	}
	if modules[1].maps[0].Path == modules[2].maps[0].Path {
		t.Fatalf("same-inode mappings were merged: %+v", modules)
	}
}

func TestRuntimeLayouts(t *testing.T) {
	for minor := 8; minor <= 14; minor++ {
		layout, err := layoutFor(version{major: 3, minor: minor})
		if err != nil {
			t.Fatalf("CPython 3.%d layout: %v", minor, err)
		}
		if layout.interpreterMode == interpreterLayoutUnknown ||
			layout.unicodeDataOffset == 0 {
			t.Fatalf("CPython 3.%d has incomplete layout: %+v", minor, layout)
		}
	}
	_, err := layoutFor(version{major: 3, minor: 99})
	if !errors.Is(err, errUnsupportedRuntime) {
		t.Fatalf("error=%v, want errUnsupportedRuntime", err)
	}
}
