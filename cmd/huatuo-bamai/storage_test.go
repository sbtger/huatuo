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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"huatuo-bamai/cmd/huatuo-bamai/config"
	"huatuo-bamai/pkg/tracing"
)

func TestInitStorageWritesProfilesToLocalFile(t *testing.T) {
	path := t.TempDir()
	cfg := &config.BamaiConfig{}
	cfg.Storage.LocalFile.Path = path
	cfg.Storage.LocalFile.RotationSizeMiB = 1
	cfg.Storage.LocalFile.MaxRotatedFiles = 1
	if err := initStorage("test", cfg); err != nil {
		t.Fatalf("initStorage: %v", err)
	}
	if err := tracing.SaveProfile(&tracing.WriteRequest{
		TracerName: "oom-java-stack", TracerID: "oom-id",
		TracerTime: time.Unix(1, 0), TracerData: map[string]any{"sample": 1},
		TracerRunType: tracing.TracerRunTypeEvent,
	}); err != nil {
		t.Fatalf("SaveProfile: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(path, "oom-java-stack"))
	if err != nil {
		t.Fatalf("read local profile: %v", err)
	}
	var document tracing.Document
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode local profile: %v", err)
	}
	if document.TracerID != "oom-id" || document.TracerName != "oom-java-stack" {
		t.Fatalf("unexpected local profile document: %+v", document)
	}
}
