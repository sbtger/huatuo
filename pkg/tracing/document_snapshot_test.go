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

package tracing

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDocumentStoreMapperPreservesOOMRuntimeSnapshot(t *testing.T) {
	document := &Document{
		TracerName: "oom",
		TracerData: map[string]any{
			"victim": map[string]any{"pid": 42, "comm": "java"},
			"runtime_memory_snapshot": map[string]any{
				"schema_version": 2,
				"status":         "PARTIAL_DEADLINE",
				"truncated":      true,
				"entries": []map[string]any{{
					"kind":          "object_type",
					"name":          "example.Payload",
					"inuse_bytes":   4096,
					"inuse_objects": 64,
				}},
			},
		},
	}

	raw, err := (DocumentStoreMapper{}).Encode(document)
	require.NoError(t, err)

	var encoded map[string]any
	require.NoError(t, json.Unmarshal(raw, &encoded))
	tracerData := encoded["tracer_data"].(map[string]any)
	snapshot := tracerData["runtime_memory_snapshot"].(map[string]any)
	require.Equal(t, "PARTIAL_DEADLINE", snapshot["status"])
	require.Equal(t, "example.Payload",
		snapshot["entries"].([]any)[0].(map[string]any)["name"])
}
