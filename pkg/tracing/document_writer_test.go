/*
 * Copyright 2026 The HuaTuo Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package tracing

import (
	"testing"
	"time"
)

func TestNewBaseDocumentAllowsMissingContainer(t *testing.T) {
	document, err := newBaseDocument(DocumentOptions{}, &WriteRequest{
		TracerName:            "oom",
		ContainerID:           "missing-container",
		TracerTime:            time.Now(),
		AllowMissingContainer: true,
	})
	if err != nil {
		t.Fatalf("newBaseDocument() error = %v", err)
	}
	if document.ContainerID != "" {
		t.Fatalf("container ID = %q, want empty", document.ContainerID)
	}
}
