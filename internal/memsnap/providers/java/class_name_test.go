// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package java

import "testing"

func TestNormalizeClassName(t *testing.T) {
	tests := map[string]string{
		"[B": "byte[]", "[[Ljava/lang/String;": "java.lang.String[][]",
		"service/CacheEntry": "service.CacheEntry",
	}
	for input, want := range tests {
		if got := normalizeClassName(input); got != want {
			t.Errorf("normalizeClassName(%q)=%q, want %q", input, got, want)
		}
	}
}
