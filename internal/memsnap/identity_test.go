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

import "testing"

func TestParseProcStatStartTime(t *testing.T) {
	stat := []byte("42 (worker (oom)) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 999 20")
	got, err := ParseProcStatStartTime(stat)
	if err != nil {
		t.Fatal(err)
	}
	if got != 999 {
		t.Fatalf("starttime=%d, want 999", got)
	}
}

func TestParseProcStatStartTimeRejectsMalformed(t *testing.T) {
	if _, err := ParseProcStatStartTime([]byte("42 worker S")); err == nil {
		t.Fatal("malformed stat accepted")
	}
}
