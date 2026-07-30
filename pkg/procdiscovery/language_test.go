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

package procdiscovery

import (
	"os"
	"testing"
)

func TestDetectLanguageByExecutableName(t *testing.T) {
	tests := map[string]Language{
		"/usr/bin/java":          LanguageJava,
		"/usr/bin/python":        LanguagePython,
		"/usr/bin/python3.12":    LanguagePython,
		"/usr/bin/node":          LanguageNode,
		"/usr/bin/npm":           LanguageNode,
		"/usr/bin/node_exporter": LanguageUnknown,
		"/usr/bin/python-worker": LanguageUnknown,
	}

	for exePath, want := range tests {
		t.Run(exePath, func(t *testing.T) {
			got := DetectLanguage(ProcessDetails{ExePath: exePath})
			if got != want {
				t.Fatalf("DetectLanguage(%q) = %q, want %q", exePath, got, want)
			}
		})
	}
}

func TestDetectLanguageReadsRunningGoExecutable(t *testing.T) {
	got := DetectLanguage(ProcessDetails{PID: os.Getpid()})
	if got != LanguageGo {
		t.Fatalf("current Go test process detected as %q, want %q", got, LanguageGo)
	}
}

func TestDetectLanguageByCapturedCmdline(t *testing.T) {
	got := DetectLanguage(ProcessDetails{
		Cmdline: "/usr/bin/env python3 worker.py",
	})
	if got != LanguagePython {
		t.Fatalf("captured env command detected as %q, want %q", got, LanguagePython)
	}
}

func TestDetectLanguageReadsCapturedGoExecutable(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	got := DetectLanguage(ProcessDetails{
		Cmdline:                executable + " -test.run=none",
		CheckCmdlineExecutable: true,
	})
	if got != LanguageGo {
		t.Fatalf("captured Go executable detected as %q, want %q", got, LanguageGo)
	}
}
