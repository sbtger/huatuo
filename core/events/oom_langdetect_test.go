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

package events

import (
	"os"
	"testing"

	"huatuo-bamai/pkg/procdiscovery"
)

func TestDetectLanguageInfoUsesComm(t *testing.T) {
	info := detectLanguageInfo(OOMActor{Comm: "java"})
	if info.Victim != procdiscovery.LanguageJava {
		t.Fatalf("Java process detected as %q, want %q",
			info.Victim, procdiscovery.LanguageJava)
	}
}

func TestDetectLanguageInfoReadsRunningGoExecutable(t *testing.T) {
	info := detectLanguageInfo(OOMActor{
		Pid:  int32(os.Getpid()),
		Comm: "worker",
	})

	if info.Victim != procdiscovery.LanguageGo {
		t.Fatalf("current Go test process detected as %q, want %q",
			info.Victim, procdiscovery.LanguageGo)
	}
}

func TestCompleteLanguageInfoUsesExitCmdline(t *testing.T) {
	oomData := &OOMTracingData{
		Victim: OOMActor{Cmdline: "/usr/bin/python3 worker.py"},
		LanguageInfo: &OOMLanguageInfo{
			Victim: procdiscovery.LanguageUnknown,
		},
	}

	completeLanguageInfo(oomData)
	if oomData.LanguageInfo.Victim != procdiscovery.LanguagePython {
		t.Fatalf("exit cmdline language = %q, want %q",
			oomData.LanguageInfo.Victim, procdiscovery.LanguagePython)
	}
}
