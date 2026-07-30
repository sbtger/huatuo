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

import "huatuo-bamai/pkg/procdiscovery"

/* OOMLanguageInfo captures the selected victim's detected language. */
type OOMLanguageInfo struct {
	Victim procdiscovery.Language `json:"victim"`
}

func detectLanguageInfo(victim OOMActor) *OOMLanguageInfo {
	detected := procdiscovery.LanguageUnknown
	if victim.Pid > 0 {
		detected = procdiscovery.DetectLanguage(procdiscovery.ProcessDetails{
			PID: int(victim.Pid),
		})
	}

	/*
	 * Fall back to captured process metadata only when live procfs
	 * detection fails.
	 */
	if detected == procdiscovery.LanguageUnknown {
		detected = procdiscovery.DetectLanguage(procdiscovery.ProcessDetails{
			ExePath: victim.Comm,
		})
	}

	return &OOMLanguageInfo{Victim: detected}
}
