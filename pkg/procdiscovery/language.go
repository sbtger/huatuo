/*
 * Copyright 2023 Odigos
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
 *
 * Adapted from odigos-io/odigos procdiscovery commit
 * 7c6279dd7530a0fd3cdb3d21829c06d65445ff70. Inspectors unrelated to OOM
 * diagnostics, runtime-version lookup, environment access, and external
 * dependencies have been removed.
 */

/* Package procdiscovery detects the runtime language of a Linux process. */
package procdiscovery

import (
	"bufio"
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

/* Language is a detected process runtime. */
type Language string

const (
	LanguageUnknown Language = "unknown"
	LanguageJava    Language = "java"
	LanguageGo      Language = "go"
	LanguagePython  Language = "python"
	LanguageNode    Language = "node"
)

/*
ProcessDetails identifies a process. Captured fields may be supplied after
the process exits. CheckCmdlineExecutable permits opening an absolute argv[0].
*/
type ProcessDetails struct {
	PID                    int
	ExePath                string
	Cmdline                string
	CheckCmdlineExecutable bool
}

var pythonExecutablePattern = regexp.MustCompile(`^python(\d+(\.\d+)?)?$`)

/*
DetectLanguage checks the executable first and shared libraries only when
the executable is inconclusive.
*/
func DetectLanguage(details ProcessDetails) Language {
	exePath := details.ExePath
	if exePath == "" && details.PID > 0 {
		exePath, _ = os.Readlink(procPath(details.PID, "exe"))
	}

	detected := languageFromExecutable(filepath.Base(exePath))
	if detected == LanguageUnknown {
		detected = languageFromCmdline(details.Cmdline)
	}

	isGo := isGoExecutable(details.PID)
	if !isGo && details.CheckCmdlineExecutable {
		isGo = isGoExecutablePath(executableFromCmdline(details.Cmdline))
	}
	if isGo {
		if detected != LanguageUnknown && detected != LanguageGo {
			return LanguageUnknown
		}
		detected = LanguageGo
	}
	if detected != LanguageUnknown {
		return detected
	}

	java := mapsContain(details.PID, "/libjvm.so")
	python := linksPython(details.PID)
	switch {
	case java && python:
		return LanguageUnknown
	case java:
		return LanguageJava
	case python:
		return LanguagePython
	default:
		return LanguageUnknown
	}
}

func languageFromCmdline(cmdline string) Language {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 {
		return LanguageUnknown
	}

	detected := languageFromExecutable(filepath.Base(fields[0]))
	if detected != LanguageUnknown || filepath.Base(fields[0]) != "env" {
		return detected
	}
	for _, field := range fields[1:] {
		if strings.HasPrefix(field, "-") || strings.Contains(field, "=") {
			continue
		}
		return languageFromExecutable(filepath.Base(field))
	}
	return LanguageUnknown
}

func executableFromCmdline(cmdline string) string {
	fields := strings.Fields(cmdline)
	if len(fields) == 0 || !filepath.IsAbs(fields[0]) {
		return ""
	}
	return fields[0]
}

func languageFromExecutable(executable string) Language {
	switch {
	case executable == "java":
		return LanguageJava
	case pythonExecutablePattern.MatchString(executable):
		return LanguagePython
	case executable == "node", executable == "npm", executable == "npx", executable == "yarn":
		return LanguageNode
	default:
		return LanguageUnknown
	}
}

func isGoExecutable(pid int) bool {
	file, err := openProcFile(pid, "exe")
	if err != nil {
		return false
	}
	defer file.Close()

	_, err = buildinfo.Read(file)
	return err == nil
}

func isGoExecutablePath(path string) bool {
	if path == "" {
		return false
	}
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	_, err = buildinfo.Read(file)
	return err == nil
}

func mapsContain(pid int, substring string) bool {
	file, err := openProcFile(pid, "maps")
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), substring) {
			return true
		}
	}
	return false
}

func linksPython(pid int) bool {
	file, err := openProcFile(pid, "exe")
	if err != nil {
		return false
	}
	defer file.Close()

	executable, err := elf.NewFile(file)
	if err != nil {
		return false
	}
	dependencies, err := executable.DynString(elf.DT_NEEDED)
	if err != nil {
		return false
	}
	for _, dependency := range dependencies {
		if strings.Contains(dependency, "libpython3") {
			return true
		}
	}
	return false
}

func openProcFile(pid int, name string) (*os.File, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("process id is unavailable")
	}
	return os.Open(procPath(pid, name))
}

func procPath(pid int, name string) string {
	return fmt.Sprintf("/proc/%d/%s", pid, name)
}
