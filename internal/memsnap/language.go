// Copyright 2023 Odigos
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
//
// Adapted from odigos-io/odigos procdiscovery commit
// 7c6279dd7530a0fd3cdb3d21829c06d65445ff70.

package memsnap

import (
	"bufio"
	"context"
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Language identifies a process runtime.
type Language string

// Supported process runtimes recognized by language detection.
const (
	LanguageUnknown Language = "unknown"
	LanguageJava    Language = "java"
	LanguageGo      Language = "go"
	LanguagePython  Language = "python"
)

var pythonExecutablePattern = regexp.MustCompile(`^python(\d+(\.\d+)?)?$`)

// DetectLanguageFromPID identifies a runtime by reading /proc/<pid>. It first
// checks the executable for readable Go build information, then the executable
// basename, then the mapped runtime libraries.
//
// Cancellation is cooperative because the procfs and ELF APIs expose only
// synchronous Read and ReadAt calls. The deadline is therefore a cooperative
// stop budget, not a wall-clock upper bound. It cannot preempt a syscall that
// has entered the kernel, and that syscall may block without a time bound. The
// readers below check the context both before and after each call, so once the
// in-flight call returns, cancellation prevents subsequent parsing I/O from
// starting. A hard bound would require isolating reads in a separately managed
// process.
func DetectLanguageFromPID(ctx context.Context, pid int) Language {
	if ctx == nil {
		ctx = context.Background()
	}
	if ctx.Err() != nil {
		return LanguageUnknown
	}
	exeFile, _ := os.Open(procPath(pid, "exe"))
	if exeFile != nil {
		defer exeFile.Close()

		// Go binaries contain readable Go build information.
		if _, err := buildinfo.Read(contextReaderAt{ctx: ctx, reader: exeFile}); err == nil {
			return LanguageGo
		}
	}

	if ctx.Err() != nil {
		return LanguageUnknown
	}
	exePath, _ := os.Readlink(procPath(pid, "exe"))
	if ctx.Err() != nil {
		return LanguageUnknown
	}
	detected := languageFromExecutable(filepath.Base(exePath))
	if detected != LanguageUnknown {
		return detected
	}

	return languageFromRuntimeLibraries(ctx, pid, exeFile)
}

func languageFromRuntimeLibraries(ctx context.Context, pid int, exeFile *os.File) Language {
	java := mapsContain(ctx, pid, "/libjvm.so")
	python := exeFile != nil && linksPython(ctx, exeFile)
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

func languageFromExecutable(executable string) Language {
	switch {
	case executable == "java":
		return LanguageJava
	case pythonExecutablePattern.MatchString(executable):
		return LanguagePython
	default:
		return LanguageUnknown
	}
}

func mapsContain(ctx context.Context, pid int, substring string) bool {
	file, err := os.Open(procPath(pid, "maps"))
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(contextReader{ctx: ctx, reader: file})
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), substring) {
			return true
		}
	}
	return false
}

func linksPython(ctx context.Context, file *os.File) bool {
	executable, err := elf.NewFile(contextReaderAt{ctx: ctx, reader: file})
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

// These adapters provide cooperative cancellation around synchronous process
// reads. A context cannot interrupt a Read or ReadAt syscall that has already
// entered the kernel, so cancellation is checked both before and after every
// call. The in-flight syscall may block without a time bound; after it returns,
// no later read is started. This is intentionally not a hard per-syscall
// deadline, which the io.Reader interfaces cannot provide.
type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.Read(p)
	if ctxErr := r.ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}
	return n, err
}

type contextReaderAt struct {
	ctx    context.Context
	reader io.ReaderAt
}

func (r contextReaderAt) ReadAt(p []byte, offset int64) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	n, err := r.reader.ReadAt(p, offset)
	if ctxErr := r.ctx.Err(); ctxErr != nil {
		return n, ctxErr
	}
	return n, err
}

func procPath(pid int, name string) string {
	return fmt.Sprintf("/proc/%d/%s", pid, name)
}
