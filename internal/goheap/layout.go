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

package goheap

import (
	"fmt"
	"strconv"
	"strings"
)

const (
	// MaxStackDepth bounds one externally copied runtime.memProfile stack.
	MaxStackDepth         = 64
	firstSupportedGoMinor = 20
	lastSupportedGoMinor  = 25
)

// RuntimeLayout describes the Go runtime heap-profile structures read from the
// OOM victim.
// The supported releases currently share this layout; keeping the release gate
// here makes an unknown runtime fail closed instead of silently corrupting data.
type RuntimeLayout struct {
	BucketHeaderSize uint64
	RecordCycles     int
	MaxStackDepth    int
}

// LayoutForVersion returns the runtime heap-profile layout for a Go version.
func LayoutForVersion(version string) (RuntimeLayout, error) {
	major, minor, err := parseGoVersion(version)
	if err != nil {
		return RuntimeLayout{}, err
	}
	if major != 1 || minor < firstSupportedGoMinor || minor > lastSupportedGoMinor {
		return RuntimeLayout{}, fmt.Errorf("unsupported Go runtime version %q: supported range is go1.%d-go1.%d",
			version, firstSupportedGoMinor, lastSupportedGoMinor)
	}
	return RuntimeLayout{
		BucketHeaderSize: 6 * 8,
		RecordCycles:     4,
		MaxStackDepth:    MaxStackDepth,
	}, nil
}

func parseGoVersion(version string) (int, int, error) {
	start := strings.Index(version, "go")
	if start < 0 {
		return 0, 0, fmt.Errorf("invalid Go runtime version %q", version)
	}
	parts := strings.Split(version[start+2:], ".")
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("invalid Go runtime version %q", version)
	}
	major, err := leadingNumber(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid Go runtime version %q", version)
	}
	minor, err := leadingNumber(parts[1])
	if err != nil {
		return 0, 0, fmt.Errorf("invalid Go runtime version %q", version)
	}
	return major, minor, nil
}

func leadingNumber(value string) (int, error) {
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, strconv.ErrSyntax
	}
	return strconv.Atoi(value[:end])
}
