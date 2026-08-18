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

import "strings"

func normalizeClassName(name string) string {
	dimensions := 0
	for dimensions < len(name) && name[dimensions] == '[' {
		dimensions++
	}
	if dimensions == 0 {
		return strings.ReplaceAll(name, "/", ".")
	}
	descriptor := name[dimensions:]
	var base string
	switch descriptor {
	case "Z":
		base = "boolean"
	case "B":
		base = "byte"
	case "C":
		base = "char"
	case "S":
		base = "short"
	case "I":
		base = "int"
	case "J":
		base = "long"
	case "F":
		base = "float"
	case "D":
		base = "double"
	default:
		if strings.HasPrefix(descriptor, "L") && strings.HasSuffix(descriptor, ";") {
			base = strings.TrimSuffix(strings.TrimPrefix(descriptor, "L"), ";")
		} else {
			return name
		}
	}
	return strings.ReplaceAll(base, "/", ".") + strings.Repeat("[]", dimensions)
}
