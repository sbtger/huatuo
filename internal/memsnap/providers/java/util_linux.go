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

package java

func alignUp(value, alignment uint64) uint64 {
	return (value + alignment - 1) &^ (alignment - 1)
}

func saturatedAdd(left, right uint64) uint64 {
	if ^uint64(0)-left < right {
		return ^uint64(0)
	}
	return left + right
}

func checkedAdd(left, right uint64) (uint64, bool) {
	if right > ^uint64(0)-left {
		return 0, false
	}
	return left + right, true
}
