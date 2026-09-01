#!/usr/bin/env bash

# Copyright 2026 The HuaTuo Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Exercise the real HotSpot and CPython external-memory readers independently
# of the privileged cgroup event-to-storage test. Runtime prerequisites are not
# installed by this test; each Go test reports a skip when its supported runtime
# or required symbols are unavailable.

set -euo pipefail

source "${ROOT_DIR}/integration/lib.sh"

log_info "validating live HotSpot and CPython memory providers"
(
	cd "${ROOT_DIR}"
	go test -mod=vendor -tags=integration -count=1 -v \
		-run '^TestCaptureLive(HotSpot|CPython)Process$' ./integration
)
