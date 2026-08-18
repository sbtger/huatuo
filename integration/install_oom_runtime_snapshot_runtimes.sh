#!/usr/bin/env bash

# Copyright 2026 The HuaTuo Authors.
# Licensed under the Apache License, Version 2.0.

# Install the exact runtime matrix used by oom_runtime_snapshot_vm.sh without
# replacing the VM's system Go, Python or Java commands.

set -euo pipefail

RUNTIME_ROOT=${HUATUO_RUNTIME_ROOT:-/opt/huatuo-runtime-matrix}
mkdir -p "${RUNTIME_ROOT}"

install_go() {
	local version=$1 expected=$2
	local destination="${RUNTIME_ROOT}/go${version}"
	[[ -x ${destination}/bin/go ]] && return
	local archive="/tmp/go${version}.linux-amd64.tar.gz"
	curl --retry 3 -fsSLo "${archive}" \
		"https://mirrors.aliyun.com/golang/go${version}.linux-amd64.tar.gz"
	(cd /tmp && printf '%s  %s\n' "${expected}" "$(basename "${archive}")" | sha256sum -c -)
	local temporary
	temporary=$(mktemp -d "${RUNTIME_ROOT}/.go${version}.XXXXXX")
	tar -xzf "${archive}" -C "${temporary}"
	mv "${temporary}/go" "${destination}"
	rmdir "${temporary}"
	rm -f "${archive}"
}

while read -r version checksum; do
	printf 'installing Go %s\n' "${version}"
	install_go "${version}" "${checksum}"
done <<'EOF'
1.20.14 ff445e48af27f93f66bd949ae060d97991c83e11289009d311f25426258f9c44
1.21.13 502fc16d5910562461e6a6631fb6377de2322aad7304bf2bcd23500ba9dab4a7
1.22.12 4fa4f869b0f7fc6bb1eb2660e74657fbf04cdd290b5aef905585c86051b34d43
1.23.12 d3847fef834e9db11bf64e3fb34db9c04db14e068eeb064f49af747010454f90
1.24.6 bbca37cc395c974ffa4893ee35819ad23ebb27426df87af92e93a9ec66ef8712
1.25.0 2852af0cb20a13139b3448992e69b868e50ed0f8a1e5940ee1de9e19a123b613
EOF

if [[ ! -x ${RUNTIME_ROOT}/uv ]]; then
	curl -LsSf https://astral.sh/uv/install.sh |
		env UV_INSTALL_DIR="${RUNTIME_ROOT}" sh
fi
export UV_PYTHON_INSTALL_DIR="${RUNTIME_ROOT}/python-installations"
"${RUNTIME_ROOT}/uv" python install 3.8 3.9 3.10 3.11 3.12 3.13 3.14
for version in 3.8 3.9 3.10 3.11 3.12 3.13 3.14; do
	python=$(${RUNTIME_ROOT}/uv python find "${version}")
	ln -sfn "$(dirname "$(dirname "${python}")")" \
		"${RUNTIME_ROOT}/python${version}"
done

# These defaults match the 2222 Ubuntu VM. Override a link after installation
# when validating a different image; the matrix runner also accepts per-version
# HUATUO_JAVA_<VERSION> environment variables.
ln -sfn /opt/huatuo-jdk8/jre "${RUNTIME_ROOT}/jdk8"
ln -sfn /usr/lib/jvm/java-11-openjdk-amd64 "${RUNTIME_ROOT}/jdk11"
ln -sfn /usr/lib/jvm/java-17-openjdk-amd64 "${RUNTIME_ROOT}/jdk17"
ln -sfn /usr/lib/jvm/java-21-openjdk-amd64 "${RUNTIME_ROOT}/jdk21"
ln -sfn /usr/lib/jvm/java-25-openjdk-amd64 "${RUNTIME_ROOT}/jdk25"

printf 'runtime matrix installed under %s\n' "${RUNTIME_ROOT}"
