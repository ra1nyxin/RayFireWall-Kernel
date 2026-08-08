#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu

if [ "$#" -ne 2 ]; then
    echo "用法: $0 <平台名称> <内核头文件包>" >&2
    exit 64
fi

CI_PLATFORM=$1
CI_HEADERS_PACKAGE=$2
CI_PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    "$CI_HEADERS_PACKAGE"

CI_KDIR=$(find /usr/src -mindepth 1 -maxdepth 1 -type d -name 'linux-headers-*' | \
    sort -V | tail -n 1)
if [ -z "$CI_KDIR" ] || [ ! -f "$CI_KDIR/Makefile" ]; then
    echo "未找到可用于外部模块构建的内核头文件。" >&2
    exit 1
fi

make -C "$CI_PROJECT_DIR" clean KDIR="$CI_KDIR"
make -C "$CI_PROJECT_DIR" all KDIR="$CI_KDIR"
make -C "$CI_PROJECT_DIR/cli" clean all
"$CI_PROJECT_DIR/cli/rayfwctl" check "$CI_PROJECT_DIR/config.example"

CI_KERNEL_RELEASE=$(make -s -C "$CI_KDIR" kernelrelease)
CI_DIST_DIR="$CI_PROJECT_DIR/dist"
CI_ARCHIVE="rayfw-${CI_PLATFORM}-${CI_KERNEL_RELEASE}-x86_64.tar.gz"
mkdir -p "$CI_DIST_DIR/package"
install -m 0755 "$CI_PROJECT_DIR/cli/rayfwctl" "$CI_DIST_DIR/package/"
install -m 0644 "$CI_PROJECT_DIR/kernel/rayfw.ko" "$CI_DIST_DIR/package/"
install -m 0644 "$CI_PROJECT_DIR/config.example" "$CI_PROJECT_DIR/README.md" \
    "$CI_PROJECT_DIR/LICENSE" "$CI_DIST_DIR/package/"
install -Dm 0644 "$CI_PROJECT_DIR/packaging/systemd/rayfw.service" \
    "$CI_DIST_DIR/package/systemd/rayfw.service"
install -Dm 0644 "$CI_PROJECT_DIR/docs/rayfwctl.8" \
    "$CI_DIST_DIR/package/man/rayfwctl.8"
tar -C "$CI_DIST_DIR/package" -czf "$CI_DIST_DIR/$CI_ARCHIVE" .
echo "artifact=$CI_DIST_DIR/$CI_ARCHIVE" >> "${GITHUB_OUTPUT:-/dev/null}"
