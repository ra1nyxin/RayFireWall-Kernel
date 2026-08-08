#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu

if [ "$#" -ne 3 ]; then
    echo "用法: $0 <平台名称> <apt|dnf|pacman> <内核头文件包>" >&2
    exit 64
fi

CI_PLATFORM=$1
CI_PACKAGE_MANAGER=$2
CI_HEADERS_PACKAGE=$3
CI_PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

case "$CI_PACKAGE_MANAGER" in
    apt)
        export DEBIAN_FRONTEND=noninteractive
        apt-get update
        apt-get install -y --no-install-recommends build-essential ca-certificates "$CI_HEADERS_PACKAGE"
        ;;
    dnf)
        dnf -y --setopt=install_weak_deps=False install gcc make ca-certificates "$CI_HEADERS_PACKAGE"
        ;;
    pacman)
        pacman -Syu --noconfirm --needed base-devel ca-certificates "$CI_HEADERS_PACKAGE"
        ;;
    *)
        echo "不支持的 CI 包管理器: $CI_PACKAGE_MANAGER" >&2
        exit 64
        ;;
esac

CI_KDIR=$(for candidate in /usr/lib/modules/*/build /lib/modules/*/build \
    /usr/src/kernels/* /usr/src/linux-headers-*; do
    if [ -f "$candidate/Makefile" ] && \
       { [ -f "$candidate/include/config/auto.conf" ] || [ -f "$candidate/include/generated/autoconf.h" ]; }; then
        printf '%s\n' "$candidate"
    fi
done | sort -V | tail -n 1)
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
CI_ARCHIVE="rayfw-${CI_PLATFORM}-${CI_KERNEL_RELEASE}-$(uname -m).tar.gz"
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
