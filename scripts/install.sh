#!/bin/sh
set -eu

VERSION=0.1.0
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE_DIR="/usr/src/rayfw-$VERSION"
KERNEL_RELEASE=$(uname -r)
KERNEL_BUILD_DIR="/lib/modules/$KERNEL_RELEASE/build"

if [ "$(id -u)" -ne 0 ]; then
    echo "请使用 root 运行安装脚本。" >&2
    exit 1
fi

run_timed() {
    if command -v timeout >/dev/null 2>&1; then
        timeout --foreground 15m "$@"
    else
        "$@"
    fi
}

install_dependencies() {
    echo "正在安装构建依赖与内核 $KERNEL_RELEASE 的头文件..."
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        run_timed apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 update
        run_timed apt-get -o DPkg::Lock::Timeout=60 install -y --no-install-recommends \
            build-essential dkms kmod "linux-headers-$KERNEL_RELEASE"
    elif command -v dnf >/dev/null 2>&1; then
        run_timed dnf -y --setopt=timeout=30 --setopt=retries=3 \
            --setopt=install_weak_deps=False install gcc make kmod "kernel-devel-$KERNEL_RELEASE"
    elif command -v yum >/dev/null 2>&1; then
        run_timed yum -y --setopt=timeout=30 install gcc make kmod "kernel-devel-$KERNEL_RELEASE"
    elif command -v pacman >/dev/null 2>&1; then
        case "$KERNEL_RELEASE" in
            *-lts*) headers_package=linux-lts-headers ;;
            *-zen*) headers_package=linux-zen-headers ;;
            *-hardened*) headers_package=linux-hardened-headers ;;
            *) headers_package=linux-headers ;;
        esac
        run_timed pacman -Syu --noconfirm --needed base-devel kmod "$headers_package"
    else
        echo "不支持的包管理器。支持 APT、DNF/YUM 和 Pacman。" >&2
        exit 1
    fi
}

install_dependencies
if [ ! -f "$KERNEL_BUILD_DIR/Makefile" ]; then
    echo "未找到当前内核的构建目录: $KERNEL_BUILD_DIR" >&2
    echo "请安装与 uname -r 完全匹配的内核头文件后重新运行。" >&2
    exit 1
fi

make -C "$PROJECT_DIR" cli
make -C "$PROJECT_DIR" install
install -d -m 0700 /etc/rayfw
if [ ! -e /etc/rayfw/rules.conf ]; then
    install -m 0600 "$PROJECT_DIR/config.example" /etc/rayfw/rules.conf
fi

if command -v dkms >/dev/null 2>&1; then
    install -d "$SOURCE_DIR/include/uapi" "$SOURCE_DIR/kernel"
    install -m 0644 "$PROJECT_DIR/Makefile" "$PROJECT_DIR/dkms.conf" "$SOURCE_DIR/"
    install -m 0644 "$PROJECT_DIR/include/uapi/rayfw.h" "$SOURCE_DIR/include/uapi/"
    install -m 0644 "$PROJECT_DIR/kernel/Makefile" "$PROJECT_DIR/kernel/rayfw.c" "$SOURCE_DIR/kernel/"
    dkms status -m rayfw -v "$VERSION" | grep -q . || dkms add -m rayfw -v "$VERSION"
    dkms build -m rayfw -v "$VERSION"
    dkms install -m rayfw -v "$VERSION"
else
    echo "未找到 DKMS，仅为当前内核安装模块；内核升级后请重新运行安装脚本。" >&2
    make -C "$PROJECT_DIR" install-module
fi

depmod -a
modprobe rayfw
systemctl daemon-reload 2>/dev/null || true
systemctl enable rayfw.service 2>/dev/null || true
echo "安装完成。执行 'sudo rayfwctl status' 检查状态。"
