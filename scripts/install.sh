#!/bin/sh
set -eu

VERSION=0.1.0
PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SOURCE_DIR="/usr/src/rayfw-$VERSION"

if [ "$(id -u)" -ne 0 ]; then
    echo "请使用 root 运行安装脚本。" >&2
    exit 1
fi

if ! command -v apt-get >/dev/null 2>&1; then
    echo "此安装脚本仅支持使用 APT 的 Debian、Ubuntu 和 Kali Linux。" >&2
    exit 1
fi

echo "正在安装构建依赖与当前内核头文件..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
    build-essential \
    dkms \
    kmod \
    "linux-headers-$(uname -r)"

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
    echo "未找到 DKMS，仅为当前内核安装模块。建议安装 dkms 后重新运行。" >&2
    make -C "$PROJECT_DIR" install-module
fi

depmod -a
modprobe rayfw
systemctl daemon-reload 2>/dev/null || true
systemctl enable rayfw.service 2>/dev/null || true
echo "安装完成。执行 'sudo rayfwctl status' 检查状态。"
