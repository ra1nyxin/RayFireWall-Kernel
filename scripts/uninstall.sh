#!/bin/sh
set -eu

VERSION=0.1.0

if [ "$(id -u)" -ne 0 ]; then
    echo "请使用 root 运行卸载脚本。" >&2
    exit 1
fi

systemctl disable --now rayfw.service 2>/dev/null || true
modprobe -r rayfw 2>/dev/null || true
if command -v dkms >/dev/null 2>&1; then
    dkms remove -m rayfw -v "$VERSION" --all 2>/dev/null || true
fi
rm -f /usr/sbin/rayfwctl
rm -f /usr/lib/systemd/system/rayfw.service
rm -f /usr/share/bash-completion/completions/rayfwctl
rm -f /usr/share/man/man8/rayfwctl.8
rm -rf "/usr/src/rayfw-$VERSION"
depmod -a
systemctl daemon-reload 2>/dev/null || true
echo "卸载完成。配置 /etc/rayfw/rules.conf 已保留。"
