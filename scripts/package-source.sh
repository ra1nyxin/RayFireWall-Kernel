#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
set -eu

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OUTPUT_DIR=${1:-"$PROJECT_DIR/dist"}

if ! command -v git >/dev/null 2>&1; then
    echo "创建源码包需要 git。" >&2
    exit 1
fi
if ! git -C "$PROJECT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "未在 Git 工作树中，无法创建可复现的源码包。" >&2
    exit 1
fi

mkdir -p "$OUTPUT_DIR"
git -C "$PROJECT_DIR" archive --format=tar.gz \
    --prefix=RayFireWall-Kernel/ HEAD > "$OUTPUT_DIR/rayfw-source.tar.gz"
echo "已创建源码包: $OUTPUT_DIR/rayfw-source.tar.gz"
