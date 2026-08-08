#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
CLI="$ROOT/cli/rayfwctl"

"$CLI" --version | grep -q '^rayfwctl 0\.1\.0$'
"$CLI" help | grep -q '添加规则选项'
"$CLI" --help | grep -q 'RayFireWall'
"$CLI" check "$ROOT/config.example" | grep -q '语法正确'
if "$CLI" check "$ROOT/tests/fixtures/invalid.conf" >/dev/null 2>&1; then
    echo "无效配置不应通过离线检查" >&2
    exit 1
fi

echo "CLI 离线测试通过。"
