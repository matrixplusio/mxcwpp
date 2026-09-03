#!/usr/bin/env bash
# 依赖漏洞检查：只放行 .govulncheck-allow 里登记过的编号。
#
# CI 与本地 make test 共用这一份，避免两边判定漂移——历史上「本地绿、CI 红」
# 的主要来源就是本地根本没跑这项检查。
#
# 退出码：0 = 通过；1 = 出现清单外的通告，或清单里的条目已经消失。
set -uo pipefail

cd "$(dirname "$0")/.."

if ! command -v govulncheck >/dev/null 2>&1; then
  echo "govulncheck 未安装，跳过依赖漏洞检查"
  echo "  装法：go install golang.org/x/vuln/cmd/govulncheck@latest"
  echo "  注意：CI 上这项一定会跑，本地跳过不代表能过。"
  exit 0
fi

out=$(mktemp)
trap 'rm -f "$out"' EXIT
govulncheck ./... > "$out" 2>&1 || true

found=$(grep -oE 'GO-[0-9]{4}-[0-9]+' "$out" | sort -u || true)
allowed=$(grep -oE 'GO-[0-9]{4}-[0-9]+' .govulncheck-allow | sort -u || true)

unexpected=$(comm -23 <(echo "$found") <(echo "$allowed"))
if [ -n "$unexpected" ]; then
  cat "$out"
  echo
  echo "以下通告不在 .govulncheck-allow 中："
  echo "$unexpected"
  echo
  echo "若上游已有修复版本，升级依赖；确无版本可升时，把编号加进"
  echo ".govulncheck-allow 并写明理由与复查条件。"
  exit 1
fi

# 清单里的条目若已不再出现，说明上游修了，应当升级依赖并移除该行。
stale=$(comm -13 <(echo "$found") <(echo "$allowed"))
if [ -n "$stale" ]; then
  echo "以下通告已不再出现，请升级依赖并从 .govulncheck-allow 移除："
  echo "$stale"
  exit 1
fi

echo "依赖漏洞检查通过"
