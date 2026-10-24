#!/usr/bin/env bash
# 依赖漏洞检查：只放行 .govulncheck-allow 里登记过的编号。
#
# CI 与本地 make test 共用这一份，避免两边判定漂移——历史上「本地绿、CI 红」
# 的主要来源就是本地根本没跑这项检查。
#
# 退出码：0 = 通过；1 = 扫描没跑成、出现清单外的通告，或清单里的条目已经消失。
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

# govulncheck 与它调用的 go list 必须是同一个 Go 版本：预装的二进制由旧版编译时，
# 遇到更新的 go list 会加载失败、一条通告都扫不出来；拿更新的 Go 现编又会在类型遍历里
# panic。所以固定用 go.mod 的 toolchain 现编现跑，与 CI 的 setup-go 一致。
# govulncheck 版本固定，原因见 CI 里的注释。
GOVULNCHECK=golang.org/x/vuln/cmd/govulncheck@v1.3.0
toolchain=$(awk '$1 == "toolchain" {print $2}' go.mod)
if [ -z "$toolchain" ]; then
  toolchain="go$(awk '$1 == "go" {print $2}' go.mod)"
fi
export GOTOOLCHAIN="$toolchain"

out=$(mktemp)
bin=$(mktemp -d)
trap 'rm -rf "$out" "$bin"' EXIT
# 不用 go run：它把子进程的退出码一律折成 1，分不清「有通告」与「没跑成」。
if ! GOBIN="$bin" go install "$GOVULNCHECK" > "$out" 2>&1; then
  cat "$out"
  echo
  echo "govulncheck 安装失败（工具链 ${GOTOOLCHAIN}），按失败处理"
  exit 1
fi
"$bin/govulncheck" ./... > "$out" 2>&1
rc=$?

# govulncheck 退出码：0 = 没有通告，3 = 有通告；其余表示扫描没跑成。
# 没跑成时 out 里没有任何编号，若照常往下走，清单为空时会被当成「通过」。
if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
  cat "$out"
  echo
  echo "govulncheck 没有跑成（退出码 ${rc}，工具链 ${GOTOOLCHAIN}），按失败处理"
  exit 1
fi

found=$(grep -oE 'GO-[0-9]{4}-[0-9]+' "$out" | sort -u || true)
# 报了有通告却提不出任何编号，说明输出格式变了；清单为空时继续往下会被当成通过。
if [ "$rc" -eq 3 ] && [ -z "$found" ]; then
  cat "$out"
  echo
  echo "govulncheck 报告有通告但未能提取编号，按失败处理"
  exit 1
fi
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
