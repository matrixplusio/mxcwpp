#!/usr/bin/env bash
#
# 远端体检：匿名克隆一个远端仓库的全部引用，逐提交扫一遍。
#
# 本地门禁只管「从这里推出去的东西」；远端上别人推的分支、tag、PR 引用
# 不经过本机钩子，要从远端整体看一遍。
#
# 用法：scripts/audit-remote.sh <仓库 URL>
#   退出码 0 = 干净，1 = 有命中，2 = 克隆失败。
#   规则与 pre-push 完全一致（.githooks/leakscan.sh），包括 leakscan:example 豁免，
#   所以这里报的就是推送时会被拦的东西，不会另起一套误报。

set -uo pipefail

url="${1:?用法：audit-remote.sh <仓库 URL>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# 匿名克隆：不用本机凭据，看到的就是外人能看到的。--mirror 会带上 refs/pull/*。
if ! GIT_TERMINAL_PROMPT=0 git -c credential.helper= clone --quiet --mirror "$url" "$work/repo.git"; then
  echo "克隆失败：$url" >&2
  exit 2
fi

export LEAKSCAN_DICT="${LEAKSCAN_DICT:-$root/.production-identifiers}"
if [ ! -s "$LEAKSCAN_DICT" ]; then
  echo "提示：没有本地字典，只跑通用规则（认不出真实主机名与业务线）。" >&2
fi

cd "$work/repo.git" || exit 2
# shellcheck source=../.githooks/leakscan.sh
. "$root/.githooks/leakscan.sh"

echo "公开引用：$(git for-each-ref | wc -l | tr -d ' ') 个（其中 PR $(git for-each-ref refs/pull | wc -l | tr -d ' ') 个）" >&2

rc=0
leakscan_commits --all || rc=1
while read -r t; do
  leakscan_tag "$t" || rc=1
done < <(git for-each-ref --format='%(objectname)' refs/tags)

if [ $rc -eq 0 ]; then
  echo "未发现命中。" >&2
fi
exit $rc
