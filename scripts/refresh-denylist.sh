#!/usr/bin/env bash
#
# 生成本地字典里的「真实值」段：从真实环境收集不该公开的名字，写进 .production-identifiers。
#
# 为什么不靠人记：手工登记总会漏，漏掉的正是没想到的那些——业务线代号、真实人名、
# 集群上下文名。只要真实环境里有，就该自动进清单。
#
# 公开脚本里不写任何真实值。收集什么、去哪收集，写在本地文件里（不入库，放进 git 的忽略规则）：
#   scripts/denylist-sources.local.sh     定义函数 collect，每行输出一个候选词
#                                         （例如只读查询主机名、业务线、服务名、镜像路径、人名）
#   scripts/denylist-stopwords.local.txt  不收的通用词，一行一个
# 会透露行业的常见词不属于这两类，直接写进 .production-identifiers 的手工段。
# 本脚本另外读本机 kubeconfig 的上下文名与集群名。
#
# 用法：
#   scripts/refresh-denylist.sh           只列出候选词与它们在当前受跟踪文件里的命中数，不写
#   scripts/refresh-denylist.sh --write   写回字典（只替换自动生成段，手工条目原样保留）
#
# 命中数不为 0 的候选要先看一眼：要么是真泄露（改代码），要么是通用词（加进停用词）。
# 不剔除通用词，全仓库都会误报，门禁就会被当噪声绕过。

set -euo pipefail

root="$(git rev-parse --show-toplevel)"
dict="${LEAKSCAN_DICT:-$root/.production-identifiers}"
src="${DENYLIST_SOURCES:-$root/scripts/denylist-sources.local.sh}"
stop_local="${DENYLIST_STOPWORDS:-$root/scripts/denylist-stopwords.local.txt}"
begin='# >>> 自动生成：scripts/refresh-denylist.sh 维护，手工条目写在这段之外'
end='# <<< 自动生成'

write=0
[ "${1:-}" = "--write" ] && write=1

# 不论在哪个环境都太通用、收进来只会误报的词。只放技术通用词，不放任何真实名字。
builtin_stop='^(default|kubernetes|localhost|minikube|docker-desktop|kind-kind|orbstack|admin|administrator|root|ubuntu|centos|debian|test|testing|staging|production|develop|master|main|cluster|server|client|agent|plugin|manager|engine|consumer|scanner|example|unknown|mxcwpp)$'

raw="$(
  {
    # 本机 kubeconfig：上下文名与集群名。GKE 的名字形如 gke_<项目>_<区域>_<集群>，拆开收。
    if command -v kubectl >/dev/null 2>&1; then
      kubectl config get-contexts -o name 2>/dev/null || true
      kubectl config view -o jsonpath='{range .clusters[*]}{.name}{"\n"}{end}' 2>/dev/null || true
    fi
    if [ -f "$src" ]; then
      # shellcheck source=/dev/null
      . "$src"
      collect
    else
      echo "提示：没有 ${src}，只收集了 kubeconfig。" >&2
    fi
  } | tr -d '\r'
)"

cands="$(
  printf '%s\n' "$raw" \
    | awk '{ if ($0 ~ /^gke_/) { n = split($0, a, "_"); for (i = 2; i <= n; i++) print a[i] } else print }' \
    | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' \
    | LC_ALL=C awk '
        /[^ -~]/ { if (length($0) >= 6) print; next }     # 非 ASCII（如中文名）：至少两个汉字
        /^[a-z0-9][a-z0-9._\/-]*$/ && /[a-z]/ && length($0) >= 5 { print }' \
    | grep -vE "$builtin_stop" \
    | { if [ -s "$stop_local" ]; then grep -vixF -f <(grep -vE '^[[:space:]]*(#|$)' "$stop_local"); else cat; fi; } \
    | sort -u || true
)"

if [ -z "$cands" ]; then
  echo "没有收集到候选词。" >&2
  exit 1
fi

# 已在手工段里的不重复收。
manual=""
if [ -f "$dict" ]; then
  manual="$(awk -v b="$begin" -v e="$end" '$0==b{s=1;next} $0==e{s=0;next} !s' "$dict")"
fi
cands="$(printf '%s\n' "$cands" | grep -vixF -f <(printf '%s\n' "$manual" | grep -vE '^[[:space:]]*(#|$)' || echo '@@none@@') || true)"

echo "候选词 $(printf '%s\n' "$cands" | sed '/^$/d' | wc -l | tr -d ' ') 个（右侧是当前受跟踪文件中命中的文件数）：" >&2
while read -r w; do
  [ -z "$w" ] && continue
  n="$({ git -C "$root" grep -I -i -l -F -e "$w" 2>/dev/null || true; } | wc -l | tr -d ' ')"
  printf '  %-40s %s\n' "$w" "$n" >&2
done <<< "$cands"

if [ $write -eq 0 ]; then
  echo "未写入。确认无通用词后加 --write。" >&2
  exit 0
fi

tmp="$(mktemp)"
{
  # 手工段原样保留，只去掉末尾空行。
  [ -f "$dict" ] && printf '%s\n' "$manual" | awk 'NF{for(;n>0;n--)print ""; print; next} {n++}'
  echo "$begin"
  printf '%s\n' "$cands" | sed '/^$/d'
  echo "$end"
} > "$tmp"
chmod 600 "$tmp"
mv "$tmp" "$dict"
echo "已写入 $dict" >&2
