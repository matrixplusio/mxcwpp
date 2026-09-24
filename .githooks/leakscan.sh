#!/usr/bin/env bash
#
# 生产信息扫描，pre-commit 与 pre-push 共用。
#
# 用法：leakscan_lines < 输入
#   输入每行「位置<TAB>文本」，位置随意（文件名、commit 短 sha），只用于报告。
#   有命中时打印到 stderr 并返回 1。
#
# 判据与 internal/deploy 下的门禁测试一致，来源标记正则就是同一个文件
# （.githooks/prod-claim-patterns）；internal/deploy/push_gate_test.go 用真实
# git 仓库跑 pre-push，钉住这里确实拦得住。
#
# 行尾带 leakscan:example 的行跳过「来源表述 / 组织标识 / 凭证」三类检查——
# 留给讲解规则本身的文档与反例固件。它跳不过地址与本地字典：
# 真实地址和真实名字不存在「作为示例」的合法用法。

# 具体数字：四位以上整数、千分位数、带量词的数。三位以内的裸数字
# （端口、超时、重试次数）不算。
LEAKSCAN_QTY='[0-9]{4,}|[0-9]{1,3}(,[0-9]{3})+|[0-9]+(\.[0-9]+)? ?([kKwWM]\+?|万|亿|台|条|次|个|行|GB|TB|MB|%|/天|/秒|/周|ms|us|秒)'

# 「实测」本身不指明来源：实验室压测也叫实测。带下列任一词的视为实验室数据放行，
# 否则按生产数据处理——宁可让写的人换个说法，也不让来源不明的数字出去。
LEAKSCAN_LAB='基准|压测|benchmark|本仓库|本地|靶机|dev|单测|测试环境|内核|kernel|centos|runtime|eps|构建|%\+?v'

# 文档用地址白名单，与 internal/deploy/no_production_identifiers_test.go 的
# documentedPrefixes 对应。只列允许的，不列禁止的：黑名单等于把真实网段写进公开仓库。
LEAKSCAN_ADDR_OK='^(10\.0\.|10\.1\.2\.3([[:space:]]|$)|10\.96\.|10\.255\.255\.255([[:space:]]|$)|127\.|169\.254\.|172\.16\.|172\.17\.|172\.31\.255\.|172\.32\.0\.1([[:space:]]|$)|192\.0\.2\.|192\.168\.[01]\.|198\.51\.100\.|203\.0\.113\.|0\.0\.0\.0([[:space:]]|$)|255\.255\.255\.255([[:space:]]|$)|8\.8\.[84]\.[84]([[:space:]]|$)|1\.1\.1\.1([[:space:]]|$)|114\.114\.114\.114([[:space:]]|$)|223\.[56]\.[56]\.[56]([[:space:]]|$)|93\.184\.216\.34([[:space:]]|$)|999\.|8\.1\.4\.|[0-9]\.[0-9]+\.[0-9]+\.[0-9]+([[:space:]]|$))'

# 形态明确的凭证。只收误报率低的：通用「password = xxx」测试固件里太多，
# 拦它只会让人习惯性绕过。
LEAKSCAN_SECRET='-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|glpat-[A-Za-z0-9_-]{20}|xox[abprs]-[A-Za-z0-9-]{10,}|sk-ant-[A-Za-z0-9_-]{20,}|"private_key_id"[[:space:]]*:[[:space:]]*"[0-9a-f]{20,}|--password[ =][A-Za-z0-9!@#%^&*+/=_.-]{8,}|://[A-Za-z0-9_.-]+:[A-Za-z0-9!%^&*+=_.-]{8,}@'  # leakscan:example

leakscan_dir() {
  cd "$(dirname "${BASH_SOURCE[0]}")" && pwd
}

leakscan_lines() {
  local dir root input hits=0 out
  dir="$(leakscan_dir)"
  root="$(git rev-parse --show-toplevel 2>/dev/null || dirname "$dir")"
  input="$(cat)"
  [ -z "$input" ] && return 0

  report() { # $1 标题  $2 命中行
    [ -z "$2" ] && return
    echo "✗ $1" >&2
    echo "$2" | head -8 | cut -c1-160 | sed 's/^/    /' >&2
    local n; n=$(echo "$2" | wc -l | tr -d ' ')
    [ "$n" -gt 8 ] && echo "    …共 $n 行" >&2
    hits=1
  }

  # 规则只作用于 TAB 之后的文本：位置列里的行号、commit sha、路径不能参与判断
  # （行号 3463 不是「具体数字」，路径里的 dev 也不是「实验室数据」）。
  local T=$'\t'
  txt() { printf '^[^%s]*%s.*(%s)' "$T" "$T" "$1"; }

  local checked
  checked="$(echo "$input" | grep -vE "$(txt 'leakscan:example')" || true)"

  # 1. 地址：白名单之外的点分四段。先剥掉紧跟 / 或 - 的四段数字（Chrome/125.0.0.0 这类版本号）。
  # 地址门禁的测试文件按职责持有「必须被拦下」的合成地址，只在这一项上豁免它。
  out="$(echo "$input" | grep -v 'internal/deploy/no_production_identifiers_test\.go' | sed -E 's#[/-][0-9]{1,3}(\.[0-9]{1,3}){3}##g' | awk -F'\t' '{
      s=$2
      while (match(s, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)) {
        ip=substr(s, RSTART, RLENGTH); s=substr(s, RSTART+RLENGTH)
        n=split(ip, p, "."); ok=1
        for (i=1;i<=4;i++) if (length(p[i])>3) ok=0
        if (ok) print $1 "\t" ip
      }}' | awk -F'\t' '{print $2 "\t" $1}' | grep -vE "$LEAKSCAN_ADDR_OK" | awk -F'\t' '{print $2 ": " $1}' | sort -u || true)"
  report "出现文档白名单之外的 IP 地址（改用 203.0.113.x / 10.0.0.x）：" "$out"

  # 2. 本地字典：真实主机名前缀、域名、项目名、地址段。
  local dict="$root/.production-identifiers"
  if [ -f "$dict" ]; then
    local terms; terms="$(grep -vE '^[[:space:]]*(#|$)' "$dict" | tr -d '\r')"
    if [ -n "$terms" ]; then
      # 条目都是 ASCII；C locale 下 -i 只折叠 ASCII，比 UTF-8 下快一个数量级。
      out="$(echo "$input" | LC_ALL=C grep -iF "$terms" || true)"
      report "命中 .production-identifiers 登记的环境标识：" "$out"
    fi
  fi

  # 3. 来源表述：生产来源标记 + 具体数字。
  out="$(echo "$checked" | grep -iE -f <(grep -vE '^[[:space:]]*(#|$)' "$dir/prod-claim-patterns" \
                                           | while IFS= read -r p; do txt "$p"; echo; done) \
         | grep -E "$(txt "$LEAKSCAN_QTY")" || true)"
  report "「生产来源 + 具体数字」（数字换量级，或删掉来源只留机制）：" "$out"

  # 4. 来源不明的「实测」数字。
  out="$(echo "$checked" | grep -E "$(txt '实测')" | grep -E "$(txt "$LEAKSCAN_QTY")" \
         | grep -viE "$(txt "$LEAKSCAN_LAB")" || true)"
  report "「实测 + 具体数字」且未注明是实验室数据（写明基准/压测/本仓库，或换量级）：" "$out"

  # 5. 组织标识：业务线编号。
  out="$(echo "$checked" | grep -E "$(txt 'G0[0-9]-(UAT|PROD)')" || true)"
  report "出现业务线编号（改用 line-a / host-1 这类中性名）：" "$out"

  # 6. 凭证。
  out="$(echo "$checked" | grep -E -- "$(txt "$LEAKSCAN_SECRET")" | grep -vE '(:|--password[ =])(<|\$\{|\$[A-Z]|\*\*\*|pass(word)?@|x{3,})' || true)"
  report "疑似凭证：" "$out"

  return $hits
}

# 不应出现在公开仓库里的文件路径。
LEAKSCAN_PATHS='(^|/)(local-reports|docs/superpowers)/|(^|/)\.production-identifiers$|(^|/)CLAUDE\.md$|\.(pem|key|p12|pfx|bundle|kubeconfig)$|(^|/)kubeconfig|(^|/)\.env$|(^|/)deploy/backup/.*\.(sql|dump|tsv)(\.gz)?$|\.(sql|tsv)\.gz$|push-approval'

leakscan_paths() { # stdin：一行一个路径
  local out
  out="$(grep -E "$LEAKSCAN_PATHS" || true)"
  if [ -n "$out" ]; then
    echo "✗ 不应进入公开仓库的文件：" >&2
    echo "$out" | head -8 | sed 's/^/    /' >&2
    return 1
  fi
  return 0
}
