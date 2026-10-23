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
# 事故叙事与环境描述：不带数字也拦。这些说法只会出现在「我们的环境里发生过什么」的语境里，
# 写机制时用不到它们（写机制用「会」「可能」，不用「曾」「当时」）。
LEAKSCAN_NARRATIVE='实机|曾因此|无人发现|拖垮(整个)?平台|平台停摆|生产实证'  # leakscan:example

# 不带年份的月-日加事件：「3-14、3-15 两台新装主机……」这种复盘。带年份的日期加事故  # leakscan:example
# 由 prod-claim-patterns 覆盖；只有日期、没有事件的（如版本号、示例时间）不拦。
LEAKSCAN_MMDD='(^|[^0-9.:-])(1[0-2]|0?[1-9])-(0[1-9]|[12][0-9]|3[01])([^0-9:]|$)'
LEAKSCAN_MMDD_EVENT='、[0-9]|两台|那次|当时|事故|上线后|被拒|漏掉|丢了|挂了|爆盘|就因为|上传时|那天'

# 规模与「曾」字叙事：不带「生产」字样，但只会出自对真实环境的观察。写机制时用「大量」「很多」
# 「随规模增长」，不用具体的规模档位。
LEAKSCAN_SCALE='(几|十几|几十|上|近|数)(十|百|千)台|近十万|十几万|几十万|数十万|[一二两三四五六七八九]百多万|上万条|几千个|几万次|上百次|千万级|亿级|数万行|几百条|[一二两三四五六七八九]千多次|连续失败数月|持续数小时|实测出现过|线上实际|实际日志'  # leakscan:example

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

  # 2. 本地字典：真实主机名前缀、域名、项目名、地址段、业务线编号格式。
  # 普通行按字面量匹配；「re:」开头的行是正则（ERE，不区分大小写）——编号格式这类规律
  # 写进公开仓库本身就是泄露，所以和字面量一样只放本地。「path:」行给 leakscan_paths 用。
  # LEAKSCAN_DICT 只给测试用。
  local dict="${LEAKSCAN_DICT:-$root/.production-identifiers}"
  if [ -f "$dict" ]; then
    local terms res
    terms="$(grep -vE '^[[:space:]]*(#|$|re:|path:)' "$dict" | tr -d '\r')"
    res="$(grep -E '^re:' "$dict" | sed 's/^re://' | tr -d '\r')"
    if [ -n "$terms" ]; then
      # 条目都是 ASCII；C locale 下 -i 只折叠 ASCII，比 UTF-8 下快一个数量级。
      out="$(echo "$input" | LC_ALL=C grep -iF "$terms" || true)"
      report "命中 .production-identifiers 登记的环境标识：" "$out"
    fi
    if [ -n "$res" ]; then
      out="$(echo "$input" | awk -F'\t' '{print $2 "\t" $1}' | grep -iE -f <(echo "$res") | awk -F'\t' '{print $2 "\t" $1}' || true)"
      report "命中 .production-identifiers 登记的环境标识（正则）：" "$out"
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

  # 5. 事故叙事与环境描述（不要求数字）。
  out="$(echo "$checked" | grep -E "$(txt "$LEAKSCAN_NARRATIVE")" || true)"
  report "事故叙事或环境描述（只写机制：「会」「可能」，不写「曾」「当时」与我们环境里的经过）：" "$out"

  # 5a. 规模档位与「曾」字叙事。
  out="$(echo "$checked" | grep -E "$(txt "$LEAKSCAN_SCALE")" || true)"
  report "规模档位或「曾」字叙事（改成「大量」「随规模增长」这类机制写法）：" "$out"

  # 5b. 不带年份的日期 + 事件。
  out="$(echo "$checked" | grep -E "$(txt "$LEAKSCAN_MMDD")" | grep -E "$(txt "$LEAKSCAN_MMDD_EVENT")" || true)"
  report "日期加事件的复盘（删掉日期与经过，只留机制）：" "$out"

  # 6. 凭证。
  out="$(echo "$checked" | grep -E -- "$(txt "$LEAKSCAN_SECRET")" | grep -vE '(:|--password[ =])(<|\$\{|\$[A-Z]|\*\*\*|pass(word)?@|x{3,})' || true)"
  report "疑似凭证：" "$out"

  return $hits
}

# 不应出现在公开仓库里的文件路径。本地私有文档的路径写在本地字典的「path:」行（ERE），不写在这里。
LEAKSCAN_PATHS='(^|/)local-reports/|(^|/)\.production-identifiers$|\.(pem|key|p12|pfx|bundle|kubeconfig)$|(^|/)kubeconfig|(^|/)\.env$|(^|/)deploy/backup/.*\.(sql|dump|tsv)(\.gz)?$|\.(sql|tsv)\.gz$|push-approval'

leakscan_paths() { # stdin：一行一个路径
  local out pat="$LEAKSCAN_PATHS" root dict extra
  root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
  dict="${LEAKSCAN_DICT:-$root/.production-identifiers}"
  if [ -f "$dict" ]; then
    extra="$(grep -E '^path:' "$dict" | sed 's/^path://' | tr -d '\r' | paste -sd'|' -)"
    [ -n "$extra" ] && pat="$pat|$extra"
  fi
  out="$(grep -E "$pat" || true)"
  if [ -n "$out" ]; then
    echo "✗ 不应进入公开仓库的文件：" >&2
    echo "$out" | head -8 | sed 's/^/    /' >&2
    return 1
  fi
  return 0
}

# 逐提交扫描：参数原样交给 git log（如 A..B、<sha> --not --remotes=origin）。
# 扫每个提交的新增行、作者、提交信息与新增路径——中间提交加了、后面又删掉的内容一样会公开。
# pre-push、CI 与远端体检共用。
leakscan_commits() {
  local rc=0
  git log --no-color --no-ext-diff -p -U0 --format='@@@COMMIT %h%n%an <%ae> / %cn <%ce>%n%B@@@END' "$@" \
    | awk '/^@@@COMMIT /{h=$2; msg=1; next}
           /^@@@END$/{msg=0; next}
           msg{print h " message\t" $0; next}
           /^\+\+\+ b\//{f=substr($0,7); next}
           /^\+/ && !/^\+\+\+/{print h " " f "\t" substr($0,2)}' \
    | leakscan_lines || rc=1
  git log --no-color --format= --name-only --diff-filter=A "$@" | sort -u | sed '/^$/d' \
    | leakscan_paths || rc=1
  return $rc
}

# 附注 tag 的说明文字（tag 对象本身，不含它指向的提交）。轻量 tag 没有说明，直接通过。
leakscan_tag() { # $1 tag 对象或引用
  [ "$(git cat-file -t "$1" 2>/dev/null)" = "tag" ] || return 0
  git cat-file -p "$1" | sed '1,/^$/d' | awk -v t="tag:$1" '{print t "\t" $0}' | leakscan_lines
}
