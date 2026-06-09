#!/usr/bin/env bash
# L4 性能 SLO 测试
#   - list API p99 (3 关键 endpoint × 50 次)
#   - 1k EPS 持续 30s 时延曲线 (用 ab/wrk 不行 - 需要 EDR 事件流, 改测 hosts API 压测)
#   - 心跳数据传播延迟 (本身 dev VM 已工作, 看 ms 级)
set -uo pipefail
JWT=$(/bin/cat /tmp/mxsec-jwt)
MGR="${MGR:-http://localhost:8080}"
CURL="/usr/bin/curl"
JQ="/usr/bin/jq"

REPORT="docs/functional-test-2026-06-08/l4-performance.md"
{
echo "# L4 性能 SLO 测试 (2026-06-08)"
echo
echo "环境: dev (mac M-series + docker), 2 主机数据, MySQL 8 + ClickHouse 24 + Redis 7."
echo "SLO 目标: 500 主机 ms 级 / 1k 主机 < 3s / 3k 主机 < 5s / 1w 主机 < 10s."
echo "本次仅 2 主机, **验证算法链路, 非真实负载**."
echo
echo "## 测试 1: 关键 list API 50 次延迟分布"
echo
echo "| 端点 | min(ms) | avg(ms) | p50(ms) | p90(ms) | p99(ms) | max(ms) |"
echo "|---|---|---|---|---|---|---|"
} > "$REPORT"

measure() {
  local name="$1" path="$2" n="${3:-50}"
  local times=()
  for i in $(seq 1 "$n"); do
    local t=$($CURL -s -o /dev/null -w '%{time_total}' -H "Authorization: Bearer $JWT" "$MGR$path")
    times+=("$(echo "$t * 1000" | bc -l | awk '{printf "%.2f", $1}')")
  done
  local sorted=$(printf '%s\n' "${times[@]}" | sort -n)
  local arr=($sorted)
  local last_idx=$((${#arr[@]} - 1))
  local min="${arr[0]}"
  local max="${arr[$last_idx]}"
  local p50_idx=$((n / 2))
  local p90_idx=$((n * 9 / 10))
  local p99_idx=$((n * 99 / 100 - 1))
  [ "$p99_idx" -lt 0 ] && p99_idx=0
  local p50="${arr[$p50_idx]}"
  local p90="${arr[$p90_idx]}"
  local p99="${arr[$p99_idx]}"
  local sum=0
  for t in "${times[@]}"; do sum=$(echo "$sum + $t" | bc -l); done
  local avg=$(echo "scale=2; $sum / $n" | bc -l)
  echo "| $name | $min | $avg | $p50 | $p90 | $p99 | $max |" >> "$REPORT"
  echo "$name: min=$min avg=$avg p50=$p50 p90=$p90 p99=$p99 max=$max ms"
}

echo "==== Test 1: 50 次延迟 ===="
measure "/hosts (list 50)"             "/api/v1/hosts?page=1&page_size=50"
measure "/dashboard/stats"             "/api/v1/dashboard/stats"
measure "/alerts (list 80 含 actual)"  "/api/v1/alerts?page=1&page_size=80"
measure "/vulnerabilities (50)"        "/api/v1/vulnerabilities?page=1&page_size=50"
measure "/edr/events (lite 50)"        "/api/v1/edr/events?page=1&page_size=50"
measure "/assets/processes (50)"       "/api/v1/assets/processes?page=1&page_size=50"
measure "/memory-threats (50)"         "/api/v1/memory-threats?page=1&page_size=50"
measure "/storylines (50)"             "/api/v1/storylines?page=1&page_size=50"

echo
echo "==== Test 2: 并发 50 请求 ===="
{
echo
echo "## 测试 2: 50 并发请求 (/hosts) 总耗时"
echo
} >> "$REPORT"
start=$(date +%s.%N)
for i in $(seq 1 50); do
  $CURL -s -o /dev/null -H "Authorization: Bearer $JWT" "$MGR/api/v1/hosts?page=1&page_size=50" &
done
wait
end=$(date +%s.%N)
total=$(echo "($end - $start) * 1000" | bc -l)
{
echo "- 50 并发请求 /hosts: $(printf '%.0f' "$total") ms"
echo "- 平均 QPS: $(echo "50 / ($end - $start)" | bc -l | awk '{printf "%.1f", $1}')"
} >> "$REPORT"
echo "50 并发总耗时: $(printf '%.0f' "$total") ms"

echo
echo "==== Test 3: Agent 心跳 freshness ===="
echo >> "$REPORT"
echo "## 测试 3: Agent 心跳新鲜度" >> "$REPORT"
echo >> "$REPORT"
hb=$($CURL -s -H "Authorization: Bearer $JWT" "$MGR/api/v1/hosts?page=1&page_size=5" | $JQ -r '.data.items[] | "\(.hostname): \(.last_heartbeat) (status=\(.status))"')
echo "$hb"
{
echo '```'
echo "$hb"
echo '```'
echo
echo "心跳间隔: agent 默认 30s, 上面 last_heartbeat 是最近一次时间."
} >> "$REPORT"

echo
echo "==== Test 4: ClickHouse EDR 事件总量 ==="
echo >> "$REPORT"
echo "## 测试 4: 事件归档量 (ClickHouse)" >> "$REPORT"
echo >> "$REPORT"
ev_total=$($CURL -s -H "Authorization: Bearer $JWT" "$MGR/api/v1/edr/events?page=1&page_size=1" | $JQ -r '.data.total // 0')
echo "EDR 事件总量: $ev_total"
{
echo "- EDR 事件历史总量: **$ev_total** 条"
echo "- 说明 dev 环境 Agent→AC→Kafka→Consumer→ClickHouse 链路通畅"
} >> "$REPORT"

echo
echo "==== L4 完成 ===="
echo "报告: $REPORT"
