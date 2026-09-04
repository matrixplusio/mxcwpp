#!/usr/bin/env bash
#
# 部署后校验：把「这次改动到底生效没有」变成可重复执行的判据。
#
# 为什么是脚本而不是临时敲命令：查询要穿过 ssh → docker exec → 数据库客户端
# 三层，每层都要一次引号转义。转义一旦被吃掉，MySQL 可能返回当前时间而不是
# MAX(updated_at)，造出「镜像每秒都在落后」这种看起来无懈可击的假信号；
# 这时若另一条查询给出矛盾的结果，该追的是那个矛盾。
#
# 这里的每条查询都先落成文件再送进容器执行，不经过嵌套引号。
#
# 用法：
#   MYSQL_PASS=xxx ./scripts/verify-deployment.sh
#
# 环境变量（都有默认值，按需覆盖）：
#   MYSQL_CONTAINER / CH_CONTAINER   数据库容器名
#   MYSQL_USER / MYSQL_PASS / MYSQL_DB
#
# 凭据只从环境读，不写进仓库。生产坐标记在 local-reports/（已 gitignore）。

set -uo pipefail

MYSQL_CONTAINER="${MYSQL_CONTAINER:-mxcwpp-mysql}"
CH_CONTAINER="${CH_CONTAINER:-mxcwpp-clickhouse}"
MYSQL_USER="${MYSQL_USER:-mxcwpp_user}"
MYSQL_DB="${MYSQL_DB:-mxcwpp}"
Q=/tmp/_verify_query.sql

if [ -z "${MYSQL_PASS:-}" ]; then
  echo "需要 MYSQL_PASS。凭据不入库，从环境传入。" >&2
  exit 1
fi

# ch / my：把 $Q 送进容器执行。分成两步而不是一行管道，
# 是为了让「查询内容」和「怎么送进去」互不干扰。
ch() {
  sudo docker cp "$Q" "$CH_CONTAINER:/tmp/q.sql" >/dev/null 2>&1 || return 1
  sudo docker exec "$CH_CONTAINER" sh -c "clickhouse-client --multiquery < /tmp/q.sql" 2>&1
}
my() {
  sudo docker cp "$Q" "$MYSQL_CONTAINER:/tmp/q.sql" >/dev/null 2>&1 || return 1
  sudo docker exec "$MYSQL_CONTAINER" sh -c \
    "mysql -u$MYSQL_USER -p$MYSQL_PASS $MYSQL_DB -t < /tmp/q.sql" 2>/dev/null
}

section() { printf '\n── %s\n   判据：%s\n' "$1" "$2"; }

echo "=== 部署校验 $(date '+%F %H:%M:%S') ==="

# ---------------------------------------------------------------------------
section "ClickHouse 写入批次" \
  "看写入量大的那几个小时：rows_per_part 远大于 1。低流量小时天然接近 1（攒批按时间冲刷，两行相隔够久就各成一批），只有峰值小时能说明问题"
cat > "$Q" <<'Q1'
SELECT toHour(event_time) AS h, count() AS parts, sum(rows) AS rws,
       round(sum(rows)/count(), 1) AS rows_per_part
FROM system.part_log
WHERE event_date = today() AND event_type = 'NewPart'
  AND table IN ('host_vulnerabilities', 'alerts', 'vulnerabilities')
GROUP BY h ORDER BY h FORMAT PrettyCompact;
Q1
ch

# 写入是周期性的：波次之间整小时没有写入是正常的。
# 判断「有没有停」之前先确认此刻本该有写入——2026-09-04 的误判正出在这一步。
section "写入相位" \
  "先看上面哪些小时有写入。空白小时属于波次间隙，不是故障"

# ---------------------------------------------------------------------------
section "FIM 是否还在复读" \
  "events 与 files 应显著低于修复前。数字每天几乎一样，说明报的不是新变更"
cat > "$Q" <<'Q2'
SELECT DATE(detected_at) AS d, COUNT(*) AS events, COUNT(DISTINCT file_path) AS files
FROM fim_events WHERE detected_at > DATE_SUB(NOW(), INTERVAL 4 DAY)
GROUP BY d ORDER BY d DESC;
SELECT status, COUNT(*) AS c FROM fim_events GROUP BY status;
Q2
my

section "FIM 基线是否被并入" \
  "advanced 应大于 0。全是 version=1 表示基线从未更新过，那就是复读的成因"
cat > "$Q" <<'Q3'
SELECT COUNT(*) AS baselines, SUM(version > 1) AS advanced, MAX(version) AS max_ver
FROM fim_baselines;
Q3
my

# ---------------------------------------------------------------------------
section "资产表是否只增不减" \
  "per_host 应是该类资产的真实量级。进程上万说明退出的进程没被清理，答案本身是错的"
cat > "$Q" <<'Q4'
SELECT 'processes' AS t, COUNT(*) AS c,
       ROUND(COUNT(*)/NULLIF(COUNT(DISTINCT host_id), 0)) AS per_host FROM processes
UNION ALL
SELECT 'ports', COUNT(*), ROUND(COUNT(*)/NULLIF(COUNT(DISTINCT host_id), 0)) FROM ports;
Q4
my

# ---------------------------------------------------------------------------
# DLQ 是 Kafka topic，数据库里查不到，只能数 consumer 的日志。
# 读容器内的落盘日志而不是 docker logs：后者只有当前容器生命周期的内容，
# 重建一次就看不到昨天，而这类问题恰恰要按天比才看得出是不是长期存在。
# 本段需要在跑 consumer 的节点上执行；数据库若在别的节点，两处分别跑。
section "写入失败转 DLQ" \
  "同一类错误天天出现，说明有一批消息永远处理不了。容器 healthy 看不出这件事"
CONSUMER_CONTAINER="${CONSUMER_CONTAINER:-mxcwpp-control-consumer-1}"
if sudo docker ps --format '{{.Names}}' | grep -qx "$CONSUMER_CONTAINER"; then
  sudo docker exec "$CONSUMER_CONTAINER" sh -c '
    for f in /var/log/mxcwpp/server.log.*; do
      [ -f "$f" ] || continue
      n=$(grep -c "转入 DLQ" "$f" 2>/dev/null || echo 0)
      [ "$n" != "0" ] && echo "    $(basename "$f")  $n 条"
    done
    echo "  失败原因（今天，前 3 种）："
    grep "转入 DLQ" /var/log/mxcwpp/server.log 2>/dev/null |
      sed -n "s/.*\"error\":\"\([^\"]*\)\".*/    \1/p" |
      sed "s/[0-9]\{4,\}/<id>/g" | sort | uniq -c | sort -rn | head -3
  ' 2>/dev/null || echo "    读取失败"
else
  echo "  未找到容器 $CONSUMER_CONTAINER（它可能在另一个节点），跳过"
fi

echo
echo "注：判断任何一项「停了」之前，先确认它此刻本该在动。"
echo "    周期性负载在间隙期不动是常态，把间隙读成故障会导致误回滚。"
