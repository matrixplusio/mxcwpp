# EDR 查询性能调优手册

> 适用版本: 2.6.0-beta.20260604+
> 关联 PR: `kerbos/perf-edr-projection` / `kerbos/feat-anomaly-trigger-context` / `kerbos/feat-edr-loading-ux`

---

## 1. 性能基线（商业级 SLO）

| 场景 | 目标 P95 | 兜底超时 |
|---|---|---|
| EDR 列表（无过滤，最近 24h） | < 100ms | 60s |
| EDR 列表 + host_id 过滤 | < 200ms | 60s |
| EDR 列表 + 关键词 (exe/cmdline LIKE) | < 500ms | 60s |
| EDR 统计（24h 趋势 + Top） | < 1s | 60s |
| 异常告警 enrichTriggerContext 回查 | < 200ms | 3s |
| count() 全量 | < 50ms | 60s |

---

## 2. ClickHouse Schema 关键决策

### 2.1 `ebpf_events` 主键 + Projection

```sql
ORDER BY (host_id, timestamp)         -- 单 host 时间扫描快
PROJECTION proj_time_desc (             -- 全局时间排序快路径
    SELECT * ORDER BY timestamp
)
```

**为什么需要 projection**：

主键 `(host_id, timestamp)` 在 part 内按 host_id 排序后再按 timestamp 排序。`ORDER BY timestamp DESC LIMIT N` 无法反向利用复合主键 → 必须扫描所有 part 后排序，1 亿+ 行规模 >10s。

`proj_time_desc` 维护一份按 timestamp 排序的列存副本。`ORDER BY timestamp [ASC|DESC]` 自动选择此 projection，主键反向扫即得 → LIMIT 50 < 100ms。

**存储成本**：双倍。482M 行 / 5.78 GiB → ~12 GiB。

### 2.2 Bloom / TokenBF 索引

```sql
INDEX idx_exe         exe          TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4
INDEX idx_cmdline     cmdline      TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4
INDEX idx_file_path   file_path    TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4
INDEX idx_remote_addr remote_addr  TYPE bloom_filter(0.01)      GRANULARITY 4
```

加速模糊查询 `exe LIKE '%X%'`。命中后跳过整个 granule（8192 行）。

### 2.3 分区 + TTL

```sql
PARTITION BY toYYYYMMDD(timestamp)
TTL toDateTime(timestamp) + INTERVAL 30 DAY
```

日分区让时间窗 WHERE 走 partition pruning。30d TTL 自动删历史，稳态数据量可控。

---

## 3. 容量规划（2026-06-04 基线）

### 3.1 当前数据规模

| 指标 | 值 |
|---|---|
| 活跃 host 数 | 221 |
| 平均 EPS | ~830 events/sec |
| 日入库 rows | ~68M |
| 日入库 raw 大小估算 | ~14 GiB |
| 日入库压缩后 | ~825 MiB |
| 7d 累积 rows | 482M |
| 7d 压缩磁盘 | 5.78 GiB |
| **30d 稳态（推算）** | **~2.06B rows / ~25 GiB** |

### 3.2 3 节点资源现状

| 节点 | CPU | RAM | Disk | Load |
|---|---|---|---|---|
| node1 control | 8c | 31G (used 12%) | 200G (used 47%) | 1.0 |
| node2 storage | 8c | 31G (used 24%) | **500G (used 8%)** | 0.93 |
| node3 kafka | 4c | 15G (used 22%) | 200G (used **58%** = 107G) | 0.78 |

### 3.3 容量预估（按当前增长率，host 数翻 X 倍）

| host 规模 | EPS | CH 30d 稳态 | CH disk 占用 | Kafka disk 占用 | 瓶颈节点 | 撑多久 |
|---|---|---|---|---|---|---|
| 221（当前） | 830 | 25 GiB | 5% | 54% | Kafka | 不卡 |
| 500 (×2.3) | 1900 | 58 GiB | 12% | ~120% ❌ | **Kafka 满** | 立即扩 |
| 1000 (×4.5) | 3700 | 115 GiB | 23% | — | Kafka 必须扩 | — |
| 2000 (×9) | 7400 | 230 GiB | 46% | — | CH 也吃紧 | — |

**结论（按当前 221 host 业务规模）**：

- **CH 存储**：稳态 25 GiB / 500G = 5%，**可撑数年**（仅受 30d TTL 限制，新增即旧出）
- **CH 内存**：3.5 GB RSS / 31 GB，余量大，可启用 8GB `uncompressed_cache_size` 进一步加速
- **CH CPU**：8.49% 平均，余量大
- **node3 Kafka disk**：107G / 200G = 58%，**3 副本 × 7d retention 已稳态**。host 数 ×2 时溢出，**优先扩盘到 500G**
- **node3 RAM**：15G 小，3 broker 共用，host 数 ×3 时可能吃紧

**预警阈值**:

- Kafka disk > 75% → 扩盘
- CH disk > 30% → 评估 TTL 缩短或扩盘
- node3 RAM available < 3G → 加内存

---

## 4. 存量 ClickHouse 集群 Migration

新部署用 `deploy/init-clickhouse.sql` 自动建表。已有 prod 集群需手动应用：

```bash
# 1. ssh 上 control 节点（mxctl 所在）
ssh devops@<prod-host>

# 2. 用 server.yaml 的 CH 凭据执行 migration
CH_PWD=$(sudo grep -A1 'clickhouse:' /opt/mxcwpp/current/config/server.yaml | grep password | awk '{print $2}')

# 3. 应用 projection（秒级完成）
curl -u default:$CH_PWD 'http://<storage-ip>:8123/?database=mxcwpp' \
    --data-binary 'ALTER TABLE ebpf_events ADD PROJECTION IF NOT EXISTS proj_time_desc (SELECT * ORDER BY timestamp)'

# 4. MATERIALIZE 历史数据（IO 密集，3-15 分钟，不阻塞读写）
curl -u default:$CH_PWD 'http://<storage-ip>:8123/?database=mxcwpp' \
    --data-binary 'ALTER TABLE ebpf_events MATERIALIZE PROJECTION proj_time_desc'

# 5. 监控进度
watch -n 5 "curl -s -u default:\$CH_PWD 'http://<storage-ip>:8123/?database=mxcwpp' \
    --data-binary \"SELECT table, parts_to_do, is_done FROM system.mutations \
    WHERE table='ebpf_events' AND not is_done ORDER BY create_time DESC\""

# 6. 失败回滚
curl -u default:$CH_PWD 'http://<storage-ip>:8123/?database=mxcwpp' \
    --data-binary 'ALTER TABLE ebpf_events DROP PROJECTION proj_time_desc'
# 原表数据零损失
```

---

## 5. 慢查询排查 Checklist

当 Prometheus 触发 `MxCwppCHQuerySlow` / `MxCwppCHQueryTimeout` 告警：

1. **看是否命中 projection**

   ```sql
   EXPLAIN PIPELINE
   SELECT * FROM ebpf_events
   WHERE timestamp >= now() - INTERVAL 24 HOUR
   ORDER BY timestamp DESC LIMIT 50;
   ```

   pipeline 含 `proj_time_desc` 节点 = 命中。否则查 projection 是否还在 materialize 或被 DROP。

2. **part 数过多（merge backlog）**

   ```sql
   SELECT table, count() AS parts FROM system.parts
   WHERE active AND database='mxcwpp' AND table='ebpf_events'
   GROUP BY table;
   ```

   > 150 parts 触发 merge 压力，可能拖慢查询。检查 consumer 写入批次大小（`clickhouse.batch_size`）是否太小。

3. **后台 mutation 卡住**

   ```sql
   SELECT * FROM system.mutations WHERE not is_done ORDER BY create_time DESC LIMIT 10;
   ```

   `latest_fail_reason` 非空说明 MATERIALIZE 失败，需手工干预。

4. **CH 进程资源**

   ```sql
   SELECT metric, value FROM system.events WHERE metric IN
     ('SelectQuery','QueryTimeMicroseconds','MergedRows','InsertedRows');
   ```

   或 `docker stats mxcwpp-clickhouse` 看 CPU/MEM 是否飙升。

5. **前端 date_to 是日期未带时分秒**

   后端会拼 `dateTo + " 23:59:59"`，可能造成 2 天窗口。验证前端已升级到 2.6.0-beta.20260604+（`feat(edr-ui): 默认 24h 精确窗口` commit）。

---

## 6. 关联代码

| 改动 | 位置 |
|---|---|
| ctx + max_execution_time + rows.Err + 慢查询 metric | `internal/server/manager/api/edr_events.go` |
| Prom histogram `mxcwpp_clickhouse_query_duration_seconds` | `internal/server/metrics/metrics.go` |
| Projection 表定义（新部署） | `deploy/init-clickhouse.sql` |
| 存量集群 migration | `deploy/migrations/clickhouse/20260604_ebpf_events_projection.sql` |
| 异常告警 trigger_context 回查 | `internal/server/consumer/anomaly/detector.go` |
| 慢查询/超时/错误率告警规则 | `deploy/config/prometheus-rules.yml` (group `mxcwpp_clickhouse`) |
| 前端 24h 默认 + 长查询 cancel | `ui/src/views/EDR/Events/index.vue` |
