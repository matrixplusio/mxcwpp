-- Migration: 为 ebpf_events 表添加 proj_time_desc projection
-- Date: 2026-06-04
-- 适用对象: 存量 ClickHouse 集群（init-clickhouse.sql 只在首次部署执行）
--
-- 背景:
--   ebpf_events 主键 ORDER BY (host_id, timestamp)
--   业务主路径 SQL: SELECT ... WHERE timestamp BETWEEN ... ORDER BY timestamp DESC LIMIT N
--   DESC 无法反向利用复合主键，触发全 part 扫描 + 归并排序
--   1.18 亿行规模下 LIMIT 50 > 10s（实测）
--
-- 解决方案:
--   Projection proj_time_desc 维护一份按 timestamp 排序的列存副本
--   ORDER BY timestamp [DESC] 自动选择此 projection，主键反向扫描
--   预期 LIMIT 50 < 100ms（P99 < 200ms）
--
-- 注意事项:
--   1. ADD PROJECTION 仅声明结构，秒级完成，不动现有数据
--   2. MATERIALIZE PROJECTION 是 IO 密集操作，后台异步执行，不阻塞读写
--      482M 行 / 5.78 GiB 预计 3-15 分钟（取决于 IO 带宽）
--   3. 存储成本：约翻倍（5.78 GiB → ~12 GiB），node2 disk 500GB / 8% used 充裕
--   4. 失败可直接 DROP PROJECTION proj_time_desc，原表数据零损失
--   5. 历史 part 完成 MATERIALIZE 后，新写入自动维护 projection
--
-- 执行步骤:
--   clickhouse-client --host=10.170.3.3 --user=default --password=<pwd> --database=mxcwpp < 20260604_ebpf_events_projection.sql
--
-- 观察 materialize 进度:
--   SELECT table, name, parts_to_do, is_done, latest_fail_reason
--   FROM system.mutations WHERE table='ebpf_events' AND not is_done ORDER BY create_time DESC;

ALTER TABLE mxcwpp.ebpf_events
ADD PROJECTION IF NOT EXISTS proj_time_desc (
    SELECT *
    ORDER BY timestamp
);

ALTER TABLE mxcwpp.ebpf_events
MATERIALIZE PROJECTION proj_time_desc;
