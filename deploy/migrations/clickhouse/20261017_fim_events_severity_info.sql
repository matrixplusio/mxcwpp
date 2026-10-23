-- Migration: fim_events.severity 枚举补上 info
-- Date: 2026-10-17
-- 适用对象: 存量 ClickHouse 集群（init-clickhouse.sql 只在首次部署执行）
--
-- 背景:
--   fim 插件 1.0.2 起把与包数据库一致的变更（包管理器写入）标成 info。旧表的枚举没有
--   这个值，含 info 的整批写入被拒，同批的 critical 变更一起丢失。
--
-- 方案:
--   只在枚举里加一个值，属元数据变更，秒级完成，不重写历史数据。
--   consumer 启动时也会执行同一条语句（ensureSchemas），这里供手工补齐与审计留档。
--
-- 执行:
--   clickhouse-client --host=<ch-host> --user=default --password=<pwd> --database=mxcwpp < 20261017_fim_events_severity_info.sql

ALTER TABLE mxcwpp.fim_events MODIFY COLUMN IF EXISTS severity Enum8('info'=0, 'low'=1, 'medium'=2, 'high'=3, 'critical'=4);
