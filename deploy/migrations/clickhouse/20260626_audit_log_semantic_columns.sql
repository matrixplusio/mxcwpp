-- Migration: audit_log 表补充语义审计列
-- Date: 2026-06-26
-- 适用对象: 存量 ClickHouse 集群（init-clickhouse.sql 只在首次部署执行）
--
-- 背景:
--   操作审计升级到商业级（等保2.0/SOC2/ISO27001）：
--   旧 schema 仅 timestamp/user_id/action/resource/detail/ip，action 存 HTTP 方法、
--   缺参与方类型、结果、资源可读名、变更详情等。
--
-- 方案（additive，零破坏）:
--   保留旧列 user_id/resource/detail，新增离散语义列；
--   ADD COLUMN 仅改元数据，秒级完成，不重写历史数据（缺省值按 DEFAULT 返回）。
--
-- 执行:
--   clickhouse-client --host=<ch-host> --user=default --password=<pwd> --database=mxcwpp < 20260626_audit_log_semantic_columns.sql

ALTER TABLE mxcwpp.audit_log ADD COLUMN IF NOT EXISTS actor_type    LowCardinality(String) DEFAULT 'user'    AFTER user_id;
ALTER TABLE mxcwpp.audit_log ADD COLUMN IF NOT EXISTS outcome       LowCardinality(String) DEFAULT 'success' AFTER action;
ALTER TABLE mxcwpp.audit_log ADD COLUMN IF NOT EXISTS resource_type LowCardinality(String) DEFAULT ''        AFTER resource;
ALTER TABLE mxcwpp.audit_log ADD COLUMN IF NOT EXISTS resource_id   String DEFAULT ''                        AFTER resource_type;
ALTER TABLE mxcwpp.audit_log ADD COLUMN IF NOT EXISTS target_name   String DEFAULT ''                        AFTER resource_id;
ALTER TABLE mxcwpp.audit_log ADD COLUMN IF NOT EXISTS path          String DEFAULT ''                        AFTER target_name;
ALTER TABLE mxcwpp.audit_log ADD COLUMN IF NOT EXISTS status_code   Int32  DEFAULT 0                          AFTER path;
ALTER TABLE mxcwpp.audit_log ADD COLUMN IF NOT EXISTS change_detail String DEFAULT ''                        AFTER detail;
