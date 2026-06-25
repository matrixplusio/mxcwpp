-- MxCwpp Platform - ClickHouse 初始化 DDL
-- 对应设计文档: docs/design/ha-architecture.md § 3.4.2

-- 显式建库并切入：docker initdb 脚本默认在 default 库执行，
-- 若不 USE，下面所有 CREATE TABLE 会落到 default 而非 mxcwpp，
-- 导致 consumer 写 mxcwpp.* 报 "table does not exist"。
CREATE DATABASE IF NOT EXISTS mxcwpp;
USE mxcwpp;

-- ==================== 主机监控指标 ====================

CREATE TABLE IF NOT EXISTS host_metrics (
    timestamp        DateTime64(3),
    host_id          String,
    hostname         String,
    cpu_usage        Float32,
    mem_usage        Float32,
    disk_usage       Float32,
    load_1           Float32,
    load_5           Float32,
    load_15          Float32,
    net_in           UInt64,
    net_out          UInt64,
    disk_read_bytes  UInt64,
    disk_write_bytes UInt64
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (host_id, timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- 小时级预聚合物化视图（Dashboard 趋势图查询，避免全表扫描）
CREATE MATERIALIZED VIEW IF NOT EXISTS host_metrics_hourly
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(hour)
ORDER BY (host_id, hour)
TTL toDateTime(hour) + INTERVAL 365 DAY
AS SELECT
    host_id,
    toStartOfHour(timestamp)      AS hour,
    avgState(cpu_usage)           AS cpu_avg,
    maxState(cpu_usage)           AS cpu_max,
    avgState(mem_usage)           AS mem_avg,
    maxState(mem_usage)           AS mem_max,
    avgState(disk_usage)          AS disk_avg,
    maxState(load_1)              AS load_max,
    sumState(net_in)              AS net_in_total,
    sumState(net_out)             AS net_out_total,
    sumState(disk_read_bytes)     AS disk_read_total,
    sumState(disk_write_bytes)    AS disk_write_total
FROM host_metrics
GROUP BY host_id, hour;

-- ==================== FIM 文件变更事件 ====================

CREATE TABLE IF NOT EXISTS fim_events (
    timestamp     DateTime64(3),
    host_id       String,
    hostname      String,
    file_path     String,
    change_type   Enum8('added'=1, 'removed'=2, 'changed'=3),
    severity      Enum8('low'=1, 'medium'=2, 'high'=3, 'critical'=4),
    category      LowCardinality(String),
    detail        String,
    trace_id      String
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (host_id, timestamp)
TTL toDateTime(timestamp) + INTERVAL 180 DAY
SETTINGS index_granularity = 8192;

-- ==================== 基线扫描结果历史归档 ====================
-- ORDER BY 包含 timestamp，支持时间范围查询

CREATE TABLE IF NOT EXISTS scan_results_history (
    timestamp   DateTime64(3),
    task_id     String,
    host_id     String,
    rule_id     String,
    status      Enum8('pass'=1, 'fail'=2, 'error'=3, 'na'=4),
    actual      String,
    expected    String,
    trace_id    String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (host_id, timestamp, task_id, rule_id)
TTL toDateTime(timestamp) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ==================== 告警事件明细 ====================
-- ReplacingMergeTree(updated_at) 支持状态更新去重（保留最新版本）

CREATE TABLE IF NOT EXISTS alert_events (
    timestamp     DateTime64(3),
    alert_id      String,
    host_id       String,
    hostname      String,
    alert_type    LowCardinality(String),
    severity      Enum8('low'=1, 'medium'=2, 'high'=3, 'critical'=4),
    source        LowCardinality(String),
    detail        String,
    status        LowCardinality(String),
    updated_at    DateTime64(3),
    trace_id      String
) ENGINE = ReplacingMergeTree(updated_at)
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (host_id, alert_id)
TTL toDateTime(timestamp) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ==================== eBPF 实时事件 ====================

CREATE TABLE IF NOT EXISTS ebpf_events (
    timestamp     DateTime64(3),
    host_id       String,
    hostname      String,
    event_type    LowCardinality(String),   -- process_exec, file_open, file_write, file_read, tcp_connect, tcp_close
    data_type     Int32,                     -- 3000=进程, 3001=文件, 3002=网络
    pid           String,
    ppid          String,
    exe           String,
    cmdline       String,
    parent_exe    String,
    file_path     String,
    remote_addr   String,
    remote_port   String,
    local_addr    String,
    local_port    String,
    protocol      LowCardinality(String),
    uid           String,
    gid           String,
    return_code   String,

    -- 跳数索引：加速 exe / cmdline / remote_addr 模糊查询
    INDEX idx_exe exe TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4,
    INDEX idx_cmdline cmdline TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4,
    INDEX idx_remote_addr remote_addr TYPE bloom_filter(0.01) GRANULARITY 4,
    INDEX idx_file_path file_path TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4,

    -- Projection: 主键 (host_id, timestamp) 导致 ORDER BY timestamp DESC LIMIT N 无法反向利用主键，
    -- 在 1 亿+ 行规模上触发全表排序（>10s）。proj_time_desc 维护一份按 timestamp 排序的副本，
    -- 让 ORDER BY timestamp [DESC] 走主键反向扫 → LIMIT 50 < 100ms。
    -- 存储成本：双倍（5.78 GiB → ~12 GiB，500GB disk 完全可承受）。
    PROJECTION proj_time_desc (
        SELECT *
        ORDER BY timestamp
    )
) ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (host_id, timestamp)
TTL toDateTime(timestamp) + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- ==================== 审计日志 ====================

CREATE TABLE IF NOT EXISTS audit_log (
    timestamp   DateTime64(3),
    user_id     String,
    action      LowCardinality(String),
    resource    String,
    detail      String,
    ip          String
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (timestamp)
TTL toDateTime(timestamp) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ==================== 攻击故事线事件 ====================
-- MySQL → CH 迁移试点 (2026-05-28)
-- 原 storyline_events MySQL 表 660w 行 / 1.8GB，错配。
-- 查询场景: 单 story_id + 时间范围 (详情页) / 按时间窗聚合 (报告)
-- ORDER BY (story_id, timestamp) 保证主键命中毫秒级
-- detail 列加 bloom_filter 索引加速全文搜索

CREATE TABLE IF NOT EXISTS storyline_events (
    id            UInt64,
    story_id      String,
    host_id       String,
    data_type     Int32,
    event_type    LowCardinality(String),
    pid           String,
    exe           String,
    detail        String,
    rule_name     LowCardinality(String),
    severity      LowCardinality(String),
    timestamp     DateTime64(3),
    created_at    DateTime64(3),
    INDEX idx_detail detail TYPE tokenbf_v1(1024, 3, 0) GRANULARITY 4
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (story_id, timestamp)
TTL toDateTime(timestamp) + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- 按 story_id 聚合的物化视图（详情页快速 count / 跨度统计）
CREATE MATERIALIZED VIEW IF NOT EXISTS storyline_events_by_story
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMM(first_seen)
ORDER BY (story_id)
TTL toDateTime(first_seen) + INTERVAL 180 DAY
AS SELECT
    story_id,
    toStartOfDay(min(timestamp))    AS first_seen,
    max(timestamp)                   AS last_seen,
    countState()                     AS event_count,
    uniqState(host_id)               AS unique_hosts,
    uniqState(event_type)            AS unique_event_types,
    uniqIfState(rule_name, rule_name != '') AS unique_rules
FROM storyline_events
GROUP BY story_id;

-- ==================== alerts (告警实体) ====================
-- MySQL → CH 迁移 (2026-05-29)
-- 原 MySQL alerts 表 1.6w 行，预期扩到 500 主机 / 攻击爆发瞬时高写入
-- ReplacingMergeTree(version) 按 alert_id 去重，version 用 updated_at unix ms
-- 写入路径：CEL/auto_response/biz 多处 INSERT，每次状态变更增 version
-- 查询：分析查询用 argMax 聚合；详情用 FINAL；批量分页用 ORDER BY created_at DESC LIMIT
CREATE TABLE IF NOT EXISTS alerts (
    id              UInt64,
    result_id       String,
    host_id         String,
    rule_id         String,
    policy_id       String,
    source          LowCardinality(String),    -- baseline/detection/agent/vulnerability/fim/virus/kube/prometheus_infra
    severity        LowCardinality(String),    -- critical/high/medium/low
    category        LowCardinality(String),
    title           String,
    description     String,
    actual          String,
    expected        String,
    fix_suggestion  String,
    status          LowCardinality(String),    -- active/resolved/ignored
    first_seen_at   DateTime64(3),
    last_seen_at    DateTime64(3),
    hit_count       UInt32,
    last_notified_at DateTime64(3),
    notify_count    UInt32,
    resolved_at     DateTime64(3),
    resolved_by     String,
    resolve_reason  String,
    created_at      DateTime64(3),
    updated_at      DateTime64(3),
    version         UInt64,                    -- updated_at unix nano，单调递增
    INDEX idx_host host_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_title title TYPE tokenbf_v1(8192, 3, 0) GRANULARITY 4,
    INDEX idx_result result_id TYPE bloom_filter GRANULARITY 4
) ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(created_at)
ORDER BY (result_id)
TTL toDateTime(created_at) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;

-- ==================== vulnerabilities (CVE 库) ====================
-- 5w 行 + 多源同步（NVD/CNNVD/OSV）UPSERT 频繁
-- ReplacingMergeTree(version) 按 cve_id 去重
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id                       UInt64,
    cve_id                   String,
    osv_id                   String,
    purl                     String,
    severity                 LowCardinality(String),
    cvss_score               Float32,
    component                String,
    description              String,
    affected_hosts           UInt32,
    patched_hosts            UInt32,
    status                   LowCardinality(String),
    discovered_at            DateTime64(3),
    patched_at               DateTime64(3),
    current_version          String,
    fixed_version            String,
    reference_url            String,
    cvss_vector              String,
    attack_vector            LowCardinality(String),
    vuln_type                LowCardinality(String),
    affected_versions        String,
    source                   LowCardinality(String),
    patch_available          UInt8,
    epss_score               Float32,
    cwe_id                   String,
    confidence               LowCardinality(String),
    vuln_category            LowCardinality(String),
    restart_action           LowCardinality(String),
    vuln_category_override   String,
    restart_action_override  String,
    cnvd_id                  String,
    cnnvd_id                 String,
    has_exploit              UInt8,
    in_kev                   UInt8,
    created_at               DateTime64(3),
    updated_at               DateTime64(3),
    version                  UInt64,
    INDEX idx_cve cve_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_purl purl TYPE bloom_filter GRANULARITY 4
) ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(discovered_at)
ORDER BY (cve_id)
TTL toDateTime(discovered_at) + INTERVAL 730 DAY
SETTINGS index_granularity = 8192;

-- ==================== host_vulnerabilities (主机漏洞关联) ====================
-- 92w 行，500 主机后预期 250w+
-- ReplacingMergeTree(version) 按 (host_id, vuln_id) 去重
CREATE TABLE IF NOT EXISTS host_vulnerabilities (
    id                            UInt64,
    vuln_id                       UInt64,
    host_id                       String,
    hostname                      String,
    ip                            String,
    current_version               String,
    status                        LowCardinality(String),
    patched_at                    DateTime64(3),
    precheck_status               LowCardinality(String),
    precheck_message              String,
    precheck_packages             String,
    precheck_affected_processes   String,
    precheck_checked_at           DateTime64(3),
    created_at                    DateTime64(3),
    updated_at                    DateTime64(3),
    version                       UInt64,
    INDEX idx_host host_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_vuln vuln_id TYPE bloom_filter GRANULARITY 4
) ENGINE = ReplacingMergeTree(version)
PARTITION BY toYYYYMM(created_at)
ORDER BY (host_id, vuln_id)
TTL toDateTime(created_at) + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;
