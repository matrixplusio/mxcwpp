-- MxSec Platform - ClickHouse 初始化 DDL
-- 对应设计文档: docs/design/ha-architecture.md § 3.4.2

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
    INDEX idx_file_path file_path TYPE tokenbf_v1(10240, 3, 0) GRANULARITY 4
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
