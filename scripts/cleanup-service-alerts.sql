-- ============================================================================
-- 清理 service 类告警脏数据
-- ----------------------------------------------------------------------------
-- 背景：
--   alerts 表中存在 category='service' 的告警，但 source/severity/title/description
--   等关键字段为空，导致 UI 服务告警列表显示空白字段。
--   代码审计确认仓库内 0 处生成 category='service' 的告警（仅查询/确认/统计三处使用），
--   该类告警可能源自历史代码版本或人工插入，属于脏数据。
--
-- 执行步骤：
--   1. 先 SELECT 确认数量和样本（DRY RUN，不修改数据）
--   2. 备份到 alerts_service_backup 表（保留 7 天）
--   3. 删除脏数据
--   4. 后续如需真正的服务监控告警生成器，应在 manager 端新增 service alert generator
--      （参考 internal/server/manager/biz/fim_escalation.go 模式）
--
-- 使用方法：
--   mysql -u<user> -p<pass> mxsec_platform < scripts/cleanup-service-alerts.sql
-- ============================================================================

-- 步骤 1: 统计待清理数据
SELECT
    COUNT(*) AS total_dirty_count,
    SUM(CASE WHEN severity = '' OR severity IS NULL THEN 1 ELSE 0 END) AS empty_severity,
    SUM(CASE WHEN title = '' OR title IS NULL THEN 1 ELSE 0 END) AS empty_title,
    SUM(CASE WHEN description = '' OR description IS NULL THEN 1 ELSE 0 END) AS empty_description,
    SUM(CASE WHEN source = '' OR source IS NULL THEN 1 ELSE 0 END) AS empty_source
FROM alerts
WHERE category = 'service';

-- 步骤 2: 样本查看（最近 10 条）
SELECT id, created_at, source, severity, title, description, status
FROM alerts
WHERE category = 'service'
ORDER BY created_at DESC
LIMIT 10;

-- 步骤 3: 备份脏数据到独立表（保留 7 天作为回滚保险）
DROP TABLE IF EXISTS alerts_service_backup;
CREATE TABLE alerts_service_backup AS
SELECT * FROM alerts WHERE category = 'service';

-- 步骤 4: 删除脏数据（仅删除字段缺失的，保留偶然合法填充的）
DELETE FROM alerts
WHERE category = 'service'
  AND (
    severity IS NULL OR severity = ''
    OR title IS NULL OR title = ''
    OR source IS NULL OR source = ''
  );

-- 步骤 5: 验证清理结果
SELECT COUNT(*) AS remaining_service_alerts FROM alerts WHERE category = 'service';
SELECT COUNT(*) AS backup_count FROM alerts_service_backup;
