-- P0-3 schema migration：software 表加 scope / source_handler / host_binary_path
--
-- 必须在部署 v1.2.0 server 前跑（agent 上报这些字段时，旧 schema 会 silently drop）。
-- 操作幂等 — 重复执行不会出错（IF NOT EXISTS）。

-- 1. 加列
ALTER TABLE software
    ADD COLUMN IF NOT EXISTS scope VARCHAR(16) NOT NULL DEFAULT 'system' COMMENT 'system|embedded|container',
    ADD COLUMN IF NOT EXISTS source_handler VARCHAR(32) NULL COMMENT '采集来源 handler',
    ADD COLUMN IF NOT EXISTS host_binary_path VARCHAR(500) NULL COMMENT '宿主 binary 路径（embedded scope 用）';

-- 2. 索引（scope 用于匹配引擎过滤；source_handler 用于运维查询）
ALTER TABLE software
    ADD INDEX IF NOT EXISTS idx_software_scope (scope),
    ADD INDEX IF NOT EXISTS idx_software_source_handler (source_handler);

-- 3. 历史 Go module 数据回填：把已有 package_type='go-module' 的记录全部标记 embedded
--    （旧 collector 不区分主模块与依赖，全部入库为 go-module —— 严格说主模块也存在
--     但量极少且无法回溯区分，整体标 embedded 后续重扫覆盖时由新 collector 校正）
UPDATE software
SET scope = 'embedded',
    source_handler = 'go_buildinfo'
WHERE package_type = 'go-module'
  AND (scope IS NULL OR scope = '' OR scope = 'system');

-- 4. 预览影响行数（验证用）
SELECT
    scope,
    package_type,
    COUNT(*) AS rows_count,
    COUNT(DISTINCT host_id) AS hosts_count
FROM software
WHERE package_type IN ('go-module', 'go-binary')
GROUP BY scope, package_type;

-- 5. 清理 embedded 来源的脏 host_vulnerabilities（P0-3 生效后这些不应再存在）
--    执行前先 SELECT 看影响行数。
SELECT COUNT(*) AS embedded_host_vulns_to_clean
FROM host_vulnerabilities hv
WHERE EXISTS (
    SELECT 1 FROM software s
    WHERE s.host_id = hv.host_id
      AND s.scope = 'embedded'
      AND s.purl IS NOT NULL
      AND s.purl != ''
);

-- 真要清的话取消下面注释：
-- DELETE hv FROM host_vulnerabilities hv
-- WHERE EXISTS (
--     SELECT 1 FROM software s
--     WHERE s.host_id = hv.host_id
--       AND s.scope = 'embedded'
--       AND s.purl IS NOT NULL
--       AND s.purl != ''
-- );
