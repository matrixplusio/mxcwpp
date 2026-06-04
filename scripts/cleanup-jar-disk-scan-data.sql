-- 清理 jar_scanner 历史脏数据（P0-6 部署后跑一次）
--
-- 背景：1.2.0 起 jar_scanner handler 改为"仅扫运行 java 进程实际加载的
-- jar（cmdline -jar/-cp + /proc fd + /proc maps）"。旧版全盘扫 /opt /usr/local
-- 等磁盘路径，把备份 jar / 测试 jar / 旧版本 war 全部入库，prod 实测达 96k+ 条
-- 噪声 + fat-jar 内嵌依赖重复记录。
--
-- 清理策略：
--   1. 删除所有 package_type='jar' 旧记录（让 1.2.0 collector 重扫真实运行 JVM 加载的 jar）
--   2. 同步删除 maven / pkg:generic 来源的 host_vulnerabilities

-- 1. 预览影响行数
SELECT
    'software' AS table_name,
    COUNT(*) AS rows_affected,
    COUNT(DISTINCT host_id) AS hosts_affected
FROM software
WHERE package_type = 'jar';

SELECT
    'host_vulnerabilities (jar-related)' AS table_name,
    COUNT(*) AS rows_affected
FROM host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
WHERE v.purl LIKE 'pkg:maven/%';

-- 2. 清理 software 表 jar 旧记录
DELETE FROM software WHERE package_type = 'jar';

-- 3. 清理 maven 来源的 host_vulnerabilities（pkg:generic 的不动 — 那些可能由其他 handler 产生）
DELETE hv FROM host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
WHERE v.purl LIKE 'pkg:maven/%';
