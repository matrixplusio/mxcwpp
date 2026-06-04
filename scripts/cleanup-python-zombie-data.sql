-- 清理 python_packages 历史脏数据（P0-4 部署后跑一次）
--
-- 背景：1.2.0 起 python_packages handler 改为"仅扫运行 Python 进程的 sys.path
-- 且排除 rpm/dpkg 管的 dist-info"。旧版无运行进程绑定 + 无 OS 包去重，导致
-- 大量虚假 pip 包入库（实测 G02-UAT 3 台报 1485 个但实际多数是 RHEL python3-*
-- RPM 装的、或 venv 残留的 dist-info）。
--
-- 清理策略：
--   1. 删除所有 package_type='pip' 旧记录（让 1.2.0 collector 重新扫一遍才是
--      真实运行 Python 应用的包清单）
--   2. 同步删除对应 host_vulnerabilities（避免残留误报漏洞）
--
-- 1.2.0 collector 首次采集后这些表会重新写入，没有数据丢失风险。

-- 1. 预览影响行数
SELECT
    'software' AS table_name,
    COUNT(*) AS rows_affected,
    COUNT(DISTINCT host_id) AS hosts_affected
FROM software
WHERE package_type = 'pip';

SELECT
    'host_vulnerabilities (pip-related)' AS table_name,
    COUNT(*) AS rows_affected
FROM host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
WHERE v.purl LIKE 'pkg:pypi/%';

-- 2. 清理 software 表 pip 旧记录
DELETE FROM software WHERE package_type = 'pip';

-- 3. 清理 pip 来源的 host_vulnerabilities
DELETE hv FROM host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
WHERE v.purl LIKE 'pkg:pypi/%';
