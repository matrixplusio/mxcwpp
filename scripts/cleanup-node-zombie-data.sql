-- 清理 node_packages 历史脏数据（P0-5 部署后跑一次）
--
-- 背景：1.2.0 起 node_packages handler 改为"仅扫运行 node 进程实际加载的
-- node_modules（cmdline 入口/cwd 上溯）且排除 rpm/dpkg 管的 package.json"。
-- 旧版扫所有全局 / .nvm / 项目目录 node_modules → 大量误报开发目录残留与
-- 全局 cli 工具包，并出现"主机无 node 进程也报 npm 包"的情况
-- （实测 G02-UAT 3 台报 135 个但无 node 应用在跑）。
--
-- 清理策略：
--   1. 删除所有 package_type='npm' 旧记录（让 1.2.0 collector 重扫真实运行树）
--   2. 同步删除对应 host_vulnerabilities 避免残留误报漏洞

-- 1. 预览影响行数
SELECT
    'software' AS table_name,
    COUNT(*) AS rows_affected,
    COUNT(DISTINCT host_id) AS hosts_affected
FROM software
WHERE package_type = 'npm';

SELECT
    'host_vulnerabilities (npm-related)' AS table_name,
    COUNT(*) AS rows_affected
FROM host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
WHERE v.purl LIKE 'pkg:npm/%';

-- 2. 清理 software 表 npm 旧记录
DELETE FROM software WHERE package_type = 'npm';

-- 3. 清理 npm 来源的 host_vulnerabilities
DELETE hv FROM host_vulnerabilities hv
JOIN vulnerabilities v ON v.id = hv.vuln_id
WHERE v.purl LIKE 'pkg:npm/%';
