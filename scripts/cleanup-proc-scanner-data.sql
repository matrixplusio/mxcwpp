-- 清理 proc_scanner 历史数据（P0-2 砍 handler 后部署时跑一次）
--
-- 背景：proc_scanner 扫 /proc/*/exe 输出"运行二进制"，version 字段固定为空，
-- 与 binary_probe 职责高度重叠（binary_probe 探针就是基于运行进程的二进制路径），
-- 但 proc_scanner 因无版本无法参与 CVE 匹配 → 仅徒增 software 表噪声。
--
-- 1.2.0 起 binary_probe 已合并"运行确认"职责（gate 1：basename / path 命中 /proc/*/exe
-- 才探测），proc_scanner 退役。残留记录需清理避免误导主机资产盘点。
--
-- 判定准则：package_type='running-binary'（proc_scanner 独有输出特征）。

-- 1. 预览待清理行数
SELECT
    COUNT(*) AS rows_affected,
    COUNT(DISTINCT host_id) AS hosts_affected
FROM software
WHERE package_type = 'running-binary';

-- 2. 清理 software 表
DELETE FROM software
WHERE package_type = 'running-binary';
