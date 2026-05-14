#!/bin/bash

# 诊断主机匹配问题的脚本

echo "=== 主机匹配问题诊断 ==="
echo ""

# 数据库连接信息（请根据实际情况修改）
DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"
DB_USER="${DB_USER:-root}"
DB_PASS="${DB_PASS:-root123}"
DB_NAME="${DB_NAME:-mxsec}"

echo "1. 检查 G02-UAT 业务线下的主机"
echo "================================"
mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "
SELECT
    host_id,
    hostname,
    os_family,
    os_version,
    runtime_type,
    business_line,
    status
FROM hosts
WHERE business_line = 'G02-UAT'
ORDER BY hostname;
" 2>/dev/null

echo ""
echo "2. 检查所有主机的 runtime_type 分布"
echo "===================================="
mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "
SELECT
    runtime_type,
    COUNT(*) as count
FROM hosts
GROUP BY runtime_type;
" 2>/dev/null

echo ""
echo "3. 检查 runtime_type 为 NULL 或空的主机"
echo "========================================"
mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "
SELECT
    host_id,
    hostname,
    business_line,
    runtime_type,
    status
FROM hosts
WHERE runtime_type IS NULL OR runtime_type = ''
LIMIT 10;
" 2>/dev/null

echo ""
echo "4. 检查策略的 OS Family 配置"
echo "============================"
mysql -h "$DB_HOST" -P "$DB_PORT" -u "$DB_USER" -p"$DB_PASS" "$DB_NAME" -e "
SELECT
    id,
    name,
    os_family,
    runtime_types,
    enabled
FROM policies
WHERE enabled = 1
LIMIT 5;
" 2>/dev/null

echo ""
echo "5. 修复建议"
echo "==========="
echo "如果发现 runtime_type 为 NULL 或空，可以执行以下 SQL 修复："
echo ""
echo "UPDATE hosts SET runtime_type = 'vm' WHERE runtime_type IS NULL OR runtime_type = '';"
echo ""
echo "如果主机的 business_line 字段为空，需要设置业务线："
echo ""
echo "UPDATE hosts SET business_line = 'G02-UAT' WHERE host_id IN ('host1', 'host2', ...);"
