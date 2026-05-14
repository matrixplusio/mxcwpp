#!/bin/bash

# 数据库初始化脚本
# 用于创建mxsec数据库（如果不存在）

set -e

# 颜色输出
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# MySQL连接配置
MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-123456}"
MYSQL_DATABASE="${MYSQL_DATABASE:-mxsec}"

echo -e "${GREEN}初始化数据库...${NC}"

# 检查mysql客户端
if ! command -v mysql &> /dev/null; then
    echo -e "${RED}错误: 未找到mysql客户端${NC}"
    echo "请安装MySQL客户端:"
    echo "  macOS: brew install mysql-client"
    echo "  Ubuntu/Debian: sudo apt-get install mysql-client"
    exit 1
fi

# 测试MySQL连接
echo -e "${YELLOW}测试MySQL连接...${NC}"
if ! mysql -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "SELECT 1;" 2>/dev/null; then
    echo -e "${RED}错误: 无法连接到MySQL${NC}"
    echo "  主机: $MYSQL_HOST:$MYSQL_PORT"
    echo "  用户: $MYSQL_USER"
    echo "  请检查MySQL是否运行，以及用户名密码是否正确"
    exit 1
fi
echo -e "${GREEN}  ✓ MySQL连接成功${NC}"

# 创建数据库
echo -e "${YELLOW}创建数据库 $MYSQL_DATABASE...${NC}"
mysql -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" <<EOF
CREATE DATABASE IF NOT EXISTS $MYSQL_DATABASE CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
EOF

if [ $? -eq 0 ]; then
    echo -e "${GREEN}  ✓ 数据库 $MYSQL_DATABASE 创建成功${NC}"
else
    echo -e "${RED}  ✗ 数据库创建失败${NC}"
    exit 1
fi

# 验证数据库
echo -e "${YELLOW}验证数据库...${NC}"
if mysql -h "$MYSQL_HOST" -P "$MYSQL_PORT" -u "$MYSQL_USER" -p"$MYSQL_PASSWORD" -e "USE $MYSQL_DATABASE;" 2>/dev/null; then
    echo -e "${GREEN}  ✓ 数据库验证成功${NC}"
else
    echo -e "${RED}  ✗ 数据库验证失败${NC}"
    exit 1
fi

echo ""
echo -e "${GREEN}数据库初始化完成！${NC}"
echo ""
echo "数据库信息："
echo "  主机: $MYSQL_HOST:$MYSQL_PORT"
echo "  用户: $MYSQL_USER"
echo "  数据库: $MYSQL_DATABASE"
echo ""
echo "注意：表结构会在Manager启动时自动创建（通过Gorm AutoMigrate）"
