#!/bin/bash

# 开发环境启动脚本
# 用于同时启动后端Manager和前端UI

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 项目根目录
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Matrix Cloud Security Platform${NC}"
echo -e "${GREEN}  开发环境启动脚本${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# 检查依赖
echo -e "${YELLOW}[1/5] 检查依赖...${NC}"

# 检查Go
if ! command -v go &> /dev/null; then
    echo -e "${RED}错误: 未找到 Go，请先安装 Go${NC}"
    exit 1
fi
echo "  ✓ Go: $(go version)"

# 检查Node.js
if ! command -v node &> /dev/null; then
    echo -e "${RED}错误: 未找到 Node.js，请先安装 Node.js${NC}"
    exit 1
fi
echo "  ✓ Node.js: $(node --version)"

# 检查npm
if ! command -v npm &> /dev/null; then
    echo -e "${RED}错误: 未找到 npm，请先安装 npm${NC}"
    exit 1
fi
echo "  ✓ npm: $(npm --version)"

# 检查MySQL是否运行
echo ""
echo -e "${YELLOW}[2/5] 检查MySQL连接...${NC}"
if command -v mysql &> /dev/null; then
    # 检查MySQL连接（使用root用户）
    if mysql -h 127.0.0.1 -P 3306 -u root -p123456 -e "SELECT 1;" 2>/dev/null; then
        echo "  ✓ MySQL 连接成功"
        # 检查数据库是否存在，不存在则创建
        if ! mysql -h 127.0.0.1 -P 3306 -u root -p123456 -e "USE mxcwpp;" 2>/dev/null; then
            echo -e "${YELLOW}  数据库 mxcwpp 不存在，正在创建...${NC}"
            mysql -h 127.0.0.1 -P 3306 -u root -p123456 -e "CREATE DATABASE IF NOT EXISTS mxcwpp CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;" 2>/dev/null
            if [ $? -eq 0 ]; then
                echo "  ✓ 数据库 mxcwpp 创建成功"
            else
                echo -e "${RED}  错误: 无法创建数据库，请手动创建${NC}"
            fi
        else
            echo "  ✓ 数据库 mxcwpp 已存在"
        fi
    else
        echo -e "${RED}  错误: 无法连接到MySQL (127.0.0.1:3306, root)${NC}"
        echo -e "${RED}  请确保MySQL已启动，并且root密码为123456${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}  警告: 未找到mysql客户端，跳过连接检查${NC}"
fi

# 检查配置文件
echo ""
echo -e "${YELLOW}[3/5] 检查配置文件...${NC}"
if [ ! -f "configs/server.yaml" ]; then
    echo -e "${YELLOW}  警告: configs/server.yaml 不存在，从示例文件创建...${NC}"
    cp configs/server.yaml.example configs/server.yaml
    echo "  ✓ 已创建 configs/server.yaml"
else
    echo "  ✓ 配置文件存在"
fi

# 检查证书
echo ""
echo -e "${YELLOW}[4/5] 检查mTLS证书...${NC}"
if [ ! -f "deploy/certs/ca.crt" ]; then
    echo -e "${YELLOW}  警告: 证书文件不存在，正在生成...${NC}"
    make certs || {
        echo -e "${RED}  错误: 证书生成失败${NC}"
        exit 1
    }
    echo "  ✓ 证书已生成"
else
    echo "  ✓ 证书文件存在"
fi

# 安装UI依赖（如果需要）
echo ""
echo -e "${YELLOW}[5/5] 检查UI依赖...${NC}"
if [ ! -d "web/node_modules" ]; then
    echo "  正在安装UI依赖..."
    cd web
    pnpm install
    cd ..
    echo "  ✓ UI依赖已安装"
else
    echo "  ✓ UI依赖已存在"
fi

# 构建后端
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  构建后端服务...${NC}"
echo -e "${GREEN}========================================${NC}"
if ! make build-server; then
    echo -e "${RED}错误: 后端构建失败${NC}"
    exit 1
fi

# 清理函数
cleanup() {
    echo ""
    echo -e "${YELLOW}正在停止服务...${NC}"
    kill $MANAGER_PID 2>/dev/null || true
    kill $UI_PID 2>/dev/null || true
    wait $MANAGER_PID 2>/dev/null || true
    wait $UI_PID 2>/dev/null || true
    echo -e "${GREEN}服务已停止${NC}"
    exit 0
}

# 注册清理函数
trap cleanup SIGINT SIGTERM

# 启动后端Manager
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  启动后端Manager服务...${NC}"
echo -e "${GREEN}========================================${NC}"
./dist/server/manager -config configs/server.yaml &
MANAGER_PID=$!

# 等待后端启动
echo "等待后端服务启动..."
sleep 3

# 检查后端是否启动成功
if ! curl -s http://localhost:8080/health > /dev/null; then
    echo -e "${RED}错误: 后端服务启动失败，请检查日志${NC}"
    kill $MANAGER_PID 2>/dev/null || true
    exit 1
fi
echo -e "${GREEN}  ✓ 后端Manager服务已启动 (http://localhost:8080)${NC}"

# 启动前端UI
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  启动前端UI服务...${NC}"
echo -e "${GREEN}========================================${NC}"
cd web
API_TARGET=http://localhost:8080 pnpm dev &
UI_PID=$!
cd ..

# 等待UI启动
echo "等待前端服务启动..."
sleep 3

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  开发环境启动完成！${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "  后端API: ${GREEN}http://localhost:8080${NC}"
echo -e "  前端UI:  ${GREEN}http://localhost:3000${NC}"
echo ""
echo -e "  按 ${YELLOW}Ctrl+C${NC} 停止所有服务"
echo ""

# 等待进程
wait $MANAGER_PID $UI_PID
