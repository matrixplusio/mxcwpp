#!/bin/bash

# Matrix Cloud Security Platform Agent 卸载脚本
# 使用方法: curl -sS http://SERVER_IP:8080/agent/uninstall.sh | bash

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 停止服务
stop_service() {
    echo -e "${GREEN}Stopping agent service...${NC}"
    
    if systemctl is-active --quiet mxsec-agent 2>/dev/null; then
        systemctl stop mxsec-agent
        echo -e "${GREEN}Agent service stopped${NC}"
    else
        echo -e "${YELLOW}Agent service is not running${NC}"
    fi
}

# 禁用服务
disable_service() {
    echo -e "${GREEN}Disabling agent service...${NC}"
    
    if systemctl is-enabled --quiet mxsec-agent 2>/dev/null; then
        systemctl disable mxsec-agent
        echo -e "${GREEN}Agent service disabled${NC}"
    else
        echo -e "${YELLOW}Agent service is not enabled${NC}"
    fi
}

# 卸载包
uninstall_package() {
    echo -e "${GREEN}Uninstalling agent package...${NC}"
    
    # 检测包管理器
    if command -v rpm &> /dev/null && rpm -q mxsec-agent &> /dev/null; then
        if command -v yum &> /dev/null; then
            yum remove -y mxsec-agent
        elif command -v dnf &> /dev/null; then
            dnf remove -y mxsec-agent
        else
            rpm -e mxsec-agent
        fi
    elif command -v dpkg &> /dev/null && dpkg -l | grep -q mxsec-agent; then
        apt-get remove -y mxsec-agent || apt-get purge -y mxsec-agent
    else
        echo -e "${YELLOW}Agent package not found in package manager${NC}"
    fi
}

# 清理文件
cleanup_files() {
    echo -e "${GREEN}Cleaning up agent files...${NC}"
    
    # 清理数据目录（可选，保留日志）
    if [ -d "/var/lib/mxsec-agent" ]; then
        read -p "Do you want to remove agent data directory (/var/lib/mxsec-agent)? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf /var/lib/mxsec-agent
            echo -e "${GREEN}Agent data directory removed${NC}"
        else
            echo -e "${YELLOW}Agent data directory kept${NC}"
        fi
    fi
    
    # 清理日志目录（可选）
    if [ -d "/var/log/mxsec-agent" ]; then
        read -p "Do you want to remove agent log directory (/var/log/mxsec-agent)? [y/N]: " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            rm -rf /var/log/mxsec-agent
            echo -e "${GREEN}Agent log directory removed${NC}"
        else
            echo -e "${YELLOW}Agent log directory kept${NC}"
        fi
    fi
}

# 主流程
main() {
    echo -e "${GREEN}=== Matrix Cloud Security Platform Agent Uninstaller ===${NC}"
    echo ""
    
    # 检查 root 权限
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
    
    # 停止服务
    stop_service
    
    # 禁用服务
    disable_service
    
    # 卸载包
    uninstall_package
    
    # 清理文件（交互式）
    cleanup_files
    
    echo ""
    echo -e "${GREEN}Uninstallation completed!${NC}"
}

# 执行主流程
main
