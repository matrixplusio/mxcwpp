#!/bin/bash

# Matrix Cloud Security Platform Agent 一键安装脚本
# 使用方法（推荐）:
#   curl -sS http://SERVER_IP:8080/agent/install.sh | bash
#
# 或者通过环境变量自定义服务器地址:
#   MXSEC_HTTP_SERVER=http://192.168.8.140:8080 MXSEC_AGENT_SERVER=192.168.8.140:6751 \
#   bash -c "$(curl -fsSL http://192.168.8.140:8080/agent/install.sh)"
#
# 可选参数:
#   INSTALL_TETRAGON=1  同时安装 Tetragon（需要 eBPF Sensor 插件，内核 >= 4.19）
#   TETRAGON_VERSION    Tetragon 版本（默认 1.2.0）
#
# 注意：如果使用前端代理（如 3000 端口），请确保代理已配置 /agent 路径

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 默认配置（可通过环境变量覆盖）
# SERVER_HOST 用于下载安装包，应该指向 Manager HTTP 服务器（例如：10.0.0.1:8080）
# AGENT_SERVER_HOST 用于 Agent 连接，应该指向 AgentCenter gRPC 服务器（例如：10.0.0.1:6751）
# BUSINESS_LINE 业务线标识（可选，如果设置，Agent 安装后会自动绑定到该业务线）
# 注意：优先使用环境变量，如果环境变量未设置，脚本中的占位符会被 Manager API 自动替换

# 优先使用环境变量（即使占位符已被后端替换）
if [ -n "$MXSEC_HTTP_SERVER" ]; then
    SERVER_HOST="$MXSEC_HTTP_SERVER"
else
    # 如果环境变量未设置，使用占位符（会被后端替换）
    SERVER_HOST="http://SERVER_HOST_PLACEHOLDER"
fi

if [ -n "$MXSEC_AGENT_SERVER" ]; then
    AGENT_SERVER_HOST="$MXSEC_AGENT_SERVER"
else
    # 如果环境变量未设置，使用占位符（会被后端替换）
    AGENT_SERVER_HOST="AGENT_SERVER_PLACEHOLDER"
fi

# 如果 SERVER_HOST 包含占位符或 0.0.0.0，说明环境变量未设置且后端替换失败，报错
if [[ "$SERVER_HOST" == *"SERVER_HOST_PLACEHOLDER"* ]] || [[ "$SERVER_HOST" == *"0.0.0.0"* ]]; then
    echo -e "${RED}Error: SERVER_HOST is not set correctly. Please set MXSEC_HTTP_SERVER environment variable.${NC}"
    echo -e "${RED}Example: MXSEC_HTTP_SERVER=192.168.8.140:8080${NC}"
    exit 1
fi

# 如果 AGENT_SERVER_HOST 包含占位符或 0.0.0.0，说明环境变量未设置且后端替换失败，报错
if [[ "$AGENT_SERVER_HOST" == *"AGENT_SERVER_PLACEHOLDER"* ]] || [[ "$AGENT_SERVER_HOST" == *"0.0.0.0"* ]]; then
    echo -e "${RED}Error: AGENT_SERVER_HOST is not set correctly. Please set MXSEC_AGENT_SERVER environment variable.${NC}"
    echo -e "${RED}Example: MXSEC_AGENT_SERVER=192.168.8.140:6751${NC}"
    exit 1
fi

# 确保 SERVER_HOST 有协议前缀（如果没有）
if [[ "$SERVER_HOST" != http://* ]] && [[ "$SERVER_HOST" != https://* ]]; then
    SERVER_HOST="http://${SERVER_HOST}"
fi
BUSINESS_LINE="${MXSEC_BUSINESS_LINE:-}"
ARCH="${MXSEC_ARCH:-$(uname -m)}"
OS_TYPE="${MXSEC_OS_TYPE:-}"

# 检测操作系统类型
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS_TYPE="$ID"
        OS_VERSION="$VERSION_ID"
    elif [ -f /etc/redhat-release ]; then
        OS_TYPE="rhel"
    elif [ -f /etc/debian_version ]; then
        OS_TYPE="debian"
    else
        echo -e "${RED}Error: Unsupported operating system${NC}"
        exit 1
    fi
}

# 检测架构
detect_arch() {
    case "$(uname -m)" in
        x86_64)
            ARCH="amd64"
            ;;
        aarch64|arm64)
            ARCH="arm64"
            ;;
        *)
            echo -e "${RED}Error: Unsupported architecture: $(uname -m)${NC}"
            exit 1
            ;;
    esac
}

# 确定包管理器
determine_package_manager() {
    if command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
        PKG_TYPE="rpm"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
        PKG_TYPE="rpm"
    elif command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt-get"
        PKG_TYPE="deb"
    else
        echo -e "${RED}Error: No supported package manager found${NC}"
        exit 1
    fi
}

# 下载安装包
download_package() {
    # 所有输出都重定向到 stderr，避免影响返回值
    echo -e "${GREEN}Downloading agent package...${NC}" >&2
    
    # 构建下载 URL
    # SERVER_HOST 在脚本中会被替换为实际的 HTTP 服务器地址
    # 如果 SERVER_HOST 包含协议前缀，直接使用；否则添加 http://
    if [[ "$SERVER_HOST" == http://* ]] || [[ "$SERVER_HOST" == https://* ]]; then
        DOWNLOAD_URL="${SERVER_HOST}/api/v1/agent/download/${PKG_TYPE}/${ARCH}"
    else
        DOWNLOAD_URL="http://${SERVER_HOST}/api/v1/agent/download/${PKG_TYPE}/${ARCH}"
    fi
    
    echo -e "${GREEN}Download URL: ${DOWNLOAD_URL}${NC}" >&2
    
    TEMP_DIR=$(mktemp -d)
    PACKAGE_FILE="${TEMP_DIR}/mxsec-agent.${PKG_TYPE}"
    
    # 下载文件
    if command -v curl &> /dev/null; then
        if ! curl -f -L -o "$PACKAGE_FILE" "$DOWNLOAD_URL"; then
            echo -e "${RED}Error: Failed to download agent package from ${DOWNLOAD_URL}${NC}" >&2
            echo -e "${RED}Please check the server address and network connection.${NC}" >&2
            rm -rf "$TEMP_DIR"
            exit 1
        fi
    elif command -v wget &> /dev/null; then
        if ! wget -O "$PACKAGE_FILE" "$DOWNLOAD_URL"; then
            echo -e "${RED}Error: Failed to download agent package from ${DOWNLOAD_URL}${NC}" >&2
            echo -e "${RED}Please check the server address and network connection.${NC}" >&2
            rm -rf "$TEMP_DIR"
            exit 1
        fi
    else
        echo -e "${RED}Error: curl or wget is required${NC}" >&2
        exit 1
    fi
    
    # 检查文件是否存在且不为空
    if [ ! -f "$PACKAGE_FILE" ] || [ ! -s "$PACKAGE_FILE" ]; then
        echo -e "${RED}Error: Downloaded file is empty or does not exist${NC}" >&2
        rm -rf "$TEMP_DIR"
        exit 1
    fi
    
    # 检查文件类型（防止下载到 HTML 错误页面）
    file_type=$(file -b "$PACKAGE_FILE" 2>/dev/null || echo "")
    if [[ "$PKG_TYPE" == "rpm" ]] && [[ "$file_type" != *"RPM"* ]] && [[ "$file_type" != *"rpm"* ]]; then
        # 检查是否是 HTML 错误页面
        if head -n 1 "$PACKAGE_FILE" | grep -q "<!DOCTYPE\|<html"; then
            echo -e "${RED}Error: Server returned HTML instead of RPM package${NC}" >&2
            echo -e "${RED}Response: $(head -n 5 "$PACKAGE_FILE")${NC}" >&2
            rm -rf "$TEMP_DIR"
            exit 1
        fi
        echo -e "${YELLOW}Warning: File type check failed, but continuing...${NC}" >&2
    elif [[ "$PKG_TYPE" == "deb" ]] && [[ "$file_type" != *"Debian"* ]] && [[ "$file_type" != *"debian"* ]]; then
        # 检查是否是 HTML 错误页面
        if head -n 1 "$PACKAGE_FILE" | grep -q "<!DOCTYPE\|<html"; then
            echo -e "${RED}Error: Server returned HTML instead of DEB package${NC}" >&2
            echo -e "${RED}Response: $(head -n 5 "$PACKAGE_FILE")${NC}" >&2
            rm -rf "$TEMP_DIR"
            exit 1
        fi
        echo -e "${YELLOW}Warning: File type check failed, but continuing...${NC}" >&2
    fi
    
    echo -e "${GREEN}Package downloaded successfully: ${PACKAGE_FILE}${NC}" >&2
    # 只输出文件路径到 stdout（用于返回值）
    echo "$PACKAGE_FILE"
}

# 安装包
install_package() {
    PACKAGE_FILE="$1"
    
    if [ ! -f "$PACKAGE_FILE" ]; then
        echo -e "${RED}Error: Package file not found: ${PACKAGE_FILE}${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}Installing agent from ${PACKAGE_FILE}...${NC}"
    
    if [ "$PKG_TYPE" = "rpm" ]; then
        if [ "$PKG_MANAGER" = "yum" ]; then
            if ! yum install -y "$PACKAGE_FILE"; then
                echo -e "${RED}Error: Failed to install RPM package${NC}"
                echo -e "${RED}Please check the package file: ${PACKAGE_FILE}${NC}"
                rm -f "$PACKAGE_FILE"
                rmdir "$(dirname "$PACKAGE_FILE")" 2>/dev/null
                exit 1
            fi
        else
            if ! dnf install -y "$PACKAGE_FILE"; then
                echo -e "${RED}Error: Failed to install RPM package${NC}"
                echo -e "${RED}Please check the package file: ${PACKAGE_FILE}${NC}"
                rm -f "$PACKAGE_FILE"
                rmdir "$(dirname "$PACKAGE_FILE")" 2>/dev/null
                exit 1
            fi
        fi
    else
        if ! apt-get update; then
            echo -e "${YELLOW}Warning: apt-get update failed, but continuing...${NC}"
        fi
        if ! apt-get install -y "$PACKAGE_FILE"; then
            echo -e "${RED}Error: Failed to install DEB package${NC}"
            echo -e "${RED}Please check the package file: ${PACKAGE_FILE}${NC}"
            rm -f "$PACKAGE_FILE"
            rmdir "$(dirname "$PACKAGE_FILE")" 2>/dev/null
            exit 1
        fi
    fi
    
    echo -e "${GREEN}Package installed successfully${NC}"
    rm -f "$PACKAGE_FILE"
    rmdir "$(dirname "$PACKAGE_FILE")" 2>/dev/null
}

# 配置业务线环境变量（如果提供了）
configure_business_line() {
    if [ -n "$BUSINESS_LINE" ]; then
        echo -e "${GREEN}Configuring business line: ${BUSINESS_LINE}${NC}"
        
        # 创建 systemd override 目录
        OVERRIDE_DIR="/etc/systemd/system/mxsec-agent.service.d"
        mkdir -p "$OVERRIDE_DIR"
        
        # 创建 override 配置文件
        OVERRIDE_FILE="$OVERRIDE_DIR/business-line.conf"
        cat > "$OVERRIDE_FILE" <<EOF
[Service]
Environment="MXSEC_BUSINESS_LINE=${BUSINESS_LINE}"
EOF
        
        echo -e "${GREEN}Business line configured in ${OVERRIDE_FILE}${NC}"
    fi
}

# 启动服务
start_service() {
    echo -e "${GREEN}Starting agent service...${NC}"
    
    # 配置业务线（如果提供了）
    configure_business_line
    
    systemctl daemon-reload
    systemctl enable mxsec-agent
    systemctl start mxsec-agent
    
    # 等待服务启动
    sleep 2
    
    if systemctl is-active --quiet mxsec-agent; then
        echo -e "${GREEN}Agent started successfully!${NC}"
        echo -e "${GREEN}Status: $(systemctl status mxsec-agent --no-pager -l | head -n 3)${NC}"
    else
        echo -e "${YELLOW}Warning: Agent service may not have started properly${NC}"
        echo -e "${YELLOW}Check logs: journalctl -u mxsec-agent${NC}"
    fi
}

# ==================== Tetragon 可选安装 ====================

TETRAGON_VERSION="${TETRAGON_VERSION:-1.2.0}"

# 安装 Tetragon（eBPF 安全监控）
install_tetragon() {
    echo -e "${GREEN}=== Installing Tetragon (eBPF security monitor) ===${NC}"

    # 检查内核版本 >= 4.19
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1-2)
    local kernel_major kernel_minor
    kernel_major=$(echo "$kernel_version" | cut -d. -f1)
    kernel_minor=$(echo "$kernel_version" | cut -d. -f2)

    if [ "$kernel_major" -lt 4 ] || { [ "$kernel_major" -eq 4 ] && [ "$kernel_minor" -lt 19 ]; }; then
        echo -e "${RED}Error: Kernel $kernel_version does not meet requirement (>= 4.19)${NC}"
        echo -e "${YELLOW}Skipping Tetragon installation.${NC}"
        return 1
    fi

    # 检查 systemd
    if ! command -v systemctl &>/dev/null; then
        echo -e "${RED}Error: systemd is required for Tetragon${NC}"
        return 1
    fi

    # 已安装则跳过
    if command -v tetra &>/dev/null; then
        echo -e "${GREEN}Tetragon already installed: $(tetra version 2>/dev/null || echo 'unknown')${NC}"
        return 0
    fi

    echo -e "${GREEN}Installing Tetragon v${TETRAGON_VERSION}...${NC}"

    # 下载安装
    if [ "$PKG_TYPE" = "deb" ]; then
        curl -fSL "https://github.com/cilium/tetragon/releases/download/v${TETRAGON_VERSION}/tetragon-${TETRAGON_VERSION}-${ARCH}.deb" -o /tmp/tetragon.deb
        dpkg -i /tmp/tetragon.deb
        rm -f /tmp/tetragon.deb
    else
        curl -fSL "https://github.com/cilium/tetragon/releases/download/v${TETRAGON_VERSION}/tetragon-${TETRAGON_VERSION}-${ARCH}.rpm" -o /tmp/tetragon.rpm
        rpm -ivh /tmp/tetragon.rpm
        rm -f /tmp/tetragon.rpm
    fi

    # 配置
    mkdir -p /etc/tetragon
    cat > /etc/tetragon/tetragon.yaml <<'TETRAGON_CONF'
# MxSec Tetragon configuration
export-filename: ""
export-file-max-size-mb: 100
export-file-rotation-interval: 24h
export-file-max-backups: 3
export-file-compress: true
enable-process-cred: true
enable-process-ns: true
process-cache-size: 65536
data-cache-size: 1024
metrics-server: ""
health-server: ""
gops-address: ""
TETRAGON_CONF

    # 启动
    systemctl daemon-reload
    systemctl enable tetragon
    systemctl restart tetragon

    # 等待就绪
    local retries=10
    while [ $retries -gt 0 ]; do
        if [ -S /var/run/tetragon/tetragon.sock ]; then
            echo -e "${GREEN}Tetragon is ready (socket: /var/run/tetragon/tetragon.sock)${NC}"
            return 0
        fi
        sleep 1
        retries=$((retries - 1))
    done

    echo -e "${YELLOW}Warning: Tetragon socket not ready, check: systemctl status tetragon${NC}"
}

# 主流程
main() {
    echo -e "${GREEN}=== Matrix Cloud Security Platform Agent Installer ===${NC}"
    echo ""
    
    # 检查 root 权限
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: This script must be run as root${NC}"
        exit 1
    fi
    
    # 检测系统信息
    detect_os
    detect_arch
    determine_package_manager
    
    echo -e "${GREEN}Detected: ${OS_TYPE} (${ARCH})${NC}"
    echo -e "${GREEN}HTTP Server: ${SERVER_HOST}${NC}"
    echo -e "${GREEN}Agent Server: ${AGENT_SERVER_HOST}${NC}"
    echo ""
    
    # 下载并安装
    PACKAGE_FILE=$(download_package)
    install_package "$PACKAGE_FILE"
    
    # 启动服务
    start_service

    # 可选：安装 Tetragon（INSTALL_TETRAGON=1）
    if [ "${INSTALL_TETRAGON:-0}" = "1" ]; then
        install_tetragon || echo -e "${YELLOW}Tetragon installation failed, agent is still running.${NC}"
    fi

    echo ""
    echo -e "${GREEN}Installation completed!${NC}"
    echo -e "${GREEN}Agent will connect to server and download configuration automatically.${NC}"
    if [ "${INSTALL_TETRAGON:-0}" = "1" ]; then
        echo -e "${GREEN}Tetragon eBPF monitor is installed for Sensor plugin.${NC}"
    fi
}

# 执行主流程
main
