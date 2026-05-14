#!/bin/bash

# Agent 打包脚本（使用 nFPM）
# 生成 RPM 和 DEB 安装包

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 配置
SERVER_HOST="${SERVER_HOST:-localhost:6751}"
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ARCH="${GOARCH:-amd64}"
OS="linux"  # 始终构建 Linux 二进制
DISTRO="${DISTRO:-}"  # 发行版：centos7, centos8, rocky8, rocky9, debian10, debian11, debian12 等
CERT_DIR="${CERT_DIR:-deploy/certs}"  # 证书目录

# 版本：环境变量 > VERSION 文件 > 默认值
if [ -n "${VERSION:-}" ]; then
    : # 使用环境变量
elif [ -f "VERSION" ]; then
    VERSION=$(cat VERSION | tr -d '[:space:]')
else
    VERSION="1.0.0"
fi

# 输出目录
DIST_DIR="dist/agent"
PACKAGE_DIR="dist/packages"
mkdir -p "$DIST_DIR"
mkdir -p "$PACKAGE_DIR"

echo -e "${GREEN}=== Agent 打包脚本 ===${NC}"
echo "Version: $VERSION"
echo "Server: $SERVER_HOST"
echo "OS/Arch: $OS/$ARCH"
echo "Distribution: ${DISTRO:-通用}"
echo "Cert Dir: $CERT_DIR"
echo ""

# 检查并安装 nFPM
NFPM_CMD=""
if command -v nfpm &> /dev/null; then
    NFPM_CMD="nfpm"
else
    # 尝试从常见路径查找
    if [ -f "$HOME/go/bin/nfpm" ]; then
        NFPM_CMD="$HOME/go/bin/nfpm"
    elif [ -n "$GOPATH" ] && [ -f "$GOPATH/bin/nfpm" ]; then
        NFPM_CMD="$GOPATH/bin/nfpm"
    else
        echo -e "${YELLOW}nfpm not found, installing...${NC}"
        go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
        
        # 等待安装完成
        sleep 2
        
        # 再次尝试查找（等待安装完成）
        sleep 3
        
        # 检查多个可能的位置
        if [ -f "$HOME/go/bin/nfpm" ]; then
            NFPM_CMD="$HOME/go/bin/nfpm"
        elif [ -n "$GOPATH" ] && [ -f "$GOPATH/bin/nfpm" ]; then
            NFPM_CMD="$GOPATH/bin/nfpm"
        elif command -v nfpm &> /dev/null; then
            NFPM_CMD="nfpm"
        else
            echo -e "${RED}Error: nfpm installation failed or not found${NC}"
            echo "Please install nfpm manually:"
            echo "  go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"
            echo "  export PATH=\$HOME/go/bin:\$PATH"
            exit 1
        fi
    fi
fi

# 1. 构建 Agent 二进制
echo -e "${GREEN}[1/4] Building agent binary...${NC}"
CGO_ENABLED=0 GOOS=$OS GOARCH=$ARCH go build -ldflags "\
    -X main.serverHost=$SERVER_HOST \
    -X main.buildVersion=$VERSION \
    -X main.buildTime=$BUILD_TIME \
    -s -w" \
    -o "$DIST_DIR/mxsec-agent-$OS-$ARCH" \
    ./cmd/agent

# 2. 创建临时目录结构
echo -e "${GREEN}[2/4] Preparing package structure...${NC}"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# 创建目录结构
mkdir -p "$TEMP_DIR/usr/bin"
mkdir -p "$TEMP_DIR/etc/systemd/system"
mkdir -p "$TEMP_DIR/var/lib/mxsec-agent"
mkdir -p "$TEMP_DIR/var/lib/mxsec-agent/certs"
mkdir -p "$TEMP_DIR/var/log/mxsec-agent"
mkdir -p "$TEMP_DIR/scripts"

# 复制二进制文件
cp "$DIST_DIR/mxsec-agent-$OS-$ARCH" "$TEMP_DIR/usr/bin/mxsec-agent"
chmod +x "$TEMP_DIR/usr/bin/mxsec-agent"

# 复制 systemd service 文件
cp deploy/systemd/mxsec-agent.service "$TEMP_DIR/etc/systemd/system/mxsec-agent.service"

# 复制证书文件（如果存在）
CERTS_INCLUDED=false
if [ -d "$CERT_DIR" ]; then
    if [ -f "$CERT_DIR/ca.crt" ] && [ -f "$CERT_DIR/client.crt" ] && [ -f "$CERT_DIR/client.key" ]; then
        echo -e "${GREEN}  → 包含证书文件${NC}"
        cp "$CERT_DIR/ca.crt" "$TEMP_DIR/var/lib/mxsec-agent/certs/"
        cp "$CERT_DIR/client.crt" "$TEMP_DIR/var/lib/mxsec-agent/certs/"
        cp "$CERT_DIR/client.key" "$TEMP_DIR/var/lib/mxsec-agent/certs/"
        chmod 644 "$TEMP_DIR/var/lib/mxsec-agent/certs/ca.crt"
        chmod 644 "$TEMP_DIR/var/lib/mxsec-agent/certs/client.crt"
        chmod 600 "$TEMP_DIR/var/lib/mxsec-agent/certs/client.key"
        CERTS_INCLUDED=true
    else
        echo -e "${YELLOW}  → 证书文件不完整，跳过证书打包${NC}"
        echo -e "${YELLOW}    需要: ca.crt, client.crt, client.key${NC}"
        echo -e "${YELLOW}    运行: make certs 生成证书${NC}"
    fi
else
    echo -e "${YELLOW}  → 证书目录不存在: $CERT_DIR${NC}"
    echo -e "${YELLOW}    运行: make certs 生成证书${NC}"
fi

# 创建安装脚本
cat > "$TEMP_DIR/scripts/postinstall.sh" <<'SCRIPT'
#!/bin/bash
systemctl daemon-reload
systemctl enable mxsec-agent
SCRIPT
chmod +x "$TEMP_DIR/scripts/postinstall.sh"

cat > "$TEMP_DIR/scripts/preremove.sh" <<'SCRIPT'
#!/bin/bash
systemctl stop mxsec-agent || true
systemctl disable mxsec-agent || true
SCRIPT
chmod +x "$TEMP_DIR/scripts/preremove.sh"

# 3. 创建 nFPM 配置文件
echo -e "${GREEN}[3/4] Creating nFPM config...${NC}"

# 解析发行版信息（用于 RPM）
RPM_DISTRO=""
RPM_RELEASE="1"
if [ -n "$DISTRO" ]; then
    case "$DISTRO" in
        centos7|el7)
            RPM_DISTRO="el7"
            RPM_RELEASE="1.el7"
            ;;
        centos8|el8)
            RPM_DISTRO="el8"
            RPM_RELEASE="1.el8"
            ;;
        rocky8|rhel8)
            RPM_DISTRO="el8"
            RPM_RELEASE="1.el8"
            ;;
        rocky9|rhel9|el9|centos9|centos-stream9)
            RPM_DISTRO="el9"
            RPM_RELEASE="1.el9"
            ;;
        *)
            RPM_DISTRO=""
            RPM_RELEASE="1"
            ;;
    esac
fi

# RPM 配置
cat > "$TEMP_DIR/nfpm-rpm.yaml" <<EOF
name: mxsec-agent
arch: ${ARCH}
platform: linux
version: ${VERSION}
release: ${RPM_RELEASE}
section: default
priority: extra
maintainer: Matrix Cloud Security Platform <dev@mxsec-platform.local>
description: |
  Matrix Cloud Security Platform Agent
  A lightweight agent for baseline security checks on Linux hosts.
vendor: Matrix Cloud Security Platform
homepage: https://github.com/imkerbos/mxsec-platform
license: Apache-2.0
contents:
  - src: ${TEMP_DIR}/usr/bin/mxsec-agent
    dst: /usr/bin/mxsec-agent
    file_info:
      mode: 0755
      owner: root
      group: root
  - src: ${TEMP_DIR}/etc/systemd/system/mxsec-agent.service
    dst: /etc/systemd/system/mxsec-agent.service
    type: config
    file_info:
      mode: 0644
      owner: root
      group: root
  - dst: /var/lib/mxsec-agent
    type: dir
    file_info:
      mode: 0755
      owner: root
      group: root
  - dst: /var/lib/mxsec-agent/certs
    type: dir
    file_info:
      mode: 0700
      owner: root
      group: root
  - dst: /var/log/mxsec-agent
    type: dir
    file_info:
      mode: 0755
      owner: root
      group: root
EOF

# 如果包含证书，添加证书配置到 RPM YAML
if [ "$CERTS_INCLUDED" = true ]; then
    cat >> "$TEMP_DIR/nfpm-rpm.yaml" <<EOF
  - src: ${TEMP_DIR}/var/lib/mxsec-agent/certs/ca.crt
    dst: /var/lib/mxsec-agent/certs/ca.crt
    file_info:
      mode: 0644
      owner: root
      group: root
  - src: ${TEMP_DIR}/var/lib/mxsec-agent/certs/client.crt
    dst: /var/lib/mxsec-agent/certs/client.crt
    file_info:
      mode: 0644
      owner: root
      group: root
  - src: ${TEMP_DIR}/var/lib/mxsec-agent/certs/client.key
    dst: /var/lib/mxsec-agent/certs/client.key
    file_info:
      mode: 0600
      owner: root
      group: root
EOF
fi

# 添加 RPM scripts
cat >> "$TEMP_DIR/nfpm-rpm.yaml" <<EOF
scripts:
  postinstall: ${TEMP_DIR}/scripts/postinstall.sh
  preremove: ${TEMP_DIR}/scripts/preremove.sh
EOF

# DEB 配置
cat > "$TEMP_DIR/nfpm-deb.yaml" <<EOF
name: mxsec-agent
arch: ${ARCH}
platform: linux
version: ${VERSION}
section: default
priority: extra
maintainer: Matrix Cloud Security Platform <dev@mxsec-platform.local>
description: |
  Matrix Cloud Security Platform Agent
  A lightweight agent for baseline security checks on Linux hosts.
vendor: Matrix Cloud Security Platform
homepage: https://github.com/imkerbos/mxsec-platform
license: Apache-2.0
contents:
  - src: ${TEMP_DIR}/usr/bin/mxsec-agent
    dst: /usr/bin/mxsec-agent
    file_info:
      mode: 0755
      owner: root
      group: root
  - src: ${TEMP_DIR}/etc/systemd/system/mxsec-agent.service
    dst: /etc/systemd/system/mxsec-agent.service
    type: config
    file_info:
      mode: 0644
      owner: root
      group: root
  - dst: /var/lib/mxsec-agent
    type: dir
    file_info:
      mode: 0755
      owner: root
      group: root
  - dst: /var/lib/mxsec-agent/certs
    type: dir
    file_info:
      mode: 0700
      owner: root
      group: root
  - dst: /var/log/mxsec-agent
    type: dir
    file_info:
      mode: 0755
      owner: root
      group: root
EOF

# 如果包含证书，添加证书配置到 DEB YAML
if [ "$CERTS_INCLUDED" = true ]; then
    cat >> "$TEMP_DIR/nfpm-deb.yaml" <<EOF
  - src: ${TEMP_DIR}/var/lib/mxsec-agent/certs/ca.crt
    dst: /var/lib/mxsec-agent/certs/ca.crt
    file_info:
      mode: 0644
      owner: root
      group: root
  - src: ${TEMP_DIR}/var/lib/mxsec-agent/certs/client.crt
    dst: /var/lib/mxsec-agent/certs/client.crt
    file_info:
      mode: 0644
      owner: root
      group: root
  - src: ${TEMP_DIR}/var/lib/mxsec-agent/certs/client.key
    dst: /var/lib/mxsec-agent/certs/client.key
    file_info:
      mode: 0600
      owner: root
      group: root
EOF
fi

# 添加 DEB scripts
cat >> "$TEMP_DIR/nfpm-deb.yaml" <<EOF
scripts:
  postinstall: ${TEMP_DIR}/scripts/postinstall.sh
  preremove: ${TEMP_DIR}/scripts/preremove.sh
EOF

# 4. 打包
echo -e "${GREEN}[4/4] Packaging...${NC}"

# 打包 RPM - 统一使用 amd64/arm64 命名
RPM_ARCH="$ARCH"

# RPM 包名（包含发行版信息）
if [ -n "$RPM_DISTRO" ]; then
    RPM_PKG_NAME="mxsec-agent-${VERSION}-${RPM_RELEASE}.${RPM_ARCH}.rpm"
else
    RPM_PKG_NAME="mxsec-agent-${VERSION}-${RPM_ARCH}.rpm"
fi

$NFPM_CMD pkg --packager rpm --config "$TEMP_DIR/nfpm-rpm.yaml" --target "$PACKAGE_DIR/$RPM_PKG_NAME"
echo -e "${GREEN}✓ RPM package: $PACKAGE_DIR/$RPM_PKG_NAME${NC}"

# 打包 DEB
if [ "$ARCH" = "amd64" ]; then
    DEB_ARCH="amd64"
elif [ "$ARCH" = "arm64" ]; then
    DEB_ARCH="arm64"
else
    DEB_ARCH="$ARCH"
fi

# DEB 包名（包含发行版信息）
DEB_DISTRO=""
DEB_RELEASE="1"
if [ -n "$DISTRO" ]; then
    case "$DISTRO" in
        debian10|buster)
            DEB_DISTRO="debian10"
            DEB_RELEASE="1~debian10"
            ;;
        debian11|bullseye)
            DEB_DISTRO="debian11"
            DEB_RELEASE="1~debian11"
            ;;
        debian12|bookworm)
            DEB_DISTRO="debian12"
            DEB_RELEASE="1~debian12"
            ;;
        ubuntu20|focal)
            DEB_DISTRO="ubuntu20"
            DEB_RELEASE="1~ubuntu20"
            ;;
        ubuntu22|jammy)
            DEB_DISTRO="ubuntu22"
            DEB_RELEASE="1~ubuntu22"
            ;;
        *)
            DEB_DISTRO=""
            DEB_RELEASE="1"
            ;;
    esac
fi

if [ -n "$DEB_DISTRO" ]; then
    DEB_PKG_NAME="mxsec-agent_${VERSION}-${DEB_RELEASE}_${DEB_ARCH}.deb"
else
    DEB_PKG_NAME="mxsec-agent_${VERSION}_${DEB_ARCH}.deb"
fi

$NFPM_CMD pkg --packager deb --config "$TEMP_DIR/nfpm-deb.yaml" --target "$PACKAGE_DIR/$DEB_PKG_NAME"
echo -e "${GREEN}✓ DEB package: $PACKAGE_DIR/$DEB_PKG_NAME${NC}"

echo ""
echo -e "${GREEN}=== 打包完成 ===${NC}"
echo "RPM: $PACKAGE_DIR/$RPM_PKG_NAME"
echo "DEB: $PACKAGE_DIR/$DEB_PKG_NAME"
if [ "$CERTS_INCLUDED" = true ]; then
    echo -e "${GREEN}✓ 证书已包含在包中${NC}"
else
    echo -e "${YELLOW}⚠ 证书未包含，Agent 启动时需要手动部署证书到 /var/lib/mxsec-agent/certs/${NC}"
fi
ls -lh "$PACKAGE_DIR"/mxsec-agent*.{rpm,deb} 2>/dev/null || true
