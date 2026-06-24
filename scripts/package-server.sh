#!/bin/bash

# Server 打包脚本（使用 nFPM）
# 生成 RPM 和 DEB 安装包（包含 AgentCenter 和 Manager）

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# 配置
VERSION="${MXCWPP_VERSION:-1.0.0}"
BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
ARCH="${GOARCH:-amd64}"
OS="${GOOS:-linux}"
DISTRO="${MXCWPP_DISTRO:-}"  # 发行版：centos7, centos8, rocky8, rocky9, debian10, debian11, debian12 等

# 输出目录
DIST_DIR="dist/server"
PACKAGE_DIR="dist/packages"
mkdir -p "$DIST_DIR"
mkdir -p "$PACKAGE_DIR"

echo -e "${GREEN}=== Server 打包脚本 ===${NC}"
echo "Version: $VERSION"
echo "OS/Arch: $OS/$ARCH"
echo "Distribution: ${DISTRO:-通用}"
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
        elif [ -f "/Users/kerbos/Workspaces/go/bin/nfpm" ]; then
            NFPM_CMD="/Users/kerbos/Workspaces/go/bin/nfpm"
        elif command -v nfpm &> /dev/null; then
            NFPM_CMD="nfpm"
        else
            echo -e "${RED}Error: nfpm installation failed or not found${NC}"
            echo "Please install nfpm manually:"
            echo "  go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest"
            echo "  export PATH=\$HOME/go/bin:\$PATH"
            echo ""
            echo "Checking common locations..."
            echo "  ~/go/bin/nfpm: $([ -f "$HOME/go/bin/nfpm" ] && echo "EXISTS" || echo "NOT FOUND")"
            echo "  GOPATH/bin/nfpm: $([ -n "$GOPATH" ] && [ -f "$GOPATH/bin/nfpm" ] && echo "EXISTS" || echo "NOT FOUND")"
            exit 1
        fi
    fi
fi

# 1. 构建 Server 二进制
echo -e "${GREEN}[1/5] Building server binaries...${NC}"
go build -ldflags "-s -w" -o "$DIST_DIR/agentcenter" ./cmd/server/agentcenter
go build -ldflags "-s -w" -o "$DIST_DIR/manager" ./cmd/server/manager

# 2. 创建临时目录结构
echo -e "${GREEN}[2/5] Preparing package structure...${NC}"
TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

# 创建目录结构
mkdir -p "$TEMP_DIR/usr/bin"
mkdir -p "$TEMP_DIR/etc/systemd/system"
mkdir -p "$TEMP_DIR/etc/mxcwpp"
mkdir -p "$TEMP_DIR/opt/mxcwpp"
mkdir -p "$TEMP_DIR/var/log/mxcwpp"

# 复制二进制文件
cp "$DIST_DIR/agentcenter" "$TEMP_DIR/usr/bin/mxcwpp-agentcenter"
cp "$DIST_DIR/manager" "$TEMP_DIR/usr/bin/mxcwpp-manager"
chmod +x "$TEMP_DIR/usr/bin/mxcwpp-agentcenter"
chmod +x "$TEMP_DIR/usr/bin/mxcwpp-manager"

# 复制 systemd service 文件
cp deploy/systemd/mxcwpp-agentcenter.service "$TEMP_DIR/etc/systemd/system/mxcwpp-agentcenter.service"
cp deploy/systemd/mxcwpp-manager.service "$TEMP_DIR/etc/systemd/system/mxcwpp-manager.service"

# 复制配置文件示例
cp configs/server.yaml.example "$TEMP_DIR/etc/mxcwpp/server.yaml.example"

# 3. 创建安装脚本
echo -e "${GREEN}[3/6] Creating install scripts...${NC}"
mkdir -p "$TEMP_DIR/scripts"

cat > "$TEMP_DIR/scripts/postinstall.sh" <<'SCRIPT_EOF'
#!/bin/bash
systemctl daemon-reload
systemctl enable mxcwpp-agentcenter || true
systemctl enable mxcwpp-manager || true
echo ""
echo "Matrix Cloud Security Platform Server installed successfully!"
echo ""
echo "Next steps:"
echo "1. Copy /etc/mxcwpp/server.yaml.example to /etc/mxcwpp/server.yaml"
echo "2. Edit /etc/mxcwpp/server.yaml and configure database and certificates"
echo "3. Generate certificates: ./scripts/generate-certs.sh"
echo "4. Start services: systemctl start mxcwpp-agentcenter mxcwpp-manager"
SCRIPT_EOF

cat > "$TEMP_DIR/scripts/postremove.sh" <<'SCRIPT_EOF'
#!/bin/bash
systemctl stop mxcwpp-agentcenter || true
systemctl stop mxcwpp-manager || true
systemctl disable mxcwpp-agentcenter || true
systemctl disable mxcwpp-manager || true
SCRIPT_EOF

chmod +x "$TEMP_DIR/scripts/postinstall.sh"
chmod +x "$TEMP_DIR/scripts/postremove.sh"

# 4. 创建 nFPM 配置文件
echo -e "${GREEN}[4/6] Creating nFPM config...${NC}"

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
name: mxcwpp-server
arch: ${ARCH}
platform: linux
version: ${VERSION}
release: ${RPM_RELEASE}
section: default
priority: extra
maintainer: Matrix Cloud Security Platform <dev@mxcwpp.local>
description: |
  Matrix Cloud Security Platform Server
  Includes AgentCenter (gRPC) and Manager (HTTP API) services.
vendor: Matrix Cloud Security Platform
homepage: https://github.com/matrixplusio/mxcwpp
license: Apache-2.0
contents:
  - src: ${TEMP_DIR}/usr/bin/mxcwpp-agentcenter
    dst: /usr/bin/mxcwpp-agentcenter
    file_info:
      mode: 0755
      owner: root
      group: root
  - src: ${TEMP_DIR}/usr/bin/mxcwpp-manager
    dst: /usr/bin/mxcwpp-manager
    file_info:
      mode: 0755
      owner: root
      group: root
  - src: ${TEMP_DIR}/etc/systemd/system/mxcwpp-agentcenter.service
    dst: /etc/systemd/system/mxcwpp-agentcenter.service
    type: config
    file_info:
      mode: 0644
      owner: root
      group: root
  - src: ${TEMP_DIR}/etc/systemd/system/mxcwpp-manager.service
    dst: /etc/systemd/system/mxcwpp-manager.service
    type: config
    file_info:
      mode: 0644
      owner: root
      group: root
  - src: ${TEMP_DIR}/etc/mxcwpp/server.yaml.example
    dst: /etc/mxcwpp/server.yaml.example
    type: config
    file_info:
      mode: 0644
      owner: root
      group: root
  - dst: /opt/mxcwpp
    type: dir
    file_info:
      mode: 0755
      owner: root
      group: root
  - dst: /var/log/mxcwpp
    type: dir
    file_info:
      mode: 0755
      owner: root
      group: root
scripts:
  postinstall: ${TEMP_DIR}/scripts/postinstall.sh
  postremove: ${TEMP_DIR}/scripts/postremove.sh
EOF

# DEB 配置
cat > "$TEMP_DIR/nfpm-deb.yaml" <<EOF
name: mxcwpp-server
arch: ${ARCH}
platform: linux
version: ${VERSION}
section: default
priority: extra
maintainer: Matrix Cloud Security Platform <dev@mxcwpp.local>
description: |
  Matrix Cloud Security Platform Server
  Includes AgentCenter (gRPC) and Manager (HTTP API) services.
vendor: Matrix Cloud Security Platform
homepage: https://github.com/matrixplusio/mxcwpp
license: Apache-2.0
contents:
  - src: ${TEMP_DIR}/usr/bin/mxcwpp-agentcenter
    dst: /usr/bin/mxcwpp-agentcenter
    file_info:
      mode: 0755
      owner: root
      group: root
  - src: ${TEMP_DIR}/usr/bin/mxcwpp-manager
    dst: /usr/bin/mxcwpp-manager
    file_info:
      mode: 0755
      owner: root
      group: root
  - src: ${TEMP_DIR}/etc/systemd/system/mxcwpp-agentcenter.service
    dst: /etc/systemd/system/mxcwpp-agentcenter.service
    type: config
    file_info:
      mode: 0644
      owner: root
      group: root
  - src: ${TEMP_DIR}/etc/systemd/system/mxcwpp-manager.service
    dst: /etc/systemd/system/mxcwpp-manager.service
    type: config
    file_info:
      mode: 0644
      owner: root
      group: root
  - src: ${TEMP_DIR}/etc/mxcwpp/server.yaml.example
    dst: /etc/mxcwpp/server.yaml.example
    type: config
    file_info:
      mode: 0644
      owner: root
      group: root
  - dst: /opt/mxcwpp
    type: dir
    file_info:
      mode: 0755
      owner: root
      group: root
  - dst: /var/log/mxcwpp
    type: dir
    file_info:
      mode: 0755
      owner: root
      group: root
scripts:
  postinstall: ${TEMP_DIR}/scripts/postinstall.sh
  postremove: ${TEMP_DIR}/scripts/postremove.sh
EOF

# 5. 打包
echo -e "${GREEN}[5/6] Packaging...${NC}"

# 打包 RPM
if [ "$ARCH" = "amd64" ]; then
    RPM_ARCH="x86_64"
elif [ "$ARCH" = "arm64" ]; then
    RPM_ARCH="aarch64"
else
    RPM_ARCH="$ARCH"
fi

# RPM 包名（包含发行版信息）
if [ -n "$RPM_DISTRO" ]; then
    RPM_PKG_NAME="mxcwpp-server-${VERSION}-${RPM_RELEASE}.${RPM_ARCH}.rpm"
else
    RPM_PKG_NAME="mxcwpp-server-${VERSION}-${RPM_ARCH}.rpm"
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
    DEB_PKG_NAME="mxcwpp-server_${VERSION}-${DEB_RELEASE}_${DEB_ARCH}.deb"
else
    DEB_PKG_NAME="mxcwpp-server_${VERSION}_${DEB_ARCH}.deb"
fi

$NFPM_CMD pkg --packager deb --config "$TEMP_DIR/nfpm-deb.yaml" --target "$PACKAGE_DIR/$DEB_PKG_NAME"
echo -e "${GREEN}✓ DEB package: $PACKAGE_DIR/$DEB_PKG_NAME${NC}"

echo ""
echo -e "${GREEN}=== 打包完成 ===${NC}"
echo "RPM: $PACKAGE_DIR/$RPM_PKG_NAME"
echo "DEB: $PACKAGE_DIR/$DEB_PKG_NAME"
ls -lh "$PACKAGE_DIR"/mxcwpp-server*.{rpm,deb} 2>/dev/null || true
