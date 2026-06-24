#!/bin/bash
# 统一构建脚本 - 只输出 RPM/DEB 包
# 用法: ./scripts/build.sh [target] [options]
#
# Targets:
#   agent           打包 agent
#   baseline        打包 baseline 插件
#   collector       打包 collector 插件
#   fim             打包 fim 插件
#   plugins         打包所有插件
#   all             打包所有 (agent + plugins)
#
# Options:
#   --arch=ARCH     架构: amd64, arm64, all (默认: amd64)
#   --version=VER   版本号 (默认: 从 VERSION 文件读取)
#   --server=HOST   Server 地址 (默认: localhost:6751)

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# 默认值
TARGET="${1:-all}"
ARCH="${GOARCH:-amd64}"
SERVER_HOST="${SERVER_HOST:-localhost:6751}"

# 版本
if [ -n "${VERSION:-}" ]; then
    :
elif [ -f "VERSION" ]; then
    VERSION=$(cat VERSION | tr -d '[:space:]')
else
    VERSION="dev"
fi

# 解析参数
shift 2>/dev/null || true
for arg in "$@"; do
    case $arg in
        --arch=*) ARCH="${arg#*=}" ;;
        --version=*) VERSION="${arg#*=}" ;;
        --server=*) SERVER_HOST="${arg#*=}" ;;
    esac
done

# 输出目录
PKG_DIR="dist/packages"
TMP_DIR=$(mktemp -d)
trap "rm -rf $TMP_DIR" EXIT

BUILD_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

mkdir -p "$PKG_DIR"

echo -e "${GREEN}=== 统一构建脚本 ===${NC}"
echo "Target:  $TARGET"
echo "Version: $VERSION"
echo "Arch:    $ARCH"
echo "Server:  $SERVER_HOST"
echo ""

# 检查 nFPM
NFPM_CMD=""
if command -v nfpm &> /dev/null; then
    NFPM_CMD="nfpm"
elif [ -f "$HOME/go/bin/nfpm" ]; then
    NFPM_CMD="$HOME/go/bin/nfpm"
elif [ -n "$GOPATH" ] && [ -f "$GOPATH/bin/nfpm" ]; then
    NFPM_CMD="$GOPATH/bin/nfpm"
else
    echo -e "${YELLOW}安装 nFPM...${NC}"
    go install github.com/goreleaser/nfpm/v2/cmd/nfpm@latest
    NFPM_CMD="$HOME/go/bin/nfpm"
fi

# 获取架构列表
#
# 支持架构 (M1-7 信创扩展):
#   amd64      — 主流 x86_64 (CentOS/Rocky/Ubuntu/Debian)
#   arm64      — ARM64 (Kylin V10 ARM64 / Ampere Altra / Apple Silicon Linux)
#   loong64    — 龙芯 LoongArch64 (UOS 1060 / 中标麒麟 / Anolis Loong 23)
#   all        — amd64 + arm64
#   xc         — amd64 + arm64 + loong64 (信创全栈)
get_archs() {
    case "$ARCH" in
        all) echo "amd64 arm64" ;;
        xc)  echo "amd64 arm64 loong64" ;;
        *)   echo "$ARCH" ;;
    esac
}

# 打包 Agent
package_agent() {
    local arch=$1
    echo -e "${GREEN}[PACKAGE] Agent ($arch)${NC}"

    # 编译
    local bin="$TMP_DIR/mxcwpp-agent-$arch"
    local sign_flag=""
    if [ -n "${SIGN_PUBLIC_KEY:-}" ]; then
        sign_flag="-X main.signPublicKey=$SIGN_PUBLIC_KEY"
    fi
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -ldflags \
        "-X main.serverHost=$SERVER_HOST -X main.buildVersion=$VERSION -X main.buildTime=$BUILD_TIME $sign_flag -s -w" \
        -o "$bin" ./cmd/agent

    # 准备打包目录
    local pkg_tmp="$TMP_DIR/pkg-agent-$arch"
    mkdir -p "$pkg_tmp/usr/bin"
    mkdir -p "$pkg_tmp/etc/systemd/system"
    mkdir -p "$pkg_tmp/var/lib/mxcwpp-agent/certs"
    mkdir -p "$pkg_tmp/var/log/mxcwpp-agent"
    mkdir -p "$pkg_tmp/scripts"

    cp "$bin" "$pkg_tmp/usr/bin/mxcwpp-agent"
    chmod +x "$pkg_tmp/usr/bin/mxcwpp-agent"
    cp deploy/systemd/mxcwpp-agent.service "$pkg_tmp/etc/systemd/system/"

    # systemd preset（推荐开机启动）
    mkdir -p "$pkg_tmp/usr/lib/systemd/system-preset"
    echo "enable mxcwpp-agent.service" > "$pkg_tmp/usr/lib/systemd/system-preset/90-mxcwpp.preset"

    # 证书（如果存在）
    local cert_dir="deploy/certs"
    if [ -f "$cert_dir/ca.crt" ] && [ -f "$cert_dir/client.crt" ] && [ -f "$cert_dir/client.key" ]; then
        cp "$cert_dir/ca.crt" "$cert_dir/client.crt" "$cert_dir/client.key" "$pkg_tmp/var/lib/mxcwpp-agent/certs/"
    fi

    # 脚本
    cat > "$pkg_tmp/scripts/postinstall.sh" <<'SCRIPT'
#!/bin/bash
# $1 == 1: 首次安装 (DEB: configure with empty $2, RPM: 1)
# $1 == 2: 升级安装 (DEB: configure with non-empty $2, RPM: 2)

if [ "$1" = "configure" -a -z "$2" ] || [ "$1" == "1" ]; then
    # 首次安装：启用并启动服务
    systemctl daemon-reload
    systemctl enable mxcwpp-agent
    systemctl start mxcwpp-agent
elif [ "$1" = "configure" -a -n "$2" ] || [ "$1" == "2" ]; then
    # 升级：只 reload daemon，服务保持运行
    systemctl daemon-reload
fi
SCRIPT
    cat > "$pkg_tmp/scripts/preremove.sh" <<'SCRIPT'
#!/bin/bash
# $1 == 0: 卸载 (DEB: remove, RPM: 0)
# $1 == 1: 升级 (RPM: 1)

if [ "$1" == "remove" ] || [ "$1" == "0" ]; then
    # 只有真正卸载时才停止和禁用服务
    systemctl stop mxcwpp-agent || true
    systemctl disable mxcwpp-agent || true
    # 清理 systemd drop-in 配置（如业务线配置）
    rm -rf /etc/systemd/system/mxcwpp-agent.service.d || true
    # 清理运行时数据（证书、插件、日志）
    rm -rf /var/lib/mxcwpp-agent || true
    rm -rf /var/log/mxcwpp-agent || true
    systemctl daemon-reload || true
fi
# 升级时 ($1 == 1) 不做任何操作，保持服务运行
SCRIPT
    chmod +x "$pkg_tmp/scripts/"*.sh

    # 构建证书 contents 条目
    local cert_contents=""
    if [ -f "$pkg_tmp/var/lib/mxcwpp-agent/certs/ca.crt" ]; then
        cert_contents="  - src: $pkg_tmp/var/lib/mxcwpp-agent/certs/ca.crt
    dst: /var/lib/mxcwpp-agent/certs/ca.crt
    file_info: { mode: 0644 }
    type: config
  - src: $pkg_tmp/var/lib/mxcwpp-agent/certs/client.crt
    dst: /var/lib/mxcwpp-agent/certs/client.crt
    file_info: { mode: 0644 }
    type: config
  - src: $pkg_tmp/var/lib/mxcwpp-agent/certs/client.key
    dst: /var/lib/mxcwpp-agent/certs/client.key
    file_info: { mode: 0600 }
    type: config"
    fi

    # nFPM 配置 - 统一使用 amd64/arm64 命名
    cat > "$pkg_tmp/nfpm.yaml" <<EOF
name: mxcwpp-agent
arch: $arch
platform: linux
version: $VERSION
vendor: MxCwpp Platform
homepage: https://github.com/matrixplusio/mxcwpp
maintainer: MxCwpp Platform <dev@mxcwpp.local>
description: Matrix Cloud Security Platform Agent - 矩阵云安全平台主机安全Agent
license: Proprietary
contents:
  - src: $pkg_tmp/usr/bin/mxcwpp-agent
    dst: /usr/bin/mxcwpp-agent
    file_info: { mode: 0755 }
  - src: $pkg_tmp/etc/systemd/system/mxcwpp-agent.service
    dst: /etc/systemd/system/mxcwpp-agent.service
    type: config
  - src: $pkg_tmp/usr/lib/systemd/system-preset/90-mxcwpp.preset
    dst: /usr/lib/systemd/system-preset/90-mxcwpp.preset
  - dst: /var/lib/mxcwpp-agent
    type: dir
  - dst: /var/lib/mxcwpp-agent/certs
    type: dir
    file_info: { mode: 0700 }
  - dst: /var/log/mxcwpp-agent
    type: dir
$cert_contents
scripts:
  postinstall: $pkg_tmp/scripts/postinstall.sh
  preremove: $pkg_tmp/scripts/preremove.sh
EOF

    # 打包 - 统一使用 amd64/arm64 命名
    $NFPM_CMD pkg -f "$pkg_tmp/nfpm.yaml" -p rpm -t "$PKG_DIR/mxcwpp-agent-${VERSION}-${arch}.rpm"
    $NFPM_CMD pkg -f "$pkg_tmp/nfpm.yaml" -p deb -t "$PKG_DIR/mxcwpp-agent_${VERSION}_${arch}.deb"

    echo -e "  ${GREEN}✓${NC} mxcwpp-agent-${VERSION}-${arch}.rpm"
    echo -e "  ${GREEN}✓${NC} mxcwpp-agent_${VERSION}_${arch}.deb"
}

# 构建插件（只输出二进制文件，不打包成 RPM/DEB）
# 插件由 Agent 动态下载和管理，不需要系统级安装
build_plugin() {
    local name=$1
    local arch=$2
    echo -e "${GREEN}[BUILD] Plugin: $name ($arch)${NC}"

    # 输出目录：dist/plugins/
    local plugin_dir="dist/plugins"
    mkdir -p "$plugin_dir"

    # 编译二进制文件（注入版本号和构建时间）
    local output_name="${name}-linux-${arch}"
    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -ldflags \
        "-X main.buildVersion=$VERSION -X main.buildTime=$BUILD_TIME -s -w" \
        -o "$plugin_dir/$output_name" ./plugins/$name

    chmod +x "$plugin_dir/$output_name"

    echo -e "  ${GREEN}✓${NC} $plugin_dir/$output_name"
}

# 构建 Scanner 插件（tar.gz 包，包含 scanner + clamscan + yr）
# Scanner 与其他插件不同，需要自带扫描引擎二进制
build_scanner() {
    local arch=$1
    echo -e "${GREEN}[BUILD] Plugin: scanner ($arch) [tar.gz bundle]${NC}"

    local plugin_dir="dist/plugins"
    mkdir -p "$plugin_dir"

    # 1. 编译 scanner 二进制
    local staging="$TMP_DIR/scanner-bundle-$arch"
    rm -rf "$staging"
    mkdir -p "$staging/bin" "$staging/etc"

    CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -ldflags \
        "-X main.buildVersion=$VERSION -X main.buildTime=$BUILD_TIME -s -w" \
        -o "$staging/scanner" ./plugins/scanner

    chmod +x "$staging/scanner"

    # 2. 下载依赖（如果尚未缓存）
    "$SCRIPT_DIR/download-scanner-deps.sh" "$arch"

    # 3. 复制 clamscan
    local clamav_dir="build/deps/clamav-${CLAMAV_VERSION:-1.5.2}-${arch}"
    if [ -f "$clamav_dir/clamscan" ]; then
        cp "$clamav_dir/clamscan" "$staging/bin/clamscan"
        chmod +x "$staging/bin/clamscan"
        echo -e "  ${GREEN}✓${NC} bin/clamscan"
    else
        echo -e "  ${YELLOW}⚠${NC} clamscan 未找到，跳过（$clamav_dir/clamscan）"
    fi

    # 4. 复制 yr
    local yarax_dir="build/deps/yarax-${YARAX_VERSION:-1.15.0}-${arch}"
    if [ -f "$yarax_dir/yr" ]; then
        cp "$yarax_dir/yr" "$staging/bin/yr"
        chmod +x "$staging/bin/yr"
        echo -e "  ${GREEN}✓${NC} bin/yr"
    else
        echo -e "  ${YELLOW}⚠${NC} yr 未找到，跳过（$yarax_dir/yr）"
    fi

    # 5. 复制 freshclam 配置（如果存在）
    if [ -f "deploy/config/freshclam.conf" ]; then
        cp "deploy/config/freshclam.conf" "$staging/etc/freshclam.conf"
    fi

    # 6. 打包为 tar.gz
    local output_name="scanner-linux-${arch}.tar.gz"
    tar -czf "$plugin_dir/$output_name" -C "$staging" .

    echo -e "  ${GREEN}✓${NC} $plugin_dir/$output_name"

    # 7. 计算 SHA256（供组件管理使用）
    local sha256
    sha256=$(sha256sum "$plugin_dir/$output_name" | awk '{print $1}')
    echo -e "  SHA256: $sha256"
}

# 主逻辑
case "$TARGET" in
    agent)
        for arch in $(get_archs); do package_agent $arch; done
        ;;
    baseline)
        for arch in $(get_archs); do build_plugin baseline $arch; done
        ;;
    collector)
        for arch in $(get_archs); do build_plugin collector $arch; done
        ;;
    fim)
        for arch in $(get_archs); do build_plugin fim $arch; done
        ;;
    scanner)
        for arch in $(get_archs); do build_scanner $arch; done
        ;;
    remediation)
        for arch in $(get_archs); do build_plugin remediation $arch; done
        ;;
    avscanner)
        for arch in $(get_archs); do build_plugin avscanner $arch; done
        ;;
    plugins)
        for arch in $(get_archs); do
            build_plugin baseline $arch
            build_plugin collector $arch
            build_plugin fim $arch
            build_plugin remediation $arch
            build_plugin avscanner $arch
            build_scanner $arch || echo -e "${YELLOW}[WARN] scanner 构建失败（依赖下载问题），已跳过。可单独执行: $0 scanner${NC}"
        done
        ;;
    all)
        for arch in $(get_archs); do
            package_agent $arch
            build_plugin baseline $arch
            build_plugin collector $arch
            build_plugin fim $arch
            build_plugin remediation $arch
            build_plugin avscanner $arch
            build_scanner $arch || echo -e "${YELLOW}[WARN] scanner 构建失败（依赖下载问题），已跳过。可单独执行: $0 scanner${NC}"
        done
        ;;
    *)
        echo -e "${RED}Unknown target: $TARGET${NC}"
        echo "Usage: $0 [agent|baseline|collector|fim|scanner|remediation|avscanner|plugins|all] [--arch=amd64|arm64|all]"
        exit 1
        ;;
esac

echo ""
echo -e "${GREEN}=== 构建完成 ===${NC}"
echo "Agent packages (RPM/DEB):"
ls -lh "$PKG_DIR"/mxcwpp-agent*.{rpm,deb} 2>/dev/null || echo "  (none)"
echo ""
echo "Plugin binaries:"
ls -lh dist/plugins/ 2>/dev/null || echo "  (none)"
