#!/bin/bash
# Tetragon 安装和策略部署脚本
# 要求：Linux kernel >= 4.19, systemd
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TETRAGON_VERSION="${TETRAGON_VERSION:-1.2.0}"

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*"; }

# 检查前置条件
check_prerequisites() {
    local kernel_version
    kernel_version=$(uname -r | cut -d. -f1-2)
    local kernel_major kernel_minor
    kernel_major=$(echo "$kernel_version" | cut -d. -f1)
    kernel_minor=$(echo "$kernel_version" | cut -d. -f2)

    if [ "$kernel_major" -lt 4 ] || { [ "$kernel_major" -eq 4 ] && [ "$kernel_minor" -lt 19 ]; }; then
        log "ERROR: 内核版本 $kernel_version 不满足要求 (需要 >= 4.19)"
        exit 1
    fi
    log "内核版本检查通过: $(uname -r)"

    if ! command -v systemctl &>/dev/null; then
        log "ERROR: 需要 systemd"
        exit 1
    fi
}

# 安装 Tetragon
install_tetragon() {
    if command -v tetra &>/dev/null; then
        log "Tetragon 已安装: $(tetra version 2>/dev/null || echo 'unknown')"
        return 0
    fi

    log "安装 Tetragon v${TETRAGON_VERSION}..."

    local arch
    arch=$(uname -m)
    case "$arch" in
        x86_64)  arch="amd64" ;;
        aarch64) arch="arm64" ;;
        *)       log "ERROR: 不支持的架构 $arch"; exit 1 ;;
    esac

    # 方式1: 包管理器 (推荐)
    if command -v apt-get &>/dev/null; then
        curl -sL "https://github.com/cilium/tetragon/releases/download/v${TETRAGON_VERSION}/tetragon-${TETRAGON_VERSION}-${arch}.deb" -o /tmp/tetragon.deb
        dpkg -i /tmp/tetragon.deb
        rm -f /tmp/tetragon.deb
    elif command -v yum &>/dev/null; then
        curl -sL "https://github.com/cilium/tetragon/releases/download/v${TETRAGON_VERSION}/tetragon-${TETRAGON_VERSION}-${arch}.rpm" -o /tmp/tetragon.rpm
        rpm -ivh /tmp/tetragon.rpm
        rm -f /tmp/tetragon.rpm
    else
        log "ERROR: 不支持的包管理器，请手动安装 Tetragon"
        exit 1
    fi

    log "Tetragon 安装完成"
}

# 部署 TracingPolicy
deploy_policies() {
    local policy_dir="/etc/tetragon/tetragon.tp.d"
    mkdir -p "$policy_dir"

    log "部署 MxSec TracingPolicy..."

    for policy in "$SCRIPT_DIR"/*.yaml; do
        local name
        name=$(basename "$policy")
        cp "$policy" "$policy_dir/$name"
        log "  已部署: $name"
    done

    log "策略文件部署完成"
}

# 配置 Tetragon
configure_tetragon() {
    local config_file="/etc/tetragon/tetragon.yaml"
    mkdir -p /etc/tetragon

    cat > "$config_file" <<'EOF'
# MxSec Tetragon 配置
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
EOF

    log "Tetragon 配置已写入: $config_file"
}

# 启动 Tetragon
start_tetragon() {
    log "启动 Tetragon 服务..."
    systemctl daemon-reload
    systemctl enable tetragon
    systemctl restart tetragon

    # 等待 socket 就绪
    local retries=10
    while [ $retries -gt 0 ]; do
        if [ -S /var/run/tetragon/tetragon.sock ]; then
            log "Tetragon 已就绪 (socket: /var/run/tetragon/tetragon.sock)"
            return 0
        fi
        sleep 1
        retries=$((retries - 1))
    done

    log "WARNING: Tetragon socket 未就绪，请检查服务状态: systemctl status tetragon"
}

# 验证
verify() {
    log "验证 Tetragon 策略..."

    if ! command -v tetra &>/dev/null; then
        log "WARNING: tetra CLI 不可用，跳过验证"
        return 0
    fi

    local policies
    policies=$(tetra tracingpolicy list 2>/dev/null || true)
    if echo "$policies" | grep -q "mxsec"; then
        log "策略加载成功:"
        echo "$policies" | grep "mxsec" | while read -r line; do
            log "  $line"
        done
    else
        log "WARNING: 未检测到 MxSec 策略，可能需要重启 Tetragon"
    fi
}

# 主流程
main() {
    log "=== MxSec Tetragon 部署 ==="
    check_prerequisites
    install_tetragon
    configure_tetragon
    deploy_policies
    start_tetragon
    verify
    log "=== 部署完成 ==="
}

main "$@"
