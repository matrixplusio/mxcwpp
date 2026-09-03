#!/bin/bash
# 下载 Scanner 插件依赖的预编译二进制（ClamAV + YARA-X）
# 按架构下载，缓存到 build/deps/ 避免重复下载
#
# 用法: ./scripts/download-scanner-deps.sh [amd64|arm64|all]
#
# 环境变量:
#   CLAMAV_VERSION    ClamAV 版本 (默认: 1.4.2)
#   YARAX_VERSION     YARA-X 版本 (默认: 0.11.0)
#   MIRROR_URL        自建镜像地址 (可选，优先使用)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 版本配置
CLAMAV_VERSION="${CLAMAV_VERSION:-1.5.2}"
YARAX_VERSION="${YARAX_VERSION:-1.15.0}"

# 缓存目录
DEPS_DIR="$PROJECT_ROOT/build/deps"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() { echo -e "${GREEN}[deps]${NC} $*"; }
warn() { echo -e "${YELLOW}[deps]${NC} $*"; }
err() { echo -e "${RED}[deps]${NC} $*" >&2; }

# 下载文件（带缓存检查）
download() {
    local url="$1"
    local dest="$2"

    if [ -f "$dest" ]; then
        log "已缓存: $(basename "$dest")"
        return 0
    fi

    mkdir -p "$(dirname "$dest")"
    log "下载: $url"
    if ! curl -fSL --progress-bar -o "$dest.tmp" "$url"; then
        rm -f "$dest.tmp"
        return 1
    fi
    mv "$dest.tmp" "$dest"
}

# 下载 ClamAV 并提取 clamscan 二进制
# ClamAV >= 1.0 只提供 RPM/DEB 包，从 GitHub releases 下载后提取
download_clamav() {
    local arch="$1"

    local clamav_arch
    case "$arch" in
        amd64) clamav_arch="x86_64" ;;
        arm64) clamav_arch="aarch64" ;;
        *) err "不支持的架构: $arch"; return 1 ;;
    esac

    local dest_dir="$DEPS_DIR/clamav-${CLAMAV_VERSION}-${arch}"
    local clamscan_bin="$dest_dir/clamscan"

    if [ -f "$clamscan_bin" ]; then
        log "ClamAV clamscan 已就绪: $arch"
        return 0
    fi

    mkdir -p "$dest_dir"

    # 从 GitHub releases 下载 RPM 包
    local rpm_file="$DEPS_DIR/clamav-${CLAMAV_VERSION}.${clamav_arch}.rpm"
    local url=""

    if [ -n "${MIRROR_URL:-}" ]; then
        url="${MIRROR_URL}/clamav/clamav-${CLAMAV_VERSION}.linux.${clamav_arch}.rpm"
    else
        url="https://github.com/Cisco-Talos/clamav/releases/download/clamav-${CLAMAV_VERSION}/clamav-${CLAMAV_VERSION}.linux.${clamav_arch}.rpm"
    fi

    if ! download "$url" "$rpm_file"; then
        err "ClamAV RPM 下载失败: $arch"
        err "请手动下载并放置到: $rpm_file"
        err "下载地址: https://github.com/Cisco-Talos/clamav/releases"
        err "或设置 MIRROR_URL 环境变量指向自建镜像"
        return 1
    fi

    # 从 RPM 提取 clamscan 二进制
    log "从 RPM 提取 clamscan ($arch)..."
    local extract_dir="$dest_dir/_rpm_extract"
    mkdir -p "$extract_dir"

    # 优先用 bsdtar/tar（macOS + Linux 通用），回退到 rpm2cpio
    if tar -xf "$rpm_file" -C "$extract_dir" 2>/dev/null; then
        true
    elif command -v rpm2cpio &>/dev/null; then
        (cd "$extract_dir" && rpm2cpio "$rpm_file" | cpio -idm 2>/dev/null)
    else
        err "无法解压 RPM：tar 不支持且 rpm2cpio 未安装"
        err "macOS: brew install rpm2cpio | Linux: dnf install rpm-tools"
        rm -rf "$extract_dir"
        return 1
    fi

    # 查找 clamscan
    local found=""
    found=$(find "$extract_dir" -name "clamscan" -type f | head -1)

    if [ -z "$found" ]; then
        err "未在 RPM 中找到 clamscan 二进制"
        rm -rf "$extract_dir"
        return 1
    fi

    cp "$found" "$clamscan_bin"
    chmod +x "$clamscan_bin"

    # 复制依赖的共享库
    find "$extract_dir" \( -name "libclamav*" -o -name "libfreshclam*" -o -name "libjson-c*" \) -type f | while read -r lib; do
        cp "$lib" "$dest_dir/" 2>/dev/null || true
    done

    rm -rf "$extract_dir"
    log "ClamAV clamscan 就绪: $arch"
}

# 下载 YARA-X 预编译二进制
# YARA-X 官方 GitHub Release 提供预编译包
download_yarax() {
    local arch="$1"

    local yarax_arch
    case "$arch" in
        amd64) yarax_arch="x86_64" ;;
        arm64) yarax_arch="aarch64" ;;
        *) err "不支持的架构: $arch"; return 1 ;;
    esac

    local dest_dir="$DEPS_DIR/yarax-${YARAX_VERSION}-${arch}"
    local yr_bin="$dest_dir/yr"

    if [ -f "$yr_bin" ]; then
        log "YARA-X yr 已就绪: $arch"
        return 0
    fi

    mkdir -p "$dest_dir"

    local archive="$DEPS_DIR/yara-x-v${YARAX_VERSION}-${yarax_arch}-unknown-linux-gnu.gz"
    local url=""

    if [ -n "${MIRROR_URL:-}" ]; then
        url="${MIRROR_URL}/yarax/yara-x-v${YARAX_VERSION}-${yarax_arch}-unknown-linux-gnu.gz"
    else
        url="https://github.com/VirusTotal/yara-x/releases/download/v${YARAX_VERSION}/yara-x-v${YARAX_VERSION}-${yarax_arch}-unknown-linux-gnu.gz"
    fi

    if ! download "$url" "$archive"; then
        err "YARA-X 下载失败: $arch"
        err "请手动下载并放置到: $archive"
        err "或设置 MIRROR_URL 环境变量指向自建镜像"
        return 1
    fi

    # 解压 .tar.gz（包含单个 yr 二进制）
    log "提取 yr ($arch)..."
    if ! tar -xzf "$archive" -C "$dest_dir" 2>/dev/null; then
        # 回退：尝试单文件 gzip
        gunzip -c "$archive" > "$yr_bin" 2>/dev/null || gzip -dc "$archive" > "$yr_bin"
    fi

    if [ ! -s "$yr_bin" ]; then
        err "解压 yr 失败"
        rm -f "$yr_bin"
        return 1
    fi

    chmod +x "$yr_bin"

    log "YARA-X yr 就绪: $arch"
}

# 主逻辑
main() {
    local target_arch="${1:-amd64}"

    local archs
    if [ "$target_arch" = "all" ]; then
        archs="amd64 arm64"
    else
        archs="$target_arch"
    fi

    log "=== 下载 Scanner 依赖 ==="
    log "ClamAV: v${CLAMAV_VERSION}"
    log "YARA-X: v${YARAX_VERSION}"
    log "架构: $archs"
    log "缓存目录: $DEPS_DIR"
    echo ""

    local failed=0
    for arch in $archs; do
        download_clamav "$arch" || { warn "ClamAV ($arch) 下载失败，继续..."; failed=1; }
        download_yarax "$arch" || { warn "YARA-X ($arch) 下载失败，继续..."; failed=1; }
    done

    echo ""
    if [ "$failed" -eq 0 ]; then
        log "=== 所有依赖下载完成 ==="
    else
        warn "=== 部分依赖下载失败，请检查上方日志 ==="
        exit 1
    fi
}

main "$@"
