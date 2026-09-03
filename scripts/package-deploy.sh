#!/bin/bash
#
# 打包生产部署包
#
# 使用方法:
#   ./scripts/package-deploy.sh
#   ./scripts/package-deploy.sh --version v1.0.0 --registry harbor.io/mxcwpp
#
# 流程:
#   1. 开发机: ./scripts/build-images.sh --version v1.0.0 [--registry xxx --push]
#   2. 开发机: ./scripts/package-deploy.sh --version v1.0.0 [--registry xxx]
#   3. 生产机: tar -xzf mxcwpp-v1.0.0.tar.gz && cd mxcwpp-v1.0.0 && ./deploy.sh
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 默认值
VERSION="${VERSION:-v1.0.0}"
REGISTRY="${REGISTRY:-}"
OUTPUT_DIR="${PROJECT_ROOT}/dist/deploy"

# 解析参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --version)
            VERSION="$2"
            shift 2
            ;;
        --registry)
            REGISTRY="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        *)
            echo "未知参数: $1"
            exit 1
            ;;
    esac
done

PACKAGE_NAME="mxcwpp-${VERSION}"
PACKAGE_DIR="${OUTPUT_DIR}/${PACKAGE_NAME}"

echo "========================================"
echo "打包生产部署包"
echo "版本: $VERSION"
echo "仓库: ${REGISTRY:-本地}"
echo "输出: ${OUTPUT_DIR}/${PACKAGE_NAME}.tar.gz"
echo "========================================"

# 清理并创建目录
rm -rf "$PACKAGE_DIR"
mkdir -p "$PACKAGE_DIR"/{config,certs,certs/ssl}

# 复制部署文件（直接用 deploy/ 下的文件，不再内嵌副本）
cp "$PROJECT_ROOT/deploy/deploy.sh" "$PACKAGE_DIR/"
cp "$PROJECT_ROOT/deploy/init.sql" "$PACKAGE_DIR/"
cp "$PROJECT_ROOT/deploy/README.md" "$PACKAGE_DIR/"
cp "$PROJECT_ROOT/deploy/config/"* "$PACKAGE_DIR/config/"

chmod +x "$PACKAGE_DIR/deploy.sh"

# SBOM：客户合规审计需要知道产品里装了哪些第三方组件。
# 出现 Log4Shell 这类事件时，它决定的是十分钟答出有没有受影响，还是翻两天源码。
if [ -x "$PROJECT_ROOT/scripts/gen-sbom.sh" ]; then
    "$PROJECT_ROOT/scripts/gen-sbom.sh" "$PACKAGE_DIR/sbom.cdx.json" || \
        echo "警告: SBOM 生成失败，发布包缺少物料清单" >&2
fi

# docker-compose.yml：直接复用官方拓扑，只把 image 换成发布镜像。
#
# 此前这里内嵌生成一份独立的 compose，服务集与 deploy/docker-compose.yml 不同——
# 客户拿到的离线包里只有 mysql/agentcenter/manager/ui，没有 Kafka、ClickHouse、
# Redis、Consumer，整条数据管道都不存在。装得起来，但什么都采不到。
# 官方拓扑只能有一份，打包只做镜像前缀替换。
if [ -n "$REGISTRY" ]; then
    IMAGE_PREFIX="${REGISTRY}/"
else
    IMAGE_PREFIX=""
fi

cp "$PROJECT_ROOT/deploy/docker-compose.yml" "$PACKAGE_DIR/docker-compose.yml"

# 去掉 build 段（发布包纯镜像模式），并按需加镜像仓库前缀。
python3 - "$PACKAGE_DIR/docker-compose.yml" "$IMAGE_PREFIX" <<'PYEOF'
import re, sys

path, prefix = sys.argv[1], sys.argv[2]
src = open(path).read()

# 移除 build: 段（含其缩进子项），发布包不在客户机上构建。
out, skip_indent = [], None
for line in src.split("\n"):
    stripped = line.lstrip()
    indent = len(line) - len(stripped)
    if skip_indent is not None:
        if stripped and indent > skip_indent:
            continue
        skip_indent = None
    if stripped.startswith("build:"):
        skip_indent = indent
        continue
    out.append(line)
src = "\n".join(out)

# mxcwpp 自有镜像加仓库前缀；第三方镜像（mysql/redis/gotenberg 等）不动。
if prefix:
    src = re.sub(r"(image:\s+)(mxcwpp-[\w.-]+:)", r"\1" + prefix + r"\2", src)

open(path, "w").write(src)
PYEOF

# 打包
cd "$OUTPUT_DIR"
tar -czf "${PACKAGE_NAME}.tar.gz" "$PACKAGE_NAME"

echo ""
echo "========================================"
echo "打包完成!"
echo ""
echo "部署包: ${OUTPUT_DIR}/${PACKAGE_NAME}.tar.gz"
echo "大小: $(du -h "${PACKAGE_NAME}.tar.gz" | cut -f1)"
echo ""
echo "部署步骤:"
echo "  1. 上传到服务器: scp ${PACKAGE_NAME}.tar.gz root@server:/opt/"
echo "  2. 解压: tar -xzf ${PACKAGE_NAME}.tar.gz"
echo "  3. 部署: cd ${PACKAGE_NAME} && ./deploy.sh"
echo "========================================"
