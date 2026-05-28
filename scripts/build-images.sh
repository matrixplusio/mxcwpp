#!/bin/bash
#
# 构建并推送 Docker 镜像
#
# 使用方法:
#   ./scripts/build-images.sh                          # 构建到本地
#   ./scripts/build-images.sh --push                   # 构建并推送
#   ./scripts/build-images.sh --registry harbor.io/mxsec --push
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 启用 BuildKit（缓存挂载需要）
export DOCKER_BUILDKIT=1

# 默认值
VERSION="${VERSION:-v1.0.0}"
REGISTRY="${REGISTRY:-}"
PUSH=false

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
        --push)
            PUSH=true
            shift
            ;;
        *)
            echo "未知参数: $1"
            exit 1
            ;;
    esac
done

# 镜像名称
if [ -n "$REGISTRY" ]; then
    PREFIX="${REGISTRY}/"
else
    PREFIX=""
fi

IMAGES=(
    "mxsec-agentcenter"
    "mxsec-manager"
    "mxsec-consumer"
    "mxsec-ui"
)

echo "========================================"
echo "构建 Docker 镜像"
echo "版本: $VERSION"
echo "仓库: ${REGISTRY:-本地}"
echo "========================================"

cd "$PROJECT_ROOT"

# 构建 AgentCenter
echo ""
echo "[1/4] 构建 AgentCenter..."
docker build \
    --network=host \
    --build-arg VERSION="${VERSION}" \
    -f deploy/docker/Dockerfile.agentcenter \
    -t "${PREFIX}mxsec-agentcenter:${VERSION}" \
    -t "${PREFIX}mxsec-agentcenter:latest" \
    .

# 构建 Manager
echo ""
echo "[2/4] 构建 Manager..."
docker build \
    --network=host \
    --build-arg VERSION="${VERSION}" \
    -f deploy/docker/Dockerfile.manager \
    -t "${PREFIX}mxsec-manager:${VERSION}" \
    -t "${PREFIX}mxsec-manager:latest" \
    .

echo ""
echo "[3/4] 构建 Consumer..."
docker build \
    --network=host \
    --build-arg VERSION="${VERSION}" \
    -f deploy/docker/Dockerfile.consumer \
    -t "${PREFIX}mxsec-consumer:${VERSION}" \
    -t "${PREFIX}mxsec-consumer:latest" \
    .

# 构建 UI
echo ""
echo "[4/4] 构建 UI..."
docker build \
    --network=host \
    --build-arg VERSION="${VERSION}" \
    -f deploy/docker/Dockerfile.ui \
    -t "${PREFIX}mxsec-ui:${VERSION}" \
    -t "${PREFIX}mxsec-ui:latest" \
    .

echo ""
echo "[5/5] 编译 mxctl 部署工具（host 二进制）..."
# mxctl 是部署工具 binary，不在容器内跑；改 internal/deploy/cluster/render.go 等
# 时若不重 build，prometheus.yml 等模板配置不会更新。
export PATH=/usr/local/go/bin:$PATH
go build -o ./bin/mxctl ./cmd/tools/mxctl && ls -la ./bin/mxctl

echo ""
echo "构建完成!"
docker images | grep mxsec

# 推送
if [ "$PUSH" = true ]; then
    echo ""
    echo "推送镜像到 $REGISTRY..."
    for img in "${IMAGES[@]}"; do
        docker push "${PREFIX}${img}:${VERSION}"
        docker push "${PREFIX}${img}:latest"
    done
    echo "推送完成!"
fi

echo ""
echo "========================================"
echo "下一步: 打包部署包"
echo "  ./scripts/package-deploy.sh --version $VERSION"
echo "========================================"
