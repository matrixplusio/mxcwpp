#!/bin/bash
#
# 打包生产部署包
#
# 使用方法:
#   ./scripts/package-deploy.sh
#   ./scripts/package-deploy.sh --version v1.0.0 --registry harbor.io/mxsec
#
# 流程:
#   1. 开发机: ./scripts/build-images.sh --version v1.0.0 [--registry xxx --push]
#   2. 开发机: ./scripts/package-deploy.sh --version v1.0.0 [--registry xxx]
#   3. 生产机: tar -xzf mxsec-platform-v1.0.0.tar.gz && cd mxsec-platform-v1.0.0 && ./deploy.sh
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

PACKAGE_NAME="mxsec-platform-${VERSION}"
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

# 生成 docker-compose.yml（纯 image 模式，无 build）
if [ -n "$REGISTRY" ]; then
    IMAGE_PREFIX="${REGISTRY}/"
else
    IMAGE_PREFIX=""
fi

cat > "$PACKAGE_DIR/docker-compose.yml" << EOF
version: '3.8'

services:
  mysql:
    image: mysql:8.0
    container_name: mxsec-mysql
    restart: always
    environment:
      MYSQL_ROOT_PASSWORD: \${MYSQL_ROOT_PASSWORD}
      MYSQL_DATABASE: \${MYSQL_DATABASE:-mxsec}
      MYSQL_USER: \${MYSQL_USER:-mxsec_user}
      MYSQL_PASSWORD: \${MYSQL_PASSWORD}
      TZ: \${TZ:-Asia/Shanghai}
    volumes:
      - \${DATA_DIR}/mysql:/var/lib/mysql
      - ./init.sql:/docker-entrypoint-initdb.d/init.sql:ro
      - ./config/mysql.cnf:/etc/mysql/conf.d/custom.cnf:ro
      - \${DATA_DIR}/logs/mysql:/var/log/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost", "-u", "root", "-p\${MYSQL_ROOT_PASSWORD}"]
      interval: 10s
      timeout: 5s
      retries: 10
      start_period: 30s
    networks:
      - mxsec-net
    deploy:
      resources:
        limits:
          memory: 4G

  agentcenter:
    image: ${IMAGE_PREFIX}mxsec-agentcenter:\${VERSION:-${VERSION}}
    container_name: mxsec-agentcenter
    restart: always
    depends_on:
      mysql:
        condition: service_healthy
    ports:
      - "\${GRPC_PORT:-6751}:6751"
    volumes:
      - ./config/server.yaml:/etc/mxsec-platform/server.yaml:ro
      - ./certs:/etc/mxsec-platform/certs:ro
      - \${DATA_DIR}/logs/agentcenter:/var/log/mxsec-platform
      - \${DATA_DIR}/plugins:/opt/mxsec-platform/plugins
    environment:
      TZ: \${TZ:-Asia/Shanghai}
    healthcheck:
      test: ["CMD-SHELL", "nc -z localhost 6751 || exit 1"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    networks:
      - mxsec-net
    deploy:
      resources:
        limits:
          memory: 4G

  manager:
    image: ${IMAGE_PREFIX}mxsec-manager:\${VERSION:-${VERSION}}
    container_name: mxsec-manager
    restart: always
    depends_on:
      mysql:
        condition: service_healthy
      agentcenter:
        condition: service_healthy
    ports:
      - "\${MANAGER_PORT:-8080}:8080"
    volumes:
      - ./config/server.yaml:/etc/mxsec-platform/server.yaml:ro
      - ./certs:/etc/mxsec-platform/certs:ro
      - \${DATA_DIR}/logs/manager:/var/log/mxsec-platform
      - \${DATA_DIR}/plugins:/opt/mxsec-platform/plugins:ro
      - \${DATA_DIR}/uploads:/opt/mxsec-platform/uploads
    environment:
      TZ: \${TZ:-Asia/Shanghai}
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 60s
    networks:
      - mxsec-net
    deploy:
      resources:
        limits:
          memory: 4G

  ui:
    image: ${IMAGE_PREFIX}mxsec-ui:\${VERSION:-${VERSION}}
    container_name: mxsec-ui
    restart: always
    depends_on:
      manager:
        condition: service_healthy
    ports:
      - "\${HTTP_PORT:-80}:80"
      - "\${HTTPS_PORT:-443}:443"
    volumes:
      - ./config/nginx.conf:/etc/nginx/conf.d/default.conf:ro
      - ./certs/ssl:/etc/nginx/ssl:ro
      - \${DATA_DIR}/logs/nginx:/var/log/nginx
    environment:
      TZ: \${TZ:-Asia/Shanghai}
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost/health"]
      interval: 30s
      timeout: 10s
      retries: 3
    networks:
      - mxsec-net

networks:
  mxsec-net:
    driver: bridge
EOF

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
