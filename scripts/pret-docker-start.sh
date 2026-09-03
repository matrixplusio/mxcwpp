#!/bin/bash

# Docker pret 压测环境启动脚本
# 目标：生产式拓扑 + 本地可运行
# 数据面与 dev 保持一致，仅通过额外副本和 HA 组件模拟压测拓扑
# - Kafka: 3 broker
# - Redis: 1 主 1 副本（默认不开 Sentinel）
# - AgentCenter: 2 副本（通过 HAProxy 暴露 localhost:6751）
# - Manager: 2 副本（通过 UI/Nginx 暴露 localhost:3000）
# - Consumer: 2 副本（Kafka ConsumerGroup 分区消费）

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$PROJECT_ROOT/deploy"
DETACH_MODE=true

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--detach)
            DETACH_MODE=true
            shift
            ;;
        --foreground)
            DETACH_MODE=false
            shift
            ;;
        *)
            echo -e "${RED}错误: 不支持的参数 $1${NC}"
            echo "用法: $0 [--detach|--foreground]"
            exit 1
            ;;
    esac
done

trim() {
    local value="$1"
    value="${value#"${value%%[![:space:]]*}"}"
    value="${value%"${value##*[![:space:]]}"}"
    printf '%s' "$value"
}

render_server_config() {
    local output="$1"
    local kafka1 kafka2 kafka3

    kafka1="$(trim "${KAFKA_BROKER_1:-kafka-1:9092}")"
    kafka2="$(trim "${KAFKA_BROKER_2:-kafka-2:9092}")"
    kafka3="$(trim "${KAFKA_BROKER_3:-kafka-3:9092}")"

    sed -i.bak \
        -e "s|__GRPC_PORT__|${GRPC_PORT:-6751}|g" \
        -e "s|__SERVER_HTTP_PORT__|${SERVER_HTTP_PORT:-8080}|g" \
        -e "s|__MYSQL_HOST__|${MYSQL_HOST:-mysql}|g" \
        -e "s|__MYSQL_PORT__|${MYSQL_PORT:-3306}|g" \
        -e "s|__MYSQL_USER__|${MYSQL_USER:-mxcwpp_user}|g" \
        -e "s|__MYSQL_PASSWORD__|${MYSQL_PASSWORD:-123456}|g" \
        -e "s|__MYSQL_DATABASE__|${MYSQL_DATABASE:-mxcwpp}|g" \
        -e "s|__DB_MAX_IDLE_CONNS__|${DB_MAX_IDLE_CONNS:-20}|g" \
        -e "s|__DB_MAX_OPEN_CONNS__|${DB_MAX_OPEN_CONNS:-200}|g" \
        -e "s|__DB_CONN_MAX_LIFETIME__|${DB_CONN_MAX_LIFETIME:-1h}|g" \
        -e "s|__REDIS_ADDR__|${REDIS_ADDR:-redis:6379}|g" \
        -e "s|__REDIS_PASSWORD__|${REDIS_PASSWORD:-}|g" \
        -e "s|__REDIS_DB__|${REDIS_DB:-0}|g" \
        -e "s|__REDIS_POOL_SIZE__|${REDIS_POOL_SIZE:-100}|g" \
        -e "s|__REDIS_SENTINEL__|${REDIS_SENTINEL:-false}|g" \
        -e "s|__REDIS_MASTER_NAME__|${REDIS_MASTER_NAME:-mymaster}|g" \
        -e "s|__REDIS_SENTINEL_ADDR_1__|${REDIS_SENTINEL_ADDR_1:-redis-sentinel-1:26379}|g" \
        -e "s|__REDIS_SENTINEL_ADDR_2__|${REDIS_SENTINEL_ADDR_2:-redis-sentinel-2:26379}|g" \
        -e "s|__REDIS_SENTINEL_ADDR_3__|${REDIS_SENTINEL_ADDR_3:-redis-sentinel-3:26379}|g" \
        -e "s|__KAFKA_ENABLED__|${KAFKA_ENABLED:-true}|g" \
        -e "s|__KAFKA_BROKER_1__|$kafka1|g" \
        -e "s|__KAFKA_BROKER_2__|$kafka2|g" \
        -e "s|__KAFKA_BROKER_3__|$kafka3|g" \
        -e "s|__KAFKA_TOPIC_PREFIX__|${KAFKA_TOPIC_PREFIX:-}|g" \
        -e "s|__CLICKHOUSE_ENABLED__|${CLICKHOUSE_ENABLED:-true}|g" \
        -e "s|__CLICKHOUSE_ADDR__|${CLICKHOUSE_ADDR:-clickhouse:9000}|g" \
        -e "s|__CLICKHOUSE_DATABASE__|${CLICKHOUSE_DATABASE:-mxcwpp}|g" \
        -e "s|__CLICKHOUSE_USER__|${CLICKHOUSE_USER:-default}|g" \
        -e "s|__CLICKHOUSE_PASSWORD__|${CLICKHOUSE_PASSWORD:-}|g" \
        -e "s|__LOG_LEVEL__|${LOG_LEVEL:-debug}|g" \
        -e "s|__LOG_FORMAT__|${LOG_FORMAT:-console}|g" \
        -e "s|__LOG_MAX_AGE__|${LOG_MAX_AGE:-7}|g" \
        -e "s|__HEARTBEAT_INTERVAL__|${HEARTBEAT_INTERVAL:-60}|g" \
        -e "s|__PLUGINS_DIR__|${PLUGINS_DIR:-/opt/mxcwpp/plugins}|g" \
        -e "s|__PLUGINS_BASE_URL__|${PLUGINS_BASE_URL:-}|g" \
        -e "s|__JWT_SECRET__|${JWT_SECRET:-dev-secret-change-in-production}|g" \
        -e "s|__MANAGER_ADDR__|${MANAGER_ADDR:-http://manager:8080}|g" \
        -e "s|__INSTANCE_ID__|${INSTANCE_ID:-}|g" \
        "$output"
    rm -f "$output.bak"
}

warn_legacy_kafka_state() {
    local legacy_kafka_dir="$DEPLOY_DIR/data/kafka"
    local legacy_zk_dir="$DEPLOY_DIR/data/zookeeper"

    if [ -d "$legacy_kafka_dir" ] || [ -d "$legacy_zk_dir" ]; then
        echo -e "${YELLOW}  检测到旧版 Kafka/Zookeeper 数据目录（pret 已切换为 KRaft）:${NC}"
        [ -d "$legacy_kafka_dir" ] && echo "    - $legacy_kafka_dir"
        [ -d "$legacy_zk_dir" ] && echo "    - $legacy_zk_dir"
        echo "    如需回收磁盘，可在确认停服后手动删除这些旧目录。"
    fi
}

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Matrix Cloud Security Platform${NC}"
echo -e "${GREEN}  Docker pret 压测环境启动脚本${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

echo -e "${YELLOW}[1/4] 检查 Docker...${NC}"
if ! command -v docker &> /dev/null; then
    echo -e "${RED}错误: 未找到 Docker，请先安装 Docker${NC}"
    exit 1
fi
echo "  ✓ Docker: $(docker --version)"

if ! docker compose version &> /dev/null && ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}错误: 未找到 docker compose${NC}"
    exit 1
fi
echo "  ✓ docker compose: 已安装"

echo ""
echo -e "${YELLOW}[2/4] 准备环境配置...${NC}"
if [ ! -f "$DEPLOY_DIR/.env" ]; then
    cp "$DEPLOY_DIR/.env.example" "$DEPLOY_DIR/.env"
    echo "  ✓ 已从 .env.example 创建 .env"
else
    echo "  ✓ .env 已存在"
fi

echo ""
echo -e "${YELLOW}[3/4] 生成 server.yaml...${NC}"
source "$DEPLOY_DIR/.env"
cp "$DEPLOY_DIR/config/server.yaml.tpl" "$DEPLOY_DIR/config/server.yaml"
render_server_config "$DEPLOY_DIR/config/server.yaml"
echo "  ✓ server.yaml 已生成（Kafka 3 broker / ClickHouse 单机 / Redis 非 Sentinel）"

echo ""
echo -e "${YELLOW}[4/4] 检查 mTLS 证书...${NC}"
if [ ! -f "$DEPLOY_DIR/certs/ca.crt" ]; then
    echo -e "${YELLOW}  证书文件不存在，正在生成...${NC}"
    cd "$PROJECT_ROOT" && make certs || {
        echo -e "${RED}  错误: 证书生成失败${NC}"
        exit 1
    }
    echo "  ✓ 证书已生成"
else
    echo "  ✓ 证书文件存在"
fi

warn_legacy_kafka_state

MANAGER_REPLICAS="${MANAGER_REPLICAS:-2}"
AGENTCENTER_REPLICAS="${AGENTCENTER_REPLICAS:-2}"
CONSUMER_REPLICAS="${CONSUMER_REPLICAS:-2}"

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  启动 Docker 服务 (pret 模式)...${NC}"
echo -e "${GREEN}========================================${NC}"
echo "  Scales: manager=${MANAGER_REPLICAS}, agentcenter=${AGENTCENTER_REPLICAS}, consumer=${CONSUMER_REPLICAS}"
echo "  UI: http://localhost:3000"
echo "  AC: 直连（Agent 通过 Manager SD 服务发现，无 LB 代理）"
echo ""

cd "$DEPLOY_DIR"

if [ "$DETACH_MODE" = true ]; then
    docker compose \
        -f docker-compose.pret.yml \
        up -d --build --remove-orphans \
        --scale manager="${MANAGER_REPLICAS}" \
        --scale agentcenter="${AGENTCENTER_REPLICAS}" \
        --scale consumer="${CONSUMER_REPLICAS}"
else
    docker compose \
        -f docker-compose.pret.yml \
        up --build --remove-orphans \
        --scale manager="${MANAGER_REPLICAS}" \
        --scale agentcenter="${AGENTCENTER_REPLICAS}" \
        --scale consumer="${CONSUMER_REPLICAS}"
fi
