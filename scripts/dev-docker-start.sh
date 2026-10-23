#!/bin/bash

# Docker 开发环境启动脚本
# 使用 docker-compose.dev.yml（自包含，Air 热重载）

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEPLOY_DIR="$PROJECT_ROOT/deploy"
DETACH_MODE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--detach)
            DETACH_MODE=true
            shift
            ;;
        *)
            echo -e "${RED}错误: 不支持的参数 $1${NC}"
            echo "用法: $0 [--detach]"
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

env_or_legacy() {
    local primary="$1"
    local fallback="$2"
    if [ -n "${!primary:-}" ]; then
        printf '%s' "${!primary}"
        return
    fi
    if [ -n "$fallback" ] && [ -n "${!fallback:-}" ]; then
        printf '%s' "${!fallback}"
    fi
}

render_server_config() {
    local output="$1"
    local kafka1 kafka2 kafka3 legacy1 legacy2 legacy3
    local ha_enabled=false

    case ",${COMPOSE_PROFILES:-}," in
        *,ha,*|*,pret-ha,*|*,kafka-ha,*)
            ha_enabled=true
            ;;
    esac

    kafka1="$(trim "${KAFKA_BROKER_1:-}")"
    kafka2="$(trim "${KAFKA_BROKER_2:-}")"
    kafka3="$(trim "${KAFKA_BROKER_3:-}")"

    if [ -z "$kafka1" ] && [ -n "${KAFKA_BROKERS:-}" ]; then
        IFS=',' read -r legacy1 legacy2 legacy3 <<< "${KAFKA_BROKERS}"
        kafka1="$(trim "${legacy1:-}")"
        kafka2="$(trim "${legacy2:-}")"
        kafka3="$(trim "${legacy3:-}")"
    fi

    if [ -z "$kafka1" ]; then
        kafka1="kafka:9092"
    fi
    if [ "$ha_enabled" = false ] || [ -z "$kafka2" ]; then
        kafka2="$kafka1"
    fi
    if [ "$ha_enabled" = false ] || [ -z "$kafka3" ]; then
        kafka3="$kafka2"
    fi

    sed -i.bak \
        -e "s|__GRPC_PORT__|${GRPC_PORT:-6751}|g" \
        -e "s|__SERVER_HTTP_PORT__|${SERVER_HTTP_PORT:-8080}|g" \
        -e "s|__MYSQL_HOST__|${MYSQL_HOST:-mysql}|g" \
        -e "s|__MYSQL_PORT__|${MYSQL_PORT:-3306}|g" \
        -e "s|__MYSQL_USER__|${MYSQL_USER:-mxcwpp_user}|g" \
        -e "s|__MYSQL_PASSWORD__|${MYSQL_PASSWORD:?未设置 MYSQL_PASSWORD，先在 .env 里配置}|g" \
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
        -e "s|__PROMETHEUS_ENABLED__|${PROMETHEUS_ENABLED:-true}|g" \
        -e "s|__PROMETHEUS_QUERY_URL__|${PROMETHEUS_QUERY_URL:-http://prometheus:9090}|g" \
        -e "s|__PROMETHEUS_TIMEOUT__|${PROMETHEUS_TIMEOUT:-10s}|g" \
        -e "s|__LOG_LEVEL__|${LOG_LEVEL:-debug}|g" \
        -e "s|__LOG_FORMAT__|${LOG_FORMAT:-console}|g" \
        -e "s|__LOG_MAX_AGE__|${LOG_MAX_AGE:-7}|g" \
        -e "s|__HEARTBEAT_INTERVAL__|${HEARTBEAT_INTERVAL:-60}|g" \
        -e "s|__PLUGINS_DIR__|${PLUGINS_DIR:-/opt/mxcwpp/plugins}|g" \
        -e "s|__PLUGINS_BASE_URL__|${PLUGINS_BASE_URL:-}|g" \
        -e "s|__JWT_SECRET__|${JWT_SECRET:-dev-secret-change-in-production}|g" \
        -e "s|__INTERNAL_SECRET__|${INTERNAL_SECRET}|g" \
        -e "s|__ENROLL_TOKEN__|${ENROLL_TOKEN}|g" \
        -e "s|__CORS_ORIGINS__|${CORS_ORIGINS:-[]}|g" \
        -e "s|__METRICS_BASIC_AUTH_USER__|${METRICS_BASIC_AUTH_USER:-}|g" \
        -e "s|__METRICS_BASIC_AUTH_PASSWORD__|${METRICS_BASIC_AUTH_PASSWORD:-}|g" \
        -e "s|__MANAGER_ADDR__|${MANAGER_ADDR:-http://manager:8080}|g" \
        -e "s|__INSTANCE_ID__|${INSTANCE_ID:-}|g" \
        "$output"
    rm -f "$output.bak"
}

# ensure_secret 保证 .env 里有这把密钥：没有或太短就生成一把并写回，之后每次启动沿用。
# 不给固定默认值：开发环境端口可能对局域网开放，写死的密钥等于公开。
# 模板里这两项不替换的话，占位符本身会被当成密钥用。
ensure_secret() {
    local key="$1"
    local value="${!key:-}"
    if [ "${#value}" -lt 32 ]; then
        value="$(openssl rand -hex 32)"
        printf '%s=%s\n' "$key" "$value" >> "$DEPLOY_DIR/.env"
        chmod 600 "$DEPLOY_DIR/.env"
        echo "  ✓ 已生成 $key 并写入 .env"
    fi
    printf -v "$key" '%s' "$value"
}

warn_legacy_kafka_state() {
    local legacy_kafka_dir="$DEPLOY_DIR/data/kafka"
    local legacy_zk_dir="$DEPLOY_DIR/data/zookeeper"

    if [ -d "$legacy_kafka_dir" ] || [ -d "$legacy_zk_dir" ]; then
        echo -e "${YELLOW}  检测到旧版 Kafka/Zookeeper 数据目录（dev 已切换为 KRaft）:${NC}"
        [ -d "$legacy_kafka_dir" ] && echo "    - $legacy_kafka_dir"
        [ -d "$legacy_zk_dir" ] && echo "    - $legacy_zk_dir"
        echo "    如需回收磁盘，可在确认停服后手动删除这些旧目录。"
    fi
}

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Matrix Cloud Security Platform${NC}"
echo -e "${GREEN}  Docker 开发环境启动脚本${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# [1/4] 检查 Docker
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

# [2/4] 准备 .env
echo ""
echo -e "${YELLOW}[2/4] 准备环境配置...${NC}"
if [ ! -f "$DEPLOY_DIR/.env" ]; then
    cp "$DEPLOY_DIR/.env.example" "$DEPLOY_DIR/.env"
    echo "  ✓ 已从 .env.example 创建 .env（可按需修改）"
else
    echo "  ✓ .env 已存在"
fi

# [3/4] 从模板生成 server.yaml
echo ""
echo -e "${YELLOW}[3/4] 生成 server.yaml...${NC}"
source "$DEPLOY_DIR/.env"
ensure_secret INTERNAL_SECRET
ensure_secret ENROLL_TOKEN
cp "$DEPLOY_DIR/config/server.yaml.tpl" "$DEPLOY_DIR/config/server.yaml"
render_server_config "$DEPLOY_DIR/config/server.yaml"
echo "  ✓ server.yaml 已生成"

# [4/4] 检查证书
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

# 启动服务
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  启动 Docker 服务 (dev 模式)...${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
if [ "$DETACH_MODE" = false ]; then
    echo -e "  按 ${YELLOW}Ctrl+C${NC} 停止服务"
fi
echo ""

cd "$DEPLOY_DIR"

# 清理函数
cleanup() {
    echo ""
    echo -e "${YELLOW}正在停止服务...${NC}"
    cd "$DEPLOY_DIR"
    docker compose -f docker-compose.dev.yml down
    echo -e "${GREEN}服务已停止${NC}"
    exit 0
}
if [ "$DETACH_MODE" = false ]; then
    trap cleanup SIGINT SIGTERM
fi

compose_args=(-f docker-compose.dev.yml up --build --remove-orphans)
if [ "$DETACH_MODE" = true ]; then
    compose_args=(-f docker-compose.dev.yml up -d --build --remove-orphans)
fi

# DEV_SERVICES 只起指定的服务（空格分隔），不设则全起。
# 接真机 agent 联调时用它跳过编排里自带的 agent 容器：DEV_SERVICES="manager agentcenter consumer engine"
if [ -n "${DEV_SERVICES:-}" ]; then
    read -r -a dev_services <<< "$DEV_SERVICES"
    compose_args+=("${dev_services[@]}")
fi

docker compose "${compose_args[@]}"
