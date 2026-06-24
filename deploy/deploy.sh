#!/bin/bash
#
# Matrix Cloud Security Platform - 生产环境部署脚本
#
# 使用方法:
#   ./deploy.sh              # 交互式部署
#   ./deploy.sh start        # 启动服务
#   ./deploy.sh stop         # 停止服务
#   ./deploy.sh restart      # 重启服务
#   ./deploy.sh status       # 查看状态
#   ./deploy.sh logs         # 查看日志
#   ./deploy.sh backup       # 备份数据
#   ./deploy.sh upgrade      # 升级服务（保留数据和配置）
#   ./deploy.sh clean-logs   # 清理旧日志
#   ./deploy.sh help         # 显示帮助
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd 2>/dev/null || echo "$SCRIPT_DIR")"
ENV_FILE="$SCRIPT_DIR/.env"

# 颜色
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "${BLUE}[STEP]${NC} $1"; }

# ============================================================
# 环境检测
# ============================================================
check_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if [ -f /etc/os-release ]; then
            . /etc/os-release
            OS_NAME=$ID
            OS_VERSION=$VERSION_ID
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        OS_NAME="macos"
        OS_VERSION=$(sw_vers -productVersion)
    else
        log_error "不支持的操作系统: $OSTYPE"
        exit 1
    fi
    log_info "操作系统: $OS_NAME $OS_VERSION"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker 未安装"
        log_info "安装方法: https://docs.docker.com/engine/install/"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker 服务未运行或无权限"
        log_info "请运行: sudo systemctl start docker"
        exit 1
    fi

    DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
    log_info "Docker 版本: $DOCKER_VERSION"
}

check_docker_compose() {
    if docker compose version &> /dev/null; then
        COMPOSE_CMD="docker compose"
        COMPOSE_VERSION=$(docker compose version --short 2>/dev/null || echo "unknown")
    elif command -v docker-compose &> /dev/null; then
        COMPOSE_CMD="docker-compose"
        COMPOSE_VERSION=$(docker-compose version --short 2>/dev/null || echo "unknown")
    else
        log_error "Docker Compose 未安装"
        exit 1
    fi
    log_info "Docker Compose 版本: $COMPOSE_VERSION"
}

check_ports() {
    local ports=("${GRPC_PORT:-6751}" "${HTTP_PORT:-80}")
    for port in "${ports[@]}"; do
        if netstat -tuln 2>/dev/null | grep -q ":$port " || ss -tuln 2>/dev/null | grep -q ":$port "; then
            log_warn "端口 $port 已被占用"
        fi
    done
}

# ============================================================
# 初始化配置
# ============================================================
init_env() {
    if [ -f "$ENV_FILE" ]; then
        log_info "配置文件已存在: $ENV_FILE"
        read -p "是否重新配置? (y/N): " confirm
        if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
            return
        fi
    fi

    log_step "配置环境变量..."

    # 数据库密码
    read -sp "MySQL Root 密码 (回车自动生成): " MYSQL_ROOT_PASSWORD
    echo
    if [ -z "$MYSQL_ROOT_PASSWORD" ]; then
        MYSQL_ROOT_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
        log_info "已自动生成 Root 密码"
    fi

    read -sp "MySQL 应用密码 (回车自动生成): " MYSQL_PASSWORD
    echo
    if [ -z "$MYSQL_PASSWORD" ]; then
        MYSQL_PASSWORD=$(openssl rand -base64 24 | tr -dc 'a-zA-Z0-9' | head -c 24)
        log_info "已自动生成应用密码"
    fi

    # 数据目录
    read -p "数据存储目录 [/data/mxcwpp]: " DATA_DIR
    DATA_DIR="${DATA_DIR:-/data/mxcwpp}"

    # 服务器IP
    DEFAULT_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "127.0.0.1")
    read -p "服务器 IP [$DEFAULT_IP]: " SERVER_IP
    SERVER_IP="${SERVER_IP:-$DEFAULT_IP}"

    # 端口
    read -p "gRPC 端口 [6751]: " GRPC_PORT
    GRPC_PORT="${GRPC_PORT:-6751}"

    read -p "HTTP 端口 [80]: " HTTP_PORT
    HTTP_PORT="${HTTP_PORT:-80}"

    read -p "Manager API 端口 [8080]: " MANAGER_PORT
    MANAGER_PORT="${MANAGER_PORT:-8080}"

    # Redis 密码
    read -sp "Redis 密码 (回车留空，无密码): " REDIS_PASSWORD
    echo
    REDIS_PASSWORD="${REDIS_PASSWORD:-}"

    # JWT 密钥
    JWT_SECRET=$(openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32)
    log_info "已自动生成 JWT 密钥"

    # 日志保留天数
    read -p "日志保留天数 [7]: " LOG_RETENTION_DAYS
    LOG_RETENTION_DAYS="${LOG_RETENTION_DAYS:-7}"

    # 版本
    read -p "部署版本 [v1.0.0]: " VERSION
    VERSION="${VERSION:-v1.0.0}"

    # 写入配置
    cat > "$ENV_FILE" << EOF
# Matrix Cloud Security Platform 配置
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')
# 修改后运行 ./deploy.sh restart 生效

# ============ General ============
VERSION=$VERSION
TZ=Asia/Shanghai

# ============ 数据库 ============
MYSQL_ROOT_PASSWORD=$MYSQL_ROOT_PASSWORD
MYSQL_PASSWORD=$MYSQL_PASSWORD
MYSQL_DATABASE=mxcwpp
MYSQL_USER=mxcwpp_user
MYSQL_HOST=mysql
MYSQL_PORT=3306

# ============ 数据库连接池 ============
DB_MAX_IDLE_CONNS=20
DB_MAX_OPEN_CONNS=200
DB_CONN_MAX_LIFETIME=1h

# ============ Redis ============
REDIS_ADDR=redis:6379
REDIS_PASSWORD=$REDIS_PASSWORD
REDIS_DB=0
REDIS_POOL_SIZE=100
REDIS_SENTINEL=false
REDIS_MASTER_NAME=mymaster
REDIS_SENTINEL_ADDR_1=redis-sentinel-1:26379
REDIS_SENTINEL_ADDR_2=redis-sentinel-2:26379
REDIS_SENTINEL_ADDR_3=redis-sentinel-3:26379

# ============ Kafka ============
KAFKA_ENABLED=true
KAFKA_BROKER_1=kafka-1:9092
KAFKA_BROKER_2=kafka-2:9092
KAFKA_BROKER_3=kafka-3:9092
KAFKA_TOPIC_PREFIX=

# ============ ClickHouse ============
CLICKHOUSE_ENABLED=true
CLICKHOUSE_ADDR=clickhouse:9000
CLICKHOUSE_DATABASE=mxcwpp
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=

# ============ Prometheus ============
PROMETHEUS_ENABLED=true
PROMETHEUS_QUERY_URL=http://prometheus:9090
PROMETHEUS_TIMEOUT=10s

# ============ 数据目录 ============
DATA_DIR=$DATA_DIR

# ============ 网络 ============
SERVER_IP=$SERVER_IP
GRPC_PORT=$GRPC_PORT
SERVER_HTTP_PORT=8080
HTTP_PORT=$HTTP_PORT
HTTPS_PORT=443
MANAGER_PORT=$MANAGER_PORT
MANAGER_ADDR=http://manager:8080
INSTANCE_ID=

# ============ 控制面副本数 ============
# deploy.sh 的 start/upgrade 会按此值显式生成 --scale 参数
# 默认 1 = 单机/功能验证；生产建议 2+ 实现 HA
MANAGER_REPLICAS=1
AGENTCENTER_REPLICAS=1
CONSUMER_REPLICAS=1

# ============ 日志 ============
LOG_LEVEL=info
LOG_FORMAT=json
LOG_MAX_AGE=7
LOG_RETENTION_DAYS=$LOG_RETENTION_DAYS

# ============ Agent ============
HEARTBEAT_INTERVAL=60

# ============ Plugins ============
PLUGINS_DIR=/opt/mxcwpp/plugins
PLUGINS_BASE_URL=

# ============ JWT ============
JWT_SECRET=$JWT_SECRET
EOF

    chmod 600 "$ENV_FILE"
    log_info "配置已保存: $ENV_FILE"
}

# ============================================================
# 初始化目录和证书
# ============================================================
init_dirs() {
    source "$ENV_FILE"

    log_step "创建数据目录..."
    sudo mkdir -p "$DATA_DIR"/{mysql,redis,logs/{agentcenter,manager,nginx,mysql},plugins,uploads}
    # 可选服务目录（即使不启用也创建，避免挂载失败）
    sudo mkdir -p "$DATA_DIR"/{kafka-1,kafka-2,kafka-3,clickhouse}
    sudo chown -R $(id -u):$(id -g) "$DATA_DIR" 2>/dev/null || true
    # MySQL 日志目录需要 mysql 用户可写（容器内 uid=999）
    sudo chmod 777 "$DATA_DIR/logs/mysql" 2>/dev/null || true
    log_info "数据目录: $DATA_DIR"
}

init_certs() {
    if [ -f "$SCRIPT_DIR/certs/ca.crt" ]; then
        log_info "证书已存在"
        return
    fi

    log_step "生成 mTLS 证书..."
    mkdir -p "$SCRIPT_DIR/certs/ssl"

    cd "$PROJECT_ROOT"
    if [ -f "./scripts/generate-certs.sh" ]; then
        ./scripts/generate-certs.sh
        cp -r certs/* "$SCRIPT_DIR/certs/"
    else
        # 手动生成证书
        cd "$SCRIPT_DIR/certs"

        # CA
        openssl genrsa -out ca.key 4096
        openssl req -new -x509 -days 3650 -key ca.key -out ca.crt -subj "/CN=MxCwpp CA"

        # Server
        openssl genrsa -out server.key 2048
        openssl req -new -key server.key -out server.csr -subj "/CN=mxcwpp-server"
        openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt
        rm -f server.csr

        # Agent
        openssl genrsa -out agent.key 2048
        openssl req -new -key agent.key -out agent.csr -subj "/CN=mxcwpp-agent"
        openssl x509 -req -days 365 -in agent.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out agent.crt
        rm -f agent.csr
    fi

    log_info "证书生成完成"
}

init_config() {
    source "$ENV_FILE"

    log_step "生成配置文件..."

    # 从模板生成配置（server.yaml.tpl 由 git 跟踪，server.yaml 已 gitignore）
    if [ ! -f "$SCRIPT_DIR/config/server.yaml.tpl" ]; then
        log_error "配置模板不存在: $SCRIPT_DIR/config/server.yaml.tpl"
        exit 1
    fi
    cp "$SCRIPT_DIR/config/server.yaml.tpl" "$SCRIPT_DIR/config/server.yaml"

    local kafka1 kafka2 kafka3
    kafka1="${KAFKA_BROKER_1:-}"
    kafka2="${KAFKA_BROKER_2:-}"
    kafka3="${KAFKA_BROKER_3:-}"
    if [ -z "$kafka1" ] && [ -n "${KAFKA_BROKERS:-}" ]; then
        IFS=',' read -r kafka1 kafka2 kafka3 <<< "${KAFKA_BROKERS}"
    fi
    kafka1="${kafka1:-kafka-1:9092}"
    kafka2="${kafka2:-$kafka1}"
    kafka3="${kafka3:-$kafka2}"
    local PLUGINS_URL="${PLUGINS_BASE_URL:-http://$SERVER_IP:${HTTP_PORT:-80}/api/v1/plugins/download}"

    sed -i.bak \
        -e "s|__GRPC_PORT__|${GRPC_PORT:-6751}|g" \
        -e "s|__SERVER_HTTP_PORT__|${SERVER_HTTP_PORT:-8080}|g" \
        -e "s|__MYSQL_HOST__|${MYSQL_HOST:-mysql}|g" \
        -e "s|__MYSQL_PORT__|${MYSQL_PORT:-3306}|g" \
        -e "s|__MYSQL_USER__|${MYSQL_USER:-mxcwpp_user}|g" \
        -e "s|__MYSQL_PASSWORD__|${MYSQL_PASSWORD}|g" \
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
        -e "s|__KAFKA_BROKER_1__|${kafka1}|g" \
        -e "s|__KAFKA_BROKER_2__|${kafka2}|g" \
        -e "s|__KAFKA_BROKER_3__|${kafka3}|g" \
        -e "s|__KAFKA_TOPIC_PREFIX__|${KAFKA_TOPIC_PREFIX:-}|g" \
        -e "s|__CLICKHOUSE_ENABLED__|${CLICKHOUSE_ENABLED:-true}|g" \
        -e "s|__CLICKHOUSE_ADDR__|${CLICKHOUSE_ADDR:-clickhouse:9000}|g" \
        -e "s|__CLICKHOUSE_DATABASE__|${CLICKHOUSE_DATABASE:-mxcwpp}|g" \
        -e "s|__CLICKHOUSE_USER__|${CLICKHOUSE_USER:-default}|g" \
        -e "s|__CLICKHOUSE_PASSWORD__|${CLICKHOUSE_PASSWORD:-}|g" \
        -e "s|__PROMETHEUS_ENABLED__|${PROMETHEUS_ENABLED:-true}|g" \
        -e "s|__PROMETHEUS_QUERY_URL__|${PROMETHEUS_QUERY_URL:-http://prometheus:9090}|g" \
        -e "s|__PROMETHEUS_TIMEOUT__|${PROMETHEUS_TIMEOUT:-10s}|g" \
        -e "s|__LOG_LEVEL__|${LOG_LEVEL:-info}|g" \
        -e "s|__LOG_FORMAT__|${LOG_FORMAT:-json}|g" \
        -e "s|__LOG_MAX_AGE__|${LOG_MAX_AGE:-7}|g" \
        -e "s|__HEARTBEAT_INTERVAL__|${HEARTBEAT_INTERVAL:-60}|g" \
        -e "s|__PLUGINS_DIR__|${PLUGINS_DIR:-/opt/mxcwpp/plugins}|g" \
        -e "s|__PLUGINS_BASE_URL__|${PLUGINS_URL}|g" \
        -e "s|__JWT_SECRET__|${JWT_SECRET:-change-me-in-production}|g" \
        -e "s|__MANAGER_ADDR__|${MANAGER_ADDR:-http://manager:8080}|g" \
        -e "s|__INSTANCE_ID__|${INSTANCE_ID:-}|g" \
        "$SCRIPT_DIR/config/server.yaml"

    rm -f "$SCRIPT_DIR/config/server.yaml.bak"

    log_info "配置生成完成（所有参数来自 .env）"
}

# ============================================================
# Docker Compose 操作
# ============================================================
dc() {
    cd "$SCRIPT_DIR"
    # 显式指定 -f docker-compose.yml，避免自动合并 docker-compose.override.yml（dev 热重载层）
    $COMPOSE_CMD -f docker-compose.yml --env-file "$ENV_FILE" "$@"
}

build() {
    # 检测是否有源码上下文（deploy/ 在项目根目录下时才能 build）
    if [ -f "$PROJECT_ROOT/go.mod" ]; then
        log_step "构建镜像（源码模式）..."
        dc build
    else
        log_warn "未检测到源码，跳过构建"
        log_info "部署包模式请先在开发机构建镜像:"
        log_info "  ./scripts/build-images.sh --version \${VERSION}"
        log_info "或推送到私有仓库后使用 docker pull"
    fi
}

# 根据 .env 中的 *_REPLICAS 变量生成 --scale 参数数组
# 使用方式：
#   read -a SCALE_ARGS < <(scale_args); dc up -d "${SCALE_ARGS[@]}"
# 默认值：每个控制面服务 1 副本（单机/功能验证）；生产建议 2+
scale_args() {
    source "$ENV_FILE"
    local m="${MANAGER_REPLICAS:-1}"
    local a="${AGENTCENTER_REPLICAS:-1}"
    local c="${CONSUMER_REPLICAS:-1}"
    echo "--scale manager=${m} --scale agentcenter=${a} --scale consumer=${c}"
}

start() {
    if [ ! -f "$ENV_FILE" ]; then
        log_error "请先运行 ./deploy.sh 初始化环境"
        exit 1
    fi

    source "$ENV_FILE"
    local m="${MANAGER_REPLICAS:-1}"
    local a="${AGENTCENTER_REPLICAS:-1}"
    local c="${CONSUMER_REPLICAS:-1}"

    log_step "启动服务..."
    log_info "控制面副本数: manager=${m} agentcenter=${a} consumer=${c} （源自 .env 的 *_REPLICAS 变量）"
    if [ "$m" -lt 2 ] || [ "$a" -lt 2 ] || [ "$c" -lt 2 ]; then
        log_warn "当前为单副本（非 HA），仅供单机或功能验证。生产建议在 .env 中将 MANAGER_REPLICAS/AGENTCENTER_REPLICAS/CONSUMER_REPLICAS 调整为 2+。"
    fi
    # shellcheck disable=SC2046
    dc up -d $(scale_args)

    log_info "等待服务就绪..."
    sleep 10

    status

    echo ""
    log_info "部署完成!"
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    log_info "Web 控制台: http://$SERVER_IP:$HTTP_PORT"
    log_info "AgentCenter gRPC: 默认 compose 不直接暴露 ${GRPC_PORT}，需额外做端口映射或接入四层负载均衡"
    log_info "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

stop() {
    log_step "停止服务..."
    dc down
    log_info "服务已停止"
}

restart() {
    log_step "重启服务..."
    # 重新生成配置（从 .env 更新 server.yaml）
    if [ -f "$SCRIPT_DIR/config/server.yaml.tpl" ] && [ -f "$ENV_FILE" ]; then
        init_config
    fi
    log_warn "restart 仅重启容器并重载 server.yaml 内部配置，不会重建容器。"
    log_warn "如修改了镜像版本 / 端口映射 / scale / volume / 网络等 Compose 级变更，请改用: docker compose --env-file .env up -d （必要时加 --scale / --force-recreate）"
    dc restart "$@"
}

status() {
    dc ps
}

logs() {
    dc logs -f "$@"
}

backup() {
    source "$ENV_FILE"
    local BACKUP_DIR="$SCRIPT_DIR/backup"
    mkdir -p "$BACKUP_DIR"
    BACKUP_FILE="$BACKUP_DIR/mxcwpp_$(date +%Y%m%d_%H%M%S).sql.gz"

    log_step "备份数据库..."
    dc exec -T mysql mysqldump -u root -p"$MYSQL_ROOT_PASSWORD" --single-transaction mxcwpp | gzip > "$BACKUP_FILE"

    log_info "备份完成: $BACKUP_FILE ($(du -h "$BACKUP_FILE" | cut -f1))"

    # 清理 30 天前的备份
    find "$BACKUP_DIR" -name "mxcwpp_*.sql.gz" -mtime +30 -delete 2>/dev/null || true
}

# ============================================================
# 升级
# ============================================================
upgrade() {
    if [ ! -f "$ENV_FILE" ]; then
        log_error "未检测到已有部署，请使用 ./deploy.sh 进行首次部署"
        exit 1
    fi

    source "$ENV_FILE"

    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Matrix Cloud Security Platform 升级"
    echo "  当前版本: ${VERSION:-unknown}"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    read -p "新版本号: " NEW_VERSION
    if [ -z "$NEW_VERSION" ]; then
        log_error "请输入版本号"
        exit 1
    fi

    # 1. 备份
    log_step "[1/4] 备份数据库..."
    backup

    # 2. 更新版本号
    log_step "[2/4] 更新版本号: $VERSION → $NEW_VERSION..."
    sed -i.bak "s/^VERSION=.*/VERSION=$NEW_VERSION/" "$ENV_FILE"
    rm -f "$ENV_FILE.bak"

    # 3. 重新生成配置（从模板）
    log_step "[3/4] 更新配置..."
    if [ -f "$SCRIPT_DIR/config/server.yaml.tpl" ]; then
        init_config
    fi

    # 4. 重新构建并启动
    log_step "[4/4] 构建镜像并重启..."
    source "$ENV_FILE"
    local m="${MANAGER_REPLICAS:-1}"
    local a="${AGENTCENTER_REPLICAS:-1}"
    local c="${CONSUMER_REPLICAS:-1}"
    log_info "保持控制面副本数: manager=${m} agentcenter=${a} consumer=${c} （源自 .env，升级前后一致）"
    if [ "$m" -lt 2 ] || [ "$a" -lt 2 ] || [ "$c" -lt 2 ]; then
        log_warn "当前为单副本（非 HA）。如需在升级中一并切到 HA，请先在 .env 将 MANAGER_REPLICAS/AGENTCENTER_REPLICAS/CONSUMER_REPLICAS 调整为 2+ 再运行 upgrade。"
    fi
    if [ -f "$PROJECT_ROOT/go.mod" ]; then
        # shellcheck disable=SC2046
        dc up -d --build $(scale_args)
    else
        dc pull 2>/dev/null || log_warn "拉取镜像失败，尝试使用本地镜像"
        # shellcheck disable=SC2046
        dc up -d $(scale_args)
    fi

    sleep 10
    status

    log_info "升级完成! 版本: $NEW_VERSION"
}

# ============================================================
# 日志清理
# ============================================================
clean_logs() {
    source "$ENV_FILE"

    local RETENTION_DAYS="${LOG_RETENTION_DAYS:-7}"

    log_step "清理 ${RETENTION_DAYS} 天前的日志..."

    local TOTAL_BEFORE=$(du -sh "$DATA_DIR/logs" 2>/dev/null | cut -f1)

    # AgentCenter 日志
    find "$DATA_DIR/logs/agentcenter/" -name "*.log.*" -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true
    # Manager 日志
    find "$DATA_DIR/logs/manager/" -name "*.log.*" -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true
    # Nginx 日志
    find "$DATA_DIR/logs/nginx/" -name "*.log.*" -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true
    # MySQL 慢查询日志
    find "$DATA_DIR/logs/mysql/" -name "*.log.*" -mtime +${RETENTION_DAYS} -delete 2>/dev/null || true

    local TOTAL_AFTER=$(du -sh "$DATA_DIR/logs" 2>/dev/null | cut -f1)

    log_info "清理完成: $TOTAL_BEFORE → $TOTAL_AFTER"
}

# ============================================================
# 主流程
# ============================================================
full_deploy() {
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Matrix Cloud Security Platform 生产环境部署"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""

    log_step "[1/7] 检测运行环境..."
    check_os
    check_docker
    check_docker_compose

    log_step "[2/7] 检测端口..."
    check_ports

    log_step "[3/7] 配置环境变量..."
    init_env

    log_step "[4/7] 初始化目录..."
    init_dirs

    log_step "[5/7] 生成证书..."
    init_certs

    log_step "[6/7] 更新配置..."
    init_config

    log_step "[7/7] 启动服务..."
    # 源码环境：先构建镜像；部署包环境：直接用预构建镜像
    build
    start
}

show_help() {
    echo "Matrix Cloud Security Platform 部署脚本"
    echo ""
    echo "用法: $0 [命令]"
    echo ""
    echo "命令:"
    echo "  (无参数)    交互式首次部署"
    echo "  start       启动服务"
    echo "  stop        停止服务"
    echo "  restart     重启服务 (可指定服务名: restart agentcenter)"
    echo "  status      查看服务状态"
    echo "  logs        查看日志 (可指定服务名: logs agentcenter)"
    echo "  backup      备份数据库 (gzip 压缩，自动清理 30 天前备份)"
    echo "  upgrade     升级服务 (自动备份 → 更新版本 → 重启)"
    echo "  clean-logs  清理旧日志 (默认保留 ${LOG_RETENTION_DAYS:-7} 天)"
    echo "  build       构建镜像"
    echo "  help        显示帮助"
}

main() {
    check_docker
    check_docker_compose

    case "${1:-}" in
        "")
            full_deploy
            ;;
        start)
            start
            ;;
        stop)
            stop
            ;;
        restart)
            shift
            restart "$@"
            ;;
        status)
            status
            ;;
        logs)
            shift
            logs "$@"
            ;;
        backup)
            backup
            ;;
        upgrade)
            upgrade
            ;;
        clean-logs)
            clean_logs
            ;;
        build)
            build
            ;;
        help|--help|-h)
            show_help
            ;;
        *)
            log_error "未知命令: $1"
            show_help
            exit 1
            ;;
    esac
}

main "$@"
