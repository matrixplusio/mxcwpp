# Matrix Cloud Security Platform - 生产环境部署

当前部署包面向 V2 控制面，核心拓扑为 `UI + Manager + AgentCenter + Consumer + MySQL + Redis + Kafka + ClickHouse`。应用层支持多副本部署，建议在生产环境显式使用 `--scale` 启动 `manager / agentcenter / consumer`；MySQL、Redis、ClickHouse 的主从与容灾需按实际生产标准额外建设。默认 compose 通过 `ui` 暴露 Web/API 入口，`agentcenter` 的 gRPC 入口需要按生产环境额外做端口映射或接入四层负载均衡。

## 部署流程

### 1. 开发机：构建镜像

```bash
# 构建镜像到本地
./scripts/build-images.sh --version v1.0.0

# 或构建并推送到私有仓库
./scripts/build-images.sh --version v1.0.0 --registry harbor.example.com/mxsec --push
```

### 2. 开发机：打包部署包

```bash
# 生成部署包
./scripts/package-deploy.sh --version v1.0.0

# 如果使用私有仓库
./scripts/package-deploy.sh --version v1.0.0 --registry harbor.example.com/mxsec

# 输出: dist/deploy/mxsec-platform-v1.0.0.tar.gz
```

### 3. 生产服务器：部署

```bash
# 上传并解压
scp dist/deploy/mxsec-platform-v1.0.0.tar.gz root@server:/opt/
ssh root@server

cd /opt
tar -xzf mxsec-platform-v1.0.0.tar.gz
cd mxsec-platform-v1.0.0

# 交互式初始化（首次部署，生成 .env / 证书 / 配置）
./deploy.sh

# 生产高可用启动（推荐）：显式指定控制面副本数
docker compose --env-file .env up -d \
  --scale manager=2 \
  --scale agentcenter=2 \
  --scale consumer=2

# 单机/功能验证：./deploy.sh start（单副本，不直接暴露 AgentCenter gRPC）
```

---

## 部署包内容

```
mxsec-platform-v1.0.0/
├── deploy.sh           # 部署脚本
├── docker-compose.yml  # 服务编排
├── init.sql            # 数据库初始化
├── init-clickhouse.sql # ClickHouse 初始化
├── config/
│   ├── server.yaml     # Server 配置（模板）
│   ├── nginx.conf      # Nginx 配置
│   ├── mysql.cnf       # MySQL 配置
│   └── clickhouse.xml  # ClickHouse 配置
└── certs/              # 证书目录（部署时生成）
```

---

## 管理命令

```bash
./deploy.sh start       # 启动服务
./deploy.sh stop        # 停止服务
./deploy.sh restart     # 重启全部（或指定服务: restart agentcenter）
./deploy.sh status      # 查看服务状态
./deploy.sh logs        # 查看日志（或指定服务: logs agentcenter）
./deploy.sh backup      # 备份数据库（gzip 压缩，自动清理 30 天前备份）
./deploy.sh upgrade     # 升级服务（自动备份 → 更新版本 → 重启）
./deploy.sh clean-logs  # 清理旧日志（默认保留 7 天）
```

---

## 端口

| 端口 | 服务 |
|------|------|
| 80 / 443 | Web 控制台 + API 代理入口 |
| 6751 | AgentCenter gRPC（默认 compose 不直接暴露，需额外配置） |
| 13306 | MySQL |
| 16379 | Redis |
| 9092 / 9094 / 9095 | Kafka Broker |
| 8123 / 9000 | ClickHouse |

---

## 配置文件说明

### .env

所有配置集中在 `.env` 文件中，首次部署时交互式生成，后续可直接编辑：

```bash
# ============ 数据库 ============
MYSQL_ROOT_PASSWORD=xxx        # MySQL root 密码
MYSQL_PASSWORD=xxx             # 应用密码
MYSQL_DATABASE=mxsec           # 数据库名
MYSQL_USER=mxsec_user          # 应用用户名
MYSQL_HOST=mysql               # 数据库地址（Docker 内部用 mysql）
MYSQL_PORT=3306                # 数据库端口

# ============ 数据库连接池 ============
DB_MAX_IDLE_CONNS=20           # 最大空闲连接数
DB_MAX_OPEN_CONNS=200          # 最大打开连接数
DB_CONN_MAX_LIFETIME=1h        # 连接最大生命周期

# ============ Redis ============
REDIS_ADDR=redis:6379          # Redis 地址
REDIS_PASSWORD=                # Redis 密码

# ============ Kafka ============
KAFKA_ENABLED=true
KAFKA_BROKER_1=kafka-1:9092
KAFKA_BROKER_2=kafka-2:9092
KAFKA_BROKER_3=kafka-3:9092

# ============ ClickHouse ============
CLICKHOUSE_ENABLED=true
CLICKHOUSE_ADDR=clickhouse:9000

# ============ Prometheus ============
PROMETHEUS_ENABLED=true
PROMETHEUS_QUERY_URL=http://prometheus:9090

# ============ 数据目录 ============
DATA_DIR=/data/mxsec           # 持久化数据根目录

# ============ 网络 ============
SERVER_IP=10.0.0.1             # 服务器 IP（用于生成插件下载 URL）
GRPC_PORT=6751                 # AgentCenter 容器内 gRPC 端口
HTTP_PORT=80                   # Web 控制台端口
HTTPS_PORT=443                 # HTTPS 端口
MANAGER_PORT=8080              # Manager / AgentCenter HTTP 管理口（容器内）

# ============ 日志 ============
LOG_LEVEL=info                 # 日志级别: debug, info, warn, error
LOG_FORMAT=json                # 日志格式: json, console
LOG_MAX_AGE=7                  # 日志文件保留天数
LOG_RETENTION_DAYS=7           # 清理日志时的保留天数

# ============ Agent ============
HEARTBEAT_INTERVAL=60          # Agent 心跳间隔（秒）

# ============ 版本 ============
VERSION=v1.0.0
TZ=Asia/Shanghai
```

修改 `.env` 后的生效方式分两种情况：

- **仅 `server.yaml` 内部配置类改动**（日志级别、业务开关、Kafka/ClickHouse 地址等，会被模板重新渲染进 `server.yaml`）：运行 `./deploy.sh restart` 即可，脚本会先重新渲染 `server.yaml`，再执行 `docker compose restart`。
- **Compose 级变更**（镜像版本 `VERSION`、端口映射、volume、网络、副本数等）：`restart` 不会重建容器，必须执行 `docker compose --env-file .env up -d`（必要时加 `--scale` / `--force-recreate`）才能生效。

**注意**：`SERVER_HOST` 不是服务端 `.env` 配置项——它是 Agent 构建参数（通过 `make package-agent-all SERVER_HOST=<AC外部入口>` 编译时嵌入），决定 Agent 连接哪个 AC gRPC 地址。`.env` 中服务端侧使用的是 `SERVER_IP`（宿主机 IP）和 `GRPC_PORT`（容器内端口）。多副本部署请始终使用显式 `--scale` 保持副本数一致。

### server.yaml

Server 配置模板，所有 `__XXX__` 占位符由 `deploy.sh` 从 `.env` 替换生成。
不要直接编辑 `server.yaml`，改 `.env` 就行。

### mysql.cnf

MySQL 自定义配置，挂载到容器 `/etc/mysql/conf.d/custom.cnf`。
包含字符集、连接数、InnoDB 参数、慢查询日志等优化配置。
修改后执行 `./deploy.sh restart mysql` 生效。

### nginx.conf

Nginx 反向代理配置，修改后执行 `./deploy.sh restart ui` 生效。

---

## 升级流程

```bash
# 1. 上传新版本镜像（或推送到私有仓库）
# 2. 执行升级命令
./deploy.sh upgrade
# 脚本会自动: 备份数据库 → 更新版本号 → 重新生成配置 → 拉取新镜像 → 按 .env 副本数重建服务
```

**副本数一致性**：`upgrade` 会读取 `.env` 里的 `MANAGER_REPLICAS / AGENTCENTER_REPLICAS / CONSUMER_REPLICAS`（默认各 1），显式以 `--scale` 启动，确保升级前后副本数一致，不再依赖当前 Compose 运行状态。生产 HA 部署请确保这三个变量为 2+。

如需在升级过程中同步切换副本数（例如 1→2 扩到 HA），请先在 `.env` 中调整这三个变量，再运行 `./deploy.sh upgrade`。

---

## 日志管理

日志存储在 `$DATA_DIR/logs/` 下，按服务分目录：

```
$DATA_DIR/logs/
├── agentcenter/    # AgentCenter 日志（按天轮转）
├── manager/        # Manager API 日志（按天轮转）
├── consumer/       # Consumer 日志
├── nginx/          # Nginx 访问/错误日志
└── mysql/          # MySQL 慢查询日志
```

清理旧日志：
```bash
./deploy.sh clean-logs    # 清理超过保留天数的日志
```

建议添加 crontab 定期清理：
```bash
# 每天凌晨 3 点清理旧日志
0 3 * * * /opt/mxsec-platform/deploy.sh clean-logs >> /var/log/mxsec-clean.log 2>&1
```

---

## 部署 Agent

```bash
# 开发机构建 Agent
make package-agent-all VERSION=v1.0.0 SERVER_HOST=YOUR_SERVER_IP:6751

# 目标主机安装
rpm -ivh mxsec-agent-*.rpm
systemctl enable --now mxsec-agent
```
