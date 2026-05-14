# 配置说明

## 配置体系

MxSec 服务端配置由两部分组成：

- **环境变量**（`.env`）：部署级参数，如数据库地址、密码、副本数
- **配置文件**（`server.yaml`）：应用级参数，由 `.env` 渲染模板生成

### 配置渲染链路

```
deploy/.env  -->  deploy/config/server.yaml.tpl  -->  deploy/config/server.yaml（运行时生效）
```

渲染过程：

1. `deploy.sh`（`init_config` 函数）启动时 `source` 读取 `.env` 文件
2. 将 `server.yaml.tpl` 复制为 `server.yaml`
3. 通过 `sed -e 's|__XXX__|${VALUE}|g'` 批量替换所有 `__XXX__` 占位符为 `.env` 中的变量值
4. 删除 sed 产生的 `.bak` 临时文件

`deploy.sh` 的 `start`、`upgrade`、`restart` 命令都会触发配置重新渲染。**生产环境不要直接编辑渲染后的 `server.yaml`**，应修改 `.env` 后通过 `deploy.sh` 重新生成。

如需新增配置项，需在三处同步：

1. `deploy/.env.example` -- 添加变量和默认值
2. `deploy/config/server.yaml.tpl` -- 添加 `__XXX__` 占位符
3. `deploy/deploy.sh` 的 `init_config` 函数 -- 添加对应的 `sed` 替换行

---

## 环境变量（.env）

完整变量列表，与 `deploy/.env.example` 保持一致。

### 基础配置

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `VERSION` | 镜像版本号 | dev |
| `TZ` | 时区 | Asia/Shanghai |
| `SERVER_IP` | 宿主机 IP（用于拼接插件下载地址等） | 127.0.0.1 |
| `JWT_SECRET` | JWT 签名密钥（生产必须替换） | dev-secret-change-in-production |
| `INSTANCE_ID` | 多实例部署时的实例标识（留空自动生成） | （空） |

### MySQL

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `MYSQL_HOST` | 主机地址 | mysql |
| `MYSQL_PORT` | 端口 | 3306 |
| `MYSQL_USER` | 用户名 | mxsec_user |
| `MYSQL_PASSWORD` | 密码 | （需手动设置） |
| `MYSQL_DATABASE` | 数据库名 | mxsec |
| `MYSQL_ROOT_PASSWORD` | root 密码 | （需手动设置） |
| `DB_MAX_IDLE_CONNS` | 空闲连接数 | 20 |
| `DB_MAX_OPEN_CONNS` | 最大连接数 | 200 |
| `DB_CONN_MAX_LIFETIME` | 连接最大存活时间 | 1h |

### Redis

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `REDIS_ADDR` | 单节点地址 | redis:6379 |
| `REDIS_PASSWORD` | 密码 | （空） |
| `REDIS_DB` | 数据库编号 | 0 |
| `REDIS_POOL_SIZE` | 连接池大小 | 100 |
| `REDIS_SENTINEL` | 是否启用 Sentinel 模式 | false |
| `REDIS_MASTER_NAME` | Sentinel master 名称 | mymaster |
| `REDIS_SENTINEL_ADDR_1` | Sentinel 节点 1 地址 | redis-sentinel-1:26379 |
| `REDIS_SENTINEL_ADDR_2` | Sentinel 节点 2 地址 | redis-sentinel-2:26379 |
| `REDIS_SENTINEL_ADDR_3` | Sentinel 节点 3 地址 | redis-sentinel-3:26379 |

### Kafka

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `KAFKA_ENABLED` | 是否启用 | true |
| `KAFKA_BROKER_1` | Broker 1 地址 | kafka-1:9092 |
| `KAFKA_BROKER_2` | Broker 2 地址 | kafka-2:9092 |
| `KAFKA_BROKER_3` | Broker 3 地址 | kafka-3:9092 |
| `KAFKA_TOPIC_PREFIX` | Topic 前缀（环境隔离用） | （空） |

`KAFKA_TOPIC_PREFIX` 在 `.env.example` 中默认为空（开发环境不需要前缀）。生产集群建议设为 `prod`，用于多环境共享 Kafka 集群时的 topic 隔离，例如 topic 会变为 `prod.agent_heartbeat`。

### ClickHouse

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `CLICKHOUSE_ENABLED` | 是否启用 | true |
| `CLICKHOUSE_ADDR` | 地址（Native 协议） | clickhouse:9000 |
| `CLICKHOUSE_DATABASE` | 数据库名 | mxsec |
| `CLICKHOUSE_USER` | 用户名 | default |
| `CLICKHOUSE_PASSWORD` | 密码 | （空） |

### Prometheus

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `PROMETHEUS_ENABLED` | 是否启用 Prometheus 指标 | true |
| `PROMETHEUS_QUERY_URL` | Prometheus Query API 地址 | http://prometheus:9090 |
| `PROMETHEUS_TIMEOUT` | 请求超时 | 10s |

Prometheus 为可选外部依赖，本项目不自动拉起 Prometheus 服务。启用后，Server 会将监控指标推送到 Prometheus，并通过 `query_url` 查询历史数据用于前端监控面板。未启用时，监控数据回退到 MySQL 存储。

### 网络与端口

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `GRPC_PORT` | AgentCenter gRPC 监听端口 | 6751 |
| `SERVER_HTTP_PORT` | Manager / AC HTTP 管理端口 | 8080 |
| `HTTP_PORT` | Nginx HTTP 端口 | 80 |
| `HTTPS_PORT` | Nginx HTTPS 端口 | 443 |
| `MANAGER_PORT` | Manager 端口 | 8080 |
| `MANAGER_ADDR` | AC 向 Manager 注册使用的内部地址 | http://manager:8080 |

### 控制面副本数

| 变量 | 说明 | 默认值 | 生产建议 |
|------|------|--------|----------|
| `MANAGER_REPLICAS` | Manager 副本数 | 1 | 2+ |
| `AGENTCENTER_REPLICAS` | AgentCenter 副本数 | 1 | 2+ |
| `CONSUMER_REPLICAS` | Consumer 副本数 | 1 | 2+ |

默认值 1 用于单机开发和功能验证。`deploy.sh` 的 `start` / `upgrade` 命令会读取这些变量并生成 `--scale` 参数，保持升级前后副本数一致。生产环境建议 2 个以上副本实现高可用。

### 数据与日志

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `DATA_DIR` | 数据持久化目录 | ./data |
| `LOG_LEVEL` | 日志级别 | debug |
| `LOG_FORMAT` | 日志格式 | console |
| `LOG_MAX_AGE` | 日志保留天数 | 7 |
| `LOG_RETENTION_DAYS` | 日志保留天数（别名） | 7 |

### Agent

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `HEARTBEAT_INTERVAL` | Agent 心跳间隔（秒） | 60 |

### 插件

| 变量 | 说明 | 默认值 |
|------|------|--------|
| `PLUGINS_DIR` | 服务端插件存放目录 | /opt/mxsec-platform/plugins |
| `PLUGINS_BASE_URL` | Agent 下载插件的 URL 前缀（必须 Agent 可达） | （空，自动拼接） |

`PLUGINS_BASE_URL` 为空时，`deploy.sh` 会自动拼接为 `http://$SERVER_IP:$HTTP_PORT/api/v1/plugins/download`。

> `SERVER_HOST` 不是 `.env` 配置项，而是 Agent 构建参数（`make package-agent-all SERVER_HOST=...`），编译时嵌入 Agent 二进制，决定 Agent 连接哪个 AC gRPC 入口。

---

## 服务端配置文件（server.yaml）

以下为 `server.yaml.tpl` 模板渲染后的各配置块说明，包含完整字段和语义。

### server

```yaml
server:
  grpc:
    host: "0.0.0.0"
    port: 6751              # AgentCenter gRPC 监听端口
  http:
    host: "0.0.0.0"
    port: 8080              # Manager / AC HTTP 管理端口
  jwt_secret: "xxx"         # JWT 签名密钥
  manager_addr: "http://manager:8080"   # AC 向 Manager 注册使用的地址
  instance_id: ""           # 多实例部署时的实例标识（留空自动生成）
  external_url: ""          # 外网访问地址（如 https://mxsec.example.com），用于拼接 K8s Audit Webhook URL
```

### database

```yaml
database:
  type: "mysql"
  mysql:
    host: "mysql"
    port: 3306
    user: "mxsec_user"
    password: "xxx"
    database: "mxsec"
    charset: "utf8mb4"
    parse_time: true
    loc: "Asia/Shanghai"
    max_idle_conns: 20
    max_open_conns: 200
    conn_max_lifetime: "1h"
```

注意：数据库用户名统一为 `mxsec_user`，与 `.env.example`、`deploy.sh`、`configs/server.yaml.example` 保持一致。

`database.type` 支持 `mysql`（默认）和 `postgres` 两种。PostgreSQL 配置示例：

```yaml
database:
  type: "postgres"
  postgres:
    host: "postgres"
    port: 5432
    user: "mxsec_user"
    password: "xxx"
    database: "mxsec"
    sslmode: "disable"
    timezone: "Asia/Shanghai"
    max_idle_conns: 20
    max_open_conns: 200
    conn_max_lifetime: "1h"
```

### redis -- 单节点模式

```yaml
redis:
  addr: "redis:6379"
  password: ""
  db: 0
  pool_size: 100
```

### redis -- Sentinel 高可用模式

生产环境建议使用 Sentinel 模式。在 `.env` 中设置 `REDIS_SENTINEL=true` 即可启用：

```yaml
redis:
  sentinel: true
  master_name: "mymaster"
  sentinel_addrs:
    - "redis-sentinel-1:26379"
    - "redis-sentinel-2:26379"
    - "redis-sentinel-3:26379"
  password: ""
  db: 0
```

启用 Sentinel 后，`addr` 字段不再生效，客户端通过 Sentinel 节点自动发现 master。`master_name` 需与 Redis Sentinel 配置中的 master 名称一致。

**高级连接参数**（可选，一般使用默认值即可）：

```yaml
redis:
  min_idle_conns: 10       # 最小空闲连接数
  dial_timeout: "5s"       # 连接超时
  read_timeout: "3s"       # 读超时
  write_timeout: "3s"      # 写超时
  # cluster: false         # 集群模式（预留，当前未实现）
  # cluster_addrs: []      # 集群节点地址列表
```

### kafka

```yaml
kafka:
  enabled: true
  brokers:
    - "kafka-1:9092"
    - "kafka-2:9092"
    - "kafka-3:9092"
  topic_prefix: ""          # 开发环境为空；生产集群建议设为 "prod"
  producer:
    required_acks: -1       # 等待所有 ISR 副本确认（最高可靠性）
```

`topic_prefix` 用于环境隔离。为空时 topic 名称不加前缀；设为 `prod` 后，所有 topic 自动加上 `prod.` 前缀。

**Producer 高级参数**（可选）：

```yaml
kafka:
  producer:
    required_acks: -1          # 0=NoResponse, 1=WaitForLocal, -1=WaitForAll
    max_message_bytes: 1048576 # 单条消息最大字节数（默认 1MB）
    flush_messages: 500        # 批量发送消息数阈值
    flush_frequency: "500ms"   # 批量发送时间间隔
    retry_max: 3               # 发送失败重试次数
```

### clickhouse

```yaml
clickhouse:
  enabled: true
  addrs: ["clickhouse:9000"]
  database: "mxsec"
  username: "default"
  password: ""
  max_open_conns: 50
  max_idle_conns: 10
  conn_max_lifetime: 1h
```

使用 Native 协议（端口 9000），支持多节点地址列表。连接池参数 `max_open_conns`、`max_idle_conns`、`conn_max_lifetime` 在模板中有硬编码默认值（不通过 `.env` 配置），如需调整需直接修改 `server.yaml.tpl`。

**高级参数**（可选）：

```yaml
clickhouse:
  dial_timeout: "10s"       # 连接超时
  read_timeout: "30s"       # 读超时
  write_timeout: "30s"      # 写超时
  batch_size: 10000         # 批量写入条数阈值
  flush_timeout: "5s"       # 批量写入时间间隔
```

### metrics（Prometheus）

```yaml
metrics:
  prometheus:
    enabled: true
    query_url: "http://prometheus:9090"
    timeout: "10s"
```

Prometheus 作为可选的监控后端。启用后，Server 通过 Prometheus 存储和查询监控指标数据。未启用时，监控数据回退到 MySQL 存储。

本地开发配置（`configs/server.yaml.example`）中提供了更完整的 Prometheus 配置选项，包括 Remote Write 和 Pushgateway 两种推送方式：

```yaml
metrics:
  # MySQL 存储（默认）
  mysql:
    enabled: true
    retention_days: 30
    batch_size: 100
    flush_interval: 5s
  # Prometheus（可选，启用后 MySQL 存储自动禁用）
  prometheus:
    enabled: false
    remote_write_url: "http://prometheus:9090/api/v1/write"
    query_url: "http://prometheus:9090"
    pushgateway_url: ""         # 与 remote_write_url 二选一
    job_name: "mxsec-platform"
    timeout: 10s
```

### mtls

```yaml
mtls:
  ca_cert: "/etc/mxsec-platform/certs/ca.crt"
  server_cert: "/etc/mxsec-platform/certs/server.crt"
  server_key: "/etc/mxsec-platform/certs/server.key"
```

mTLS 用于 Agent 与 AgentCenter 之间的双向认证通信。证书由 `deploy.sh` 的 `init` 命令调用 `scripts/generate-certs.sh` 自动生成。证书路径为容器内路径，通过 volume 挂载 `deploy/certs/` 目录映射。

### log

```yaml
log:
  level: "debug"            # debug / info / warn / error
  format: "console"         # console / json
  file: "/var/log/mxsec-platform/server.log"
  error_file: "/var/log/mxsec-platform/error.log"
  max_age: 7                # 日志保留天数
```

- `level`：日志级别。开发环境默认 `debug`，生产环境建议 `info` 或 `warn`
- `format`：`console` 格式适合开发环境终端阅读，`json` 格式适合生产环境日志采集（ELK / Loki 等）
- `file` / `error_file`：日志输出文件路径。`error_file` 单独记录 error 级别及以上日志，便于快速定位问题
- `max_age`：日志文件保留天数，超过自动清理

### agent

```yaml
agent:
  heartbeat_interval: 60    # Agent 心跳上报间隔（秒）
  work_dir: "/var/lib/mxsec-agent"
```

此配置块定义 Server 端对 Agent 行为的预期参数。`heartbeat_interval` 决定 Agent 心跳频率，也影响 Server 端判定 Agent 离线的超时阈值。

### plugins

```yaml
plugins:
  dir: "/opt/mxsec-platform/plugins"
  base_url: "http://<SERVER_IP>/api/v1/plugins/download"   # Agent 可达的下载地址
```

- `dir`：服务端插件文件存放目录（容器内路径）
- `base_url`：Agent 下载插件时使用的 URL 前缀，**必须是 Agent 网络可达的地址**，不能使用 `localhost`
- `sign_private_key`：Ed25519 签名私钥文件路径（可选），用于对插件 SHA256 进行签名验证，Agent 下载插件时校验签名防篡改

### llm（可选）

```yaml
llm:
  api_url: "https://api.anthropic.com/v1"   # LLM API 地址
  api_key: ""                                 # API Key
  model: "claude-sonnet-4-20250514"          # 模型名称
```

启用后，Manager 可通过 LLM 对告警事件进行辅助分析，生成告警摘要和处置建议。未配置 `api_key` 时该功能自动禁用。

---

## Agent 配置

Agent 配置分为编译时嵌入和运行时服务端下发两部分。运行时不依赖本地配置文件。

### 编译时参数

通过 `make package-agent-all` 嵌入（`-ldflags` 注入）：

| 参数 | 说明 |
|------|------|
| `VERSION` | Agent 版本号 |
| `SERVER_HOST` | AC gRPC 入口地址（IP:Port 或域名:Port） |

构建示例：

```bash
go build -ldflags "-X main.serverHost=10.0.0.1:6751 -X main.buildVersion=1.0.0" ./cmd/agent
```

### 运行时默认值

Agent 内置以下默认配置，不需要外部配置文件：

| 配置 | 默认值 |
|------|--------|
| 日志路径 | /var/log/mxsec-agent/agent.log |
| 日志轮转 | 每天一个文件（agent.log.YYYY-MM-DD） |
| 日志保留 | 7 天 |
| Agent ID 文件 | /var/lib/mxsec-agent/agent_id |
| 证书目录 | /var/lib/mxsec-agent/certs/（由 Server 下发） |

### 服务发现

Agent 支持两种方式发现 AgentCenter：

1. **SD 接口**：查询 Manager `GET /api/v1/discovery/agentcenter`，获取健康 AC 列表
2. **静态地址**：配置文件中写死 AC 地址列表，作为 SD 不可用时的回退

```yaml
server:
  agent_center:
    discovery_url: "http://manager-lb:8080/api/v1/discovery/agentcenter"
    addresses:                    # 回退静态地址
      - "agentcenter-1:6751"
      - "agentcenter-2:6751"
```

Agent 使用 power-of-two-choices 算法选择负载较低的 AC 实例。

---

## Nginx 配置

配置文件：`deploy/config/nginx.conf`

主要职责：

- 托管 UI 静态文件（`/`）
- 反向代理 API 到 Manager 集群（`/api/` -> upstream manager）
- 反向代理插件下载（`/uploads/` -> Manager:8080）

多 Manager 实例的 upstream 配置示例：

```nginx
upstream mxsec-manager {
    least_conn;
    server manager-1:8080;
    server manager-2:8080;
}
```

---

## 关键配置文件一览

| 文件 | 说明 |
|------|------|
| `deploy/.env` | 部署环境变量（从 .env.example 复制后修改） |
| `deploy/.env.example` | 环境变量模板（所有变量的参考） |
| `deploy/config/server.yaml.tpl` | 服务端配置模板（含 `__XXX__` 占位符） |
| `deploy/config/server.yaml` | 渲染后的运行时配置（gitignore，不要手动编辑） |
| `deploy/config/nginx.conf` | Nginx 配置 |
| `deploy/config/mysql.cnf` | MySQL 配置 |
| `deploy/docker-compose.yml` | Docker Compose 编排 |
| `configs/server.yaml.example` | 本地开发配置示例（完整注释版） |
| `configs/agent.yaml.example` | Agent 配置说明 |
| `configs/rules/` | 内置 CEL 检测规则（通过 go:embed 嵌入二进制） |

---

## 配置建议

1. **JWT_SECRET**：生产环境必须使用高强度随机字符串，建议 32 字符以上
2. **MYSQL_USER**：统一使用 `mxsec_user`，不要使用 root 账户连接应用数据库
3. **PLUGINS_BASE_URL**：不能写成 Agent 无法访问的 `localhost`，必须是 Agent 网络可达的地址
4. **MANAGER_ADDR**：必须保证 AgentCenter 能回连 Manager（同一 Docker 网络内可用服务名）
5. **数据盘**：MySQL、ClickHouse、Kafka 数据建议挂载到独立磁盘，避免磁盘 IO 争抢
6. **Sentinel / Kafka / ClickHouse**：启用对应功能时，必须确保端点可达
7. **日志级别**：生产环境建议 `info` 或 `warn`，避免 `debug` 级别产生大量日志
8. **副本数**：生产环境 `MANAGER_REPLICAS`、`AGENTCENTER_REPLICAS`、`CONSUMER_REPLICAS` 建议设为 2 以上
