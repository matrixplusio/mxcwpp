# 安装部署

## 前置要求

### 服务端

- Linux 服务器（CentOS 7+ / Rocky Linux 8+ / Ubuntu 20.04+）
- Docker Engine >= 24, Docker Compose v2
- 时钟同步（NTP），所有节点需保持时钟一致

### Agent 目标主机

- 支持的操作系统（参见下方平台支持列表）
- Linux 内核 >= 4.18（eBPF / Tetragon 要求）
- 网络可达 AgentCenter gRPC 端口（默认 6751）

### 平台支持

| 发行版 | 版本 |
|--------|------|
| Rocky Linux | 9, 10 |
| Oracle Linux | 7, 8, 9 |
| CentOS | 7, 8, 9 |
| Debian | 10, 11, 12 |
| Ubuntu | 20.04, 22.04 |

运行时类型：物理机 / VM、Docker 容器宿主机、Kubernetes 节点

---

## 部署模式概览

项目支持四种部署模式，分别面向不同阶段的需求：

| 模式 | 配置文件 | 特点 | 适用场景 |
|------|---------|------|---------|
| 开发环境 | `docker-compose.dev.yml` | 源码热重载（Air），单 Kafka 节点，包含 engine/llmproxy/vulnsync 全 6 微服务 | 日常开发调试 |
| 完整 v2 编排 | `docker-compose.v2.yml` | 预构建镜像，**完整 6 微服务**（manager + agentcenter + consumer + engine + llmproxy + vulnsync + ui）+ 基础设施 | 单机 v2 部署、验证联调 |
| 压测环境 | `docker-compose.pret.yml` | 预构建镜像，3 Kafka 节点，支持 `--scale` 多副本 | 性能压测、预发布验证 |
| 生产环境 | `cluster.example.yaml` + `mxctl deploy` | 多节点角色分离，完整 HA | 正式生产部署 |

---

## 开发环境

开发环境采用 `docker-compose.dev.yml` + Air 热更新模式，不构建 Agent / 插件产物。

```bash
make dev-docker-up       # 启动开发环境（前台，带日志）
make dev-docker-up-d     # 启动开发环境（后台）
make dev-docker-logs     # 查看日志
make dev-docker-down     # 停止服务
make dev-docker-restart  # 重启后端 (manager)
make web-dev             # 本机启动前端 (端口 3000, 热更新快)
```

> 前端 web 不进容器：macOS 下 bind mount 走 virtiofs，热更新慢。后端用 Docker，前端在本机 `make web-dev` 跑，代理 /api 到 host:8080。

| 服务 | 地址 |
|------|------|
| Manager API | http://localhost:8080 |
| UI (本机 make web-dev) | http://localhost:3000 |
| AgentCenter gRPC | localhost:6751 |
| AgentCenter HTTP | localhost:6752 -> 8080 |
| Engine HTTP | localhost:8090 |
| LLMProxy HTTP | localhost:8091 |
| VulnSync HTTP | localhost:8092 |
| MySQL | localhost:13306 -> 3306 |
| Redis | localhost:16379 -> 6379 |
| Kafka | localhost:9092 |
| ClickHouse HTTP | localhost:8123 |
| ClickHouse TCP | localhost:9000 |
| Prometheus | localhost:9090 |

> 端口为示例，以 `deploy/docker-compose.dev.yml` 实际映射为准。

---

## v2 完整微服务编排

`docker-compose.v2.yml` 提供 v2.0 完整六微服务架构的单机编排，可在单台机器上启动全部 6 个 mxcwpp 服务 + 基础设施，用于联调和功能验证。

```bash
cd deploy/
cp env.example .env
vim .env  # 修改密码、SERVER_IP 等

docker compose -f docker-compose.v2.yml up -d
```

包含的 mxcwpp 服务：

| 服务 | 端口 | 职责 |
|------|------|------|
| manager | 8080 | HTTP API + 控制台后端 |
| agentcenter | 6751/6752 | Agent gRPC 接入 |
| consumer | - | Kafka 持久化（无对外端口） |
| engine | 8090 | 检测分析引擎（16 stages） |
| llmproxy | 8091 | LLM 适配网关 |
| vulnsync | 8092 | 漏洞情报融合 |
| web | 3000 | Next.js (React) SPA, 静态导出 |

基础设施服务：mysql / redis / kafka(KRaft) / clickhouse / prometheus / grafana。

---

## 压测环境

压测环境采用 `docker-compose.pret.yml`，使用预构建镜像，配置 3 个 Kafka 节点，支持通过 `--scale` 参数启动多副本。

```bash
make pret-docker-up      # 启动压测环境（前台，带日志）
make pret-docker-up-d    # 启动压测环境（后台）
make pret-docker-down    # 停止压测环境
```

---

## 生产部署

### 部署形态选型

| 形态 | 节点数 | Agent 规模 | 适用场景 |
|------|--------|-----------|---------|
| 单机 All-in-One | 1 台 | <= 50 | 评估试用、小型内网 |
| 标准生产 | 3 台 | 50 - 500 | 中小型企业 |
| 高规格生产 | 5+ 台 | 500+ | 大规模多集群 |

### 单机 All-in-One

所有服务运行在同一台机器，使用 `deploy/docker-compose.yml` 编排。

**硬件要求**：8 核 CPU / 32 GB 内存 / 100 GB SSD 系统盘 / 200 GB 数据盘（推荐：16 核 / 64 GB / 500 GB SSD）

```bash
cd deploy/
cp .env.example .env
vim .env
# 修改: SERVER_IP / JWT_SECRET / 数据库密码 / *_REPLICAS=2

docker compose --env-file .env up -d \
  --scale manager=2 --scale agentcenter=2 --scale consumer=2
```

验证：

```bash
docker compose ps
curl -X POST http://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'
```

访问 `http://<SERVER_IP>` 进入管理界面，默认账户 `admin / admin123`。

### 标准生产（3 节点）-- 集群部署

控制面、存储层、消息队列分离部署。

```
+--------------------+    +--------------------+    +--------------------+
|  node1-control     |    |  node2-storage     |    |  node3-kafka       |
|  roles: [control]  |    |  roles: [storage]  |    |  roles: [kafka]    |
|                    |    |                    |    |                    |
|  Nginx (80/443)    |    |  MySQL 8.0         |    |  Kafka Broker x3   |
|  Manager           |    |  Redis 7           |    |  (KRaft 模式)      |
|  AgentCenter       |    |  ClickHouse 24     |    |                    |
|  Consumer          |    |  Prometheus        |    |                    |
|  Engine            |    |                    |    |                    |
|  LLMProxy          |    |                    |    |                    |
|  VulnSync          |    |                    |    |                    |
|  UI (SPA)          |    |                    |    |                    |
+--------------------+    +--------------------+    +--------------------+
```

**硬件要求**：

| 节点 | CPU | 内存 | 系统盘 | 数据盘 |
|------|-----|------|--------|--------|
| node1-control 控制面 | 8 核 | 32 GB | 100 GB SSD | 100 GB |
| node2-storage 存储层 | 8 核 | 32 GB | 100 GB SSD | 500 GB SSD |
| node3-kafka 消息队列 | 4 核 | 16 GB | 50 GB SSD | 200 GB SSD |

#### mxctl 集群部署工具

`mxctl` 是集群部署的核心 CLI 工具，位于 `cmd/tools/mxctl/`，负责配置校验、预检查、渲染部署文件和远程部署。

**构建**：

```bash
go build -o ./bin/mxctl ./cmd/tools/mxctl
```

**子命令**：

| 子命令 | 说明 |
|--------|------|
| `check`（别名 `validate`） | 校验 cluster.yaml 配置文件（语法、字段完整性、节点角色约束） |
| `preflight` | 预部署检查（本地环境 + SSH 连通性 + 远端 OS / sudo / 目录可写性） |
| `render` | 根据 cluster.yaml 渲染每个节点的部署文件（Compose、server.yaml、证书、脚本） |
| `deploy` | 完整部署流程（render + SCP 上传 + 按角色顺序启动 + 健康检查） |

**通用参数**：

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-f` | `deploy/prod/cluster.example.yaml` | cluster.yaml 配置文件路径 |
| `-o` | `deploy/prod/out` | 渲染输出目录（render / deploy） |
| `--skip-install` | `false` | 跳过远端依赖安装（deploy） |
| `--skip-healthcheck` | `false` | 跳过部署后健康检查（deploy） |

**典型使用流程**：

```bash
# 1. 校验配置
./bin/mxctl check -f deploy/prod/my-cluster.yaml

# 2. 预检查（SSH 连通、远端 OS 检测、sudo 权限）
./bin/mxctl preflight -f deploy/prod/my-cluster.yaml

# 3. 仅渲染（查看输出后再决定是否部署）
./bin/mxctl render -f deploy/prod/my-cluster.yaml -o deploy/prod/out

# 4. 完整部署
./bin/mxctl deploy -f deploy/prod/my-cluster.yaml
```

**check 校验项**：
- `metadata.name`、`release.version`、`app.jwt_secret` 不能为空
- `network.ui.host`、`network.grpc.host` 不能为空
- `infrastructure.mysql.root_password` 和 `infrastructure.mysql.password` 不能为空
- 至少一个 control 节点，恰好一个 storage 节点，恰好一个 kafka 节点
- 每个 node 必须配置 `name`、`host` 和 `roles`
- `roles` 只能是 `control` / `storage` / `kafka`
- 节点 name / host 不能重复
- Kafka broker_ports 必须配置 3 个端口
- `control_plane.manager_replicas` 和 `agentcenter_replicas` 不能小于 control 节点数
- 启用 Prometheus 时必须有 storage 节点

**preflight 检查项**：
- 本地环境：`ssh`、`scp` 命令可用
- 远端节点：SSH 可连通、OS 为受支持发行版（Ubuntu / Debian / Rocky / CentOS / RHEL / Oracle / AlmaLinux）
- 非 root 用户：sudo 免密可用
- 安装目录和数据目录可创建

**deploy 执行顺序（5 步）**：

```
[1/5] 准备远端节点    -- 创建 release 目录、SCP 上传 bundle、切换 current 软链、安装依赖、Docker login
[2/5] 启动 Kafka      -- docker compose up kafka 节点
[3/5] 启动 Storage    -- docker compose up storage 节点（MySQL / Redis / ClickHouse）
[4/5] 启动 Control    -- docker compose up control 节点（Manager / AgentCenter / Consumer / Engine / LLMProxy / VulnSync / UI）
[5/5] 健康检查        -- docker compose ps + curl /health
```

每次部署生成独立的 release 目录 `{install_dir}/releases/{version}-{timestamp}/`，通过 `{install_dir}/current` 软链切换版本，支持快速回滚。

#### 集群配置工具链

集群部署使用 `deploy/prod/` 下的配置工具链：

- `cluster.example.yaml`：定义集群拓扑（节点、角色、版本、基础设施配置）
- Go 包 `internal/deploy/cluster/`：配置解析、校验、模板渲染、证书生成、远程部署
- 模板目录 `deploy/prod/templates/`：
  - `docker-compose.control.yml.tmpl` -- 控制面节点模板
  - `docker-compose.storage.yml.tmpl` -- 存储层节点模板
  - `docker-compose.kafka.yml.tmpl` -- Kafka 节点模板
- 渲染输出到 `deploy/prod/out/{cluster-name}/nodes/{node-name}/`

渲染输出结构：

```
deploy/prod/out/{cluster-name}/
├── resolved-cluster.yaml              # 应用默认值后的完整配置（用于排查）
└── nodes/
    ├── node1-control/
    │   ├── compose/
    │   │   └── docker-compose.control.yml
    │   ├── config/
    │   │   ├── server.yaml            # Manager 服务端配置
    │   │   ├── server-ac.yaml         # AgentCenter 服务端配置
    │   │   └── nginx.conf             # Nginx 反向代理配置
    │   ├── certs/                     # mTLS 证书
    │   └── scripts/                   # 部署辅助脚本
    ├── node2-storage/
    │   ├── compose/
    │   │   └── docker-compose.storage.yml
    │   └── config/
    │       ├── mysql.cnf              # MySQL 配置
    │       ├── clickhouse.xml         # ClickHouse 配置
    │       └── prometheus.yml         # Prometheus 配置
    └── node3-kafka/
        └── compose/
            └── docker-compose.kafka.yml
```

#### 集群配置示例

编辑 `deploy/prod/cluster.example.yaml`（或复制为自定义文件），定义集群拓扑：

```yaml
api_version: mxcwpp.io/v1alpha1
kind: ClusterConfig

metadata:
  name: prod-cluster
  environment: prod

release:
  version: v1.0.0
  install_dir: /opt/mxcwpp
  data_root: /data/mxcwpp
  timezone: Asia/Shanghai         # 默认 Asia/Shanghai

registry:                          # 私有镜像仓库（可选）
  domain: registry.example.com
  namespace: mxcwpp
  username: deploy
  password: change-registry-password

network:
  ui:
    scheme: https
    host: security.example.com     # 管理界面入口域名或 IP
    port: 443
  grpc:
    host: 10.0.0.10                # AgentCenter gRPC 入口（L4 LB 或控制面 IP）
    port: 6751
  additional_sans:                 # 额外 SAN（证书中包含）
    ips: ["10.0.0.100"]
    dns: ["security-internal.example.com"]

app:
  jwt_secret: change-jwt-secret
  log_level: info
  log_format: json
  prometheus_enabled: true

infrastructure:
  mysql:
    root_password: change-root-password
    database: mxcwpp
    user: mxcwpp_user
    password: change-mysql-password
    port: 13306
  redis:
    password: change-redis-password
    port: 16379
  clickhouse:
    database: mxcwpp
    user: default
    password: change-clickhouse-password
    http_port: 8123
    tcp_port: 9000
  kafka:
    enabled: true
    broker_ports: [9092, 9094, 9095]

control_plane:                     # 控制面副本数（默认 = control 节点数）
  manager_replicas: 2
  agentcenter_replicas: 2
  consumer_replicas: 2

nodes:
  - name: node1-control
    host: 10.0.0.10
    ssh_user: root                 # 默认 root
    ssh_port: 22                   # 默认 22
    ssh_key_path: ~/.ssh/id_rsa    # 支持相对路径（相对于 cluster.yaml 所在目录）
    roles: [control]
  - name: node2-storage
    host: 10.0.0.11
    roles: [storage]
  - name: node3-kafka
    host: 10.0.0.12
    roles: [kafka]
```

> 生产集群使用 `network_mode: host`（非 bridge 网络），各节点间直接通过宿主机 IP 通信。

**部署顺序**：node3-kafka（Kafka）-> node2-storage（存储）-> node1-control（控制面）

**多控制面副本分配**：当配置多个 control 节点时，`control_plane.*_replicas` 会自动均匀分配到各控制面节点。例如 2 个 control 节点 + `manager_replicas: 3` = node1 运行 2 个 Manager、node2 运行 1 个 Manager。

### 高规格生产（5+ 节点）

控制面各组件独立部署，存储层可选主从。

```
Node 1: Manager x2 + Nginx / UI
Node 2: AgentCenter x2 + HAProxy(:6751)
Node 3: Consumer x2
Node 4: MySQL + Redis + ClickHouse + Prometheus
Node 5: Kafka Broker x3 (KRaft)
Node 6: MySQL 从库 + Redis Sentinel（可选）
```

Node 1-3 可继续水平扩展，Docker Compose `--scale` 或 systemd 部署均可。

---

## deploy.sh 部署脚本

`deploy/deploy.sh` 是生产环境的部署管理脚本，支持以下命令：

| 命令 | 说明 |
|------|------|
| `./deploy.sh` | 交互式完整部署（首次） |
| `./deploy.sh start` | 启动服务 |
| `./deploy.sh stop` | 停止服务 |
| `./deploy.sh restart` | 重启服务（可指定服务名：`restart agentcenter`） |
| `./deploy.sh status` | 查看服务状态 |
| `./deploy.sh logs` | 查看日志（可指定服务名：`logs agentcenter`） |
| `./deploy.sh backup` | 备份数据库（gzip 压缩，自动清理 30 天前备份） |
| `./deploy.sh upgrade` | 升级服务（备份 -> 更新版本号 -> 更新配置 -> 构建并重启，共 4 步） |
| `./deploy.sh clean-logs` | 清理旧日志（默认保留 7 天） |
| `./deploy.sh build` | 构建镜像 |
| `./deploy.sh help` | 显示帮助信息（也支持 `--help` / `-h`） |

### 首次部署流程（7 步）

执行 `./deploy.sh`（无参数）进入交互式首次部署，流程如下：

1. **环境检测** -- 检测操作系统、Docker 版本
2. **端口检查** -- 检测所需端口是否被占用
3. **交互配置** -- 初始化 `.env` 环境变量（SERVER_IP、密码等）
4. **初始化目录** -- 创建数据、日志、证书等目录
5. **生成证书** -- 生成自签名 mTLS 证书
6. **生成 server.yaml** -- 根据 `.env` 渲染服务端配置
7. **启动服务** -- 构建镜像并启动所有容器

---

## HA 副本数配置

通过 `.env` 文件控制控制面组件的副本数：

```bash
# deploy/.env
MANAGER_REPLICAS=1       # Manager 副本数（生产建议 2+）
AGENTCENTER_REPLICAS=1   # AgentCenter 副本数（生产建议 2+）
CONSUMER_REPLICAS=1      # Consumer 副本数（生产建议 2+）
```

`deploy.sh` 的 `start` / `upgrade` 命令会读取这些值并自动生成 `--scale` 参数，保持升级前后副本数一致。

手动启动时需显式指定副本数：

```bash
docker compose --env-file .env up -d \
  --scale manager=2 --scale agentcenter=2 --scale consumer=2
```

---

## 证书管理

```bash
# 生成自签名 mTLS 证书
./scripts/generate-certs.sh
# 或使用 Makefile
make certs
```

证书目录结构：

```
deploy/certs/
  ca.crt / ca.key            # CA 证书
  server.crt / server.key    # AgentCenter 使用
  agent.crt / agent.key      # Agent 使用
  client.crt / client.key    # agent.crt/key 的副本，兼容旧名称
```

Agent 首次连接时 AgentCenter 自动下发证书，后续连接切换为正式 mTLS。

---

## 镜像构建

```bash
# 构建所有镜像（manager / agentcenter / consumer / ui 共 4 个）
./scripts/build-images.sh --version v1.0.0

# 构建并推送到私有仓库
./scripts/build-images.sh --version v1.0.0 --registry registry.example.com/mxcwpp --push
```

支持参数：`--version`（版本号）、`--registry`（镜像仓库前缀）、`--push`（构建后推送）。脚本一次构建全部 4 个镜像。

镜像建议在目标架构的机器上构建，避免跨平台问题。

---

## Agent 部署

### 构建安装包

```bash
# 构建 Agent RPM/DEB（SERVER_HOST 编译时嵌入，指向 AC gRPC 入口）
make package-agent-all VERSION=1.0.0 SERVER_HOST=<AC_LB_IP>:6751

# 构建插件包
make package-plugins-all VERSION=1.0.0
```

> `SERVER_HOST` 是 Agent 构建参数，不是服务端配置项。生产环境应指向四层 LB 或 AC 的外部入口地址。

### 安装

```bash
# RPM (CentOS / Rocky / Oracle)
sudo rpm -ivh mxcwpp-agent-1.0.0.x86_64.rpm

# DEB (Debian / Ubuntu)
sudo dpkg -i mxcwpp-agent_1.0.0_amd64.deb
```

### 目录结构

| 路径 | 说明 |
|------|------|
| `/var/lib/mxcwpp-agent/` | 工作目录 |
| `/var/lib/mxcwpp-agent/certs/` | 证书目录 |
| `/var/lib/mxcwpp-agent/plugin/` | 插件目录 |
| `/var/log/mxcwpp-agent/` | 日志目录 |

### 管理

```bash
systemctl status mxcwpp-agent
systemctl restart mxcwpp-agent
journalctl -u mxcwpp-agent -f
```

---

## 升级

### 服务端升级

推荐使用 `deploy.sh upgrade`（自动备份 -> 更新版本 -> 重建容器）：

```bash
git pull origin main
./scripts/build-images.sh --version v1.1.0
cd deploy && ./deploy.sh upgrade
```

手动升级时必须显式带 `--scale` 保持副本数：

```bash
cd deploy
sed -i 's/^VERSION=.*/VERSION=v1.1.0/' .env
docker compose --env-file .env up -d \
  --scale manager=2 --scale agentcenter=2 --scale consumer=2
```

> `docker compose restart` 只重启容器不切换镜像，升级必须用 `up -d`。

### Agent 升级

```bash
# 服务端推送（管理界面触发）
# CLI 主动更新
mxcwpp-agent --update
mxcwpp-agent --update --server http://manager:8080
# 本地包更新
mxcwpp-agent --update --file ./mxcwpp-agent-1.1.0.rpm
```

### Agent 运维命令

```bash
# 查看运行状态（systemd 状态、PID、uptime、Server 可达性、Agent ID）
mxcwpp-agent --status
mxcwpp-agent --status --json      # 机器可解析格式

# 查看本地日志（默认末尾 100 行）
sudo mxcwpp-agent --logs
sudo mxcwpp-agent --logs -n 500   # 末尾 500 行
sudo mxcwpp-agent --logs -f       # 实时跟踪（Ctrl-C 退出）

# 显示配置快照（构建嵌入的 Server 地址、证书包状态、Agent ID）
mxcwpp-agent --config
mxcwpp-agent --config --json

# 生成诊断包（最近 7 天日志 + systemctl/journalctl/uname/ss 输出）
sudo mxcwpp-agent --diag
sudo mxcwpp-agent --diag -o /tmp/diag.tar.gz
# 输出文件权限 0600，上传前检查敏感信息
```

> `--logs` 和 `--diag` 需要 root 权限读取 `/var/log/mxcwpp-agent/`。

---

## 备份

```bash
./deploy/deploy.sh backup
```

备份文件存放在 `deploy/backup/` 目录，包含数据库和配置文件。

---

## 网络与端口

| 端口 | 宿主机端口 | 协议 | 方向 | 说明 |
|------|-----------|------|------|------|
| 80 / 443 | 80 / 443 | HTTP/S | 用户 -> Nginx | 管理界面 + API（UI） |
| 8080 | 8080 | HTTP | 内网 | Manager HTTP API |
| 6751 | 6751 | gRPC | Agent -> AC | AgentCenter 接入（mTLS），生产必须接 L4 LB |
| 3306 | 13306 | TCP | 内网 | MySQL |
| 6379 | 16379 | TCP | 内网 | Redis |
| 9000 | 9000 | TCP | 内网 | ClickHouse Native（TCP） |
| 8123 | 8123 | HTTP | 运维 | ClickHouse HTTP |
| 9092 / 9094 / 9095 | 9092 / 9094 / 9095 | TCP | 内网 | Kafka Broker |
| 9090 | 9090 | HTTP | 内网 | Prometheus |

**防火墙规则**：仅 80/443 和 6751 对外开放，存储层端口限制为控制面节点访问。

---

## Makefile 命令速查

| 命令 | 说明 |
|------|------|
| `make proto` | 生成 Protobuf Go 代码 |
| `make build-server` | 构建 Server 二进制（agentcenter + manager） |
| `make build-consumer` | 构建 Consumer 二进制 |
| `make package-agent` | 打包 Agent（单架构 RPM/DEB） |
| `make package-agent-all` | 打包 Agent（amd64 + arm64） |
| `make package-plugins` | 构建所有插件（单架构） |
| `make package-plugins-all` | 构建所有插件（amd64 + arm64） |
| `make package-all` | 构建全部（单架构） |
| `make package-all-arch` | 构建全部（amd64 + arm64） |
| `make test` | 运行测试 |
| `make fmt` | 格式化代码 |
| `make lint` | 代码检查 |
| `make deps` | 下载依赖 |
| `make clean` | 清理构建产物 |
| `make certs` | 生成 mTLS 证书 |
| `make dev-docker-up` | 启动开发环境（前台） |
| `make dev-docker-up-d` | 启动开发环境（后台） |
| `make dev-docker-down` | 停止开发环境 |
| `make dev-docker-logs` | 查看开发环境日志 |
| `make dev-docker-restart` | 重启后端 (manager) |
| `make web-dev` | 本机启动前端 (端口 3000) |
| `make pret-docker-up` | 启动压测环境（前台） |
| `make pret-docker-up-d` | 启动压测环境（后台） |
| `make pret-docker-down` | 停止压测环境 |

构建示例：

```bash
make package-agent-all VERSION=1.0.5 SERVER_HOST=10.0.0.1:6751
make package-all-arch VERSION=1.0.5 SERVER_HOST=10.0.0.1:6751
```

输出目录：Agent RPM/DEB 在 `dist/packages/`，插件二进制在 `dist/plugins/`。

---

## 存储容量估算

以 100 台 Agent、30 天保留为基准：

| 数据类型 | 存储位置 | 估算量 |
|---------|---------|--------|
| 心跳 | MySQL | ~4 GB |
| 资产指纹 | MySQL | ~1 GB |
| 基线结果 | ClickHouse | ~180 MB |
| FIM 事件 | ClickHouse | ~150 MB |
| eBPF 事件 | ClickHouse | ~130 GB（TTL 30 天自动清理） |
| 告警 | MySQL + ClickHouse | ~500 MB |
| Kafka 消息 | Kafka 磁盘 | ~50 GB 峰值（保留 72h） |

eBPF 事件量取决于 Tetragon 策略配置，建议根据试运行数据调整磁盘规划。

---

## 健康检查

```bash
# 服务状态
docker compose ps

# API 健康检查
curl http://localhost/health
curl http://localhost/api/v1/health

# AC 服务发现（需认证）
TOKEN=$(curl -s -X POST http://localhost/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}' | jq -r '.data.token')
curl -H "Authorization: Bearer $TOKEN" http://localhost/api/v1/discovery/agentcenter

# Consumer 消费状态
docker compose logs consumer | tail -20

# Agent 连通性（需已暴露 AC gRPC 端口）
nc -zv <AC_HOST> 6751
```
