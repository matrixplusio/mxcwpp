# 常见问题

## Server 端

### AgentCenter 无法启动

1. 检查端口占用：`lsof -i :6751`
2. 检查证书文件：`ls -la deploy/certs/`，确认 `ca.crt`、`server.crt`、`server.key` 存在且权限正确
3. 检查配置：`deploy/config/server.yaml` 中 `grpc.port` 是否与 `.env` 一致
4. 查看日志：`docker compose logs agentcenter`

### Manager API 返回 500

1. 查看日志定位错误：`docker compose logs manager | grep ERROR`
2. 检查 MySQL 连接：确认 MySQL 服务运行且 `.env` 中的凭证正确
3. 检查表结构：重启 Manager 触发 Gorm AutoMigrate 自动建表/补字段

### Consumer 持续报错

1. 检查 Kafka 连通性：确认 Broker 地址与 `.env` 配置一致
2. 检查 DLQ 堆积：观察 `*.dlq` Topic 是否有大量失败消息
3. 检查 ClickHouse 连接：Consumer 写入 ClickHouse 失败时会进 DLQ
4. 查看日志：`docker compose logs consumer | grep ERROR`

### 数据库连接失败

1. 确认 MySQL 服务运行：`docker compose ps mysql`
2. 检查凭证：`deploy/.env` 中的 `MYSQL_USER` / `MYSQL_PASSWORD`
3. 测试连接：`docker compose exec mysql mysql -u mxsec -p mxsec`

### 服务启动顺序异常

MySQL / Redis / Kafka / ClickHouse 需要先就绪，控制面组件有健康检查依赖。如果数据库尚未初始化完成，Manager / AgentCenter / Consumer 会自动重启重试。

如果持续失败，手动检查依赖服务状态：

```bash
docker compose ps
docker compose logs mysql | tail -20
docker compose logs redis | tail -20
docker compose logs kafka-1 | tail -20
```

## Agent 端

### Agent 无法连接 Server

1. **检查地址**：Agent 构建时嵌入的 `SERVER_HOST` 是否指向正确的 AC 入口（生产环境应为 L4 LB 地址）
2. **检查网络**：`nc -zv <agentcenter-host> 6751`
3. **检查防火墙**：确认 6751 端口开放
4. **检查证书**：
   - 首次连接：AgentCenter 自动下发证书，确认服务端 `deploy/certs/` 完整
   - 后续连接：检查 `/var/lib/mxsec-agent/certs/` 下 `ca.crt`、`client.crt`、`client.key`
   - mTLS 连续失败 3 次后 Agent 会暂时降级为不安全模式重新取证
5. **检查 DNS**：Agent 配置的主机名能否正确解析

### 插件未启动

1. 检查插件文件是否存在：`ls -la /var/lib/mxsec-agent/plugin/`
2. 检查执行权限：`chmod +x /var/lib/mxsec-agent/plugin/baseline`
3. 查看 Agent 日志：`tail -f /var/log/mxsec-agent/agent.log | grep plugin`
4. 确认 Server 已下发插件配置（插件版本和 sha256 需匹配）

### 没有检测数据上报

1. 确认 Agent 在线：查看管理界面主机列表或 `GET /api/v1/hosts`
2. 确认已创建扫描任务：查看 `GET /api/v1/tasks`
3. 检查插件运行状态：Agent 日志中搜索插件名称
4. 检查 AgentCenter 是否收到数据：`docker compose logs agentcenter | grep "baseline\|8000"`
5. 检查 Consumer 是否正常消费：`docker compose logs consumer | grep "write"`

### Agent 更新方式

Agent 支持三种更新方式：

```bash
# 服务端推送更新（管理界面触发）
# CLI 主动更新
mxsec-agent --update
mxsec-agent --update --server http://manager:8080
# 本地文件更新
mxsec-agent --update --file ./mxsec-agent-1.1.0.rpm
```

## 前端

### 无法连接 API

1. 确认 Manager 运行：`curl http://localhost/api/v1/health`
2. 检查 Nginx 代理配置：`deploy/config/nginx.conf` 中 `/api/*` 的 upstream 是否指向 Manager
3. 检查 CORS 配置

### 登录后立即跳回登录页

1. 检查 Token 存储：浏览器 DevTools → Application → localStorage
2. 检查 login 接口响应是否返回了 token
3. 检查 Nginx 是否正确代理了 API 请求（注意 `/api/` 结尾的斜杠）

### 页面空白

1. 检查浏览器 Console（F12）是否有 JavaScript 错误
2. 确认前端构建成功：`cd ui && npm run build`
3. 检查 Nginx 静态文件路径配置

## 数据库

### 查询慢

1. 检查关键索引：
   - `scan_results`：`(host_id, rule_id, checked_at DESC)`、`(host_id, checked_at DESC)`
   - `scan_tasks`：`(status, created_at)`
2. 检查数据量：`SELECT COUNT(*) FROM scan_results`，超大表考虑清理历史数据
3. 开启慢查询日志：`SET GLOBAL slow_query_log = 'ON'`

### 表不存在

重启 Manager 或 AgentCenter 触发 Gorm AutoMigrate 自动建表。

### ClickHouse 写入积压

1. 检查 ClickHouse 磁盘空间
2. 检查 parts 数量：`SELECT count() FROM system.parts WHERE active AND database = 'mxsec'`
3. 如果 parts 过多，等待后台 merge 完成或适当调大 Consumer 的批量写入间隔

## mxctl 工具

### 如何使用 mxctl 部署集群

构建：`go build -o ./bin/mxctl ./cmd/tools/mxctl`。典型流程：`mxctl check -f cluster.yaml`（校验配置）→ `mxctl preflight -f cluster.yaml`（SSH 连通性和远端环境检查）→ `mxctl deploy -f cluster.yaml`（完整部署）。详见[部署文档](deployment.md)。

### mxctl preflight 失败提示 unsupported_os

远端节点的 `/etc/os-release` 中 `ID` 不在支持列表中（ubuntu / debian / rocky / rhel / centos / almalinux / ol）。确认操作系统发行版是否受支持。

## 集群部署问题

### 多节点部署时 AC 注册不上 Manager

检查 `network_mode: host` 下端口是否可达，确认 Manager HTTP 端口 8080 在节点间可访问。AC 注册接口为 `POST /api/v1/internal/ac/register`，启动时最多重试 3 次。

排查步骤：

1. 在 AC 所在节点执行：`curl http://<manager-ip>:8080/api/v1/health`
2. 检查 AC 启动日志：`docker compose logs agentcenter | grep register`
3. 确认防火墙规则允许节点间 8080 端口通信
4. 检查 `.env` 中 `MANAGER_HOST` 是否配置为 Manager 节点的实际 IP

### Kafka 跨节点 Broker 通信失败

检查 `KAFKA_ADVERTISED_LISTENERS` 配置，生产 host 网络下需使用实际 IP 而非容器名。

排查步骤：

1. 确认每个 Broker 的 `KAFKA_ADVERTISED_LISTENERS` 使用了节点真实 IP
2. 在其他节点测试连通性：`nc -zv <broker-ip> 9092`
3. 检查 Kafka 日志：`docker compose logs kafka-1 | grep -i "listener\|advertised"`
4. 确认所有 Broker 节点间 9092 端口互通

## mTLS 证书问题

### Agent 首次连接报 TLS 握手失败

Agent 首次连接允许无证书降级（insecure 模式），连接后 Server 自动下发证书，后续恢复 mTLS。如果首次连接就报 TLS 握手失败，说明降级逻辑未生效或 CA 证书有问题。

排查步骤：

1. 检查 Server 端 `ca.crt` 是否存在且有效：`openssl x509 -in deploy/certs/ca.crt -noout -dates`
2. 检查 AgentCenter 日志中是否有证书相关错误：`docker compose logs agentcenter | grep -i "tls\|cert"`
3. 确认 Agent 版本支持 insecure 降级（v1.0.0 及以上）
4. 如果 CA 证书损坏，执行 `make certs` 重新生成后重启 Server

### 证书过期如何更新

执行 `make certs` 重新生成全部证书，然后重启 Server 组件。Agent 会在下次心跳时自动获取新证书。

操作步骤：

```bash
# 1. 重新生成证书
make certs

# 2. 重启 Server 端所有组件
docker compose restart agentcenter manager

# 3. 验证证书有效期
openssl x509 -in deploy/certs/server.crt -noout -dates
openssl x509 -in deploy/certs/ca.crt -noout -dates
```

注意事项：

- 证书更新后无需手动操作 Agent，Agent 心跳周期内会自动拉取新证书
- 如果大量 Agent 同时拉取证书，注意 Server 端负载
- 建议在业务低峰期执行证书更换

## 业务问题

### 如何修改内置检测规则

内置规则通过 `configs/rules/builtin-rules.yaml` 嵌入到二进制中（`go:embed`），服务启动时自动同步到数据库 `detection_rules` 表。用户可在管理界面编辑内置规则，编辑后自动标记 `user_modified=true`，后续版本升级不会覆盖用户修改。

### 内置规则和自定义规则的区别

内置规则带 `builtin=true` 标记，不可删除只能禁用；自定义规则可自由编辑和删除。版本升级时，新增的内置规则自动导入，已有未修改的内置规则自动更新，用户修改过的规则保持不变。

### 修复任务执行失败如何排查

1. 查看 Manager 日志中 remediation 相关记录
2. 确认 Agent 侧 remediation 插件是否已安装且状态正常（管理界面 -> 主机详情 -> 插件列表）
3. 检查修复命令是否需要 root 权限（Agent 以 root 运行时插件也以 root 执行）
4. 查看 Agent 日志中对应任务 ID 的执行记录

### 检测规则已启用但告警为 0

可能原因及排查步骤：

1. **检查规则数据**：确认 `detection_rules` 表中有对应规则数据，且 `enabled` 字段为 true
2. **检查 CEL 引擎**：查看 Consumer 日志中 CEL 表达式引擎是否正常启动
   ```bash
   docker compose logs consumer | grep -i "cel\|detection\|rule"
   ```
3. **检查数据源**：EDR/eBPF 已内置于 agent（不再独立 sensor/tetragon plugin），确认 agent 进程含 EDR 采集器
   ```bash
   # 在 Agent 所在主机检查
   sudo systemctl status mxsec-agent
   sudo journalctl -u mxsec-agent --since=10min | grep -iE "edr|ebpf|tetragon"
   ```
4. **检查数据流转**：确认 EDR 事件已写入 Kafka，Consumer 正常消费

### 任务创建后一直 pending 不执行

可能原因及排查步骤：

1. **确认 Agent 在线**：检查主机心跳是否正常，管理界面主机状态应为"在线"
2. **检查 AgentCenter 注册**：确认 AC 已成功注册到 Manager 的服务发现（SD）
   ```bash
   docker compose logs agentcenter | grep -i "register\|sd"
   ```
3. **检查任务匹配**：确认任务的 `target_type` 和目标条件能匹配到至少一台主机
4. **检查任务下发日志**：
   ```bash
   docker compose logs manager | grep -i "task\|dispatch"
   docker compose logs agentcenter | grep -i "task"
   ```

### Kafka 消费积压如何处理

增加 Consumer 副本数（`CONSUMER_REPLICAS` 环境变量），ConsumerGroup 使用 RoundRobin 策略自动 rebalance。

排查和处理步骤：

1. **确认积压情况**：查看各 Topic 的 Consumer Lag
2. **排除下游阻塞**：检查 ClickHouse 写入是否正常
   ```bash
   docker compose logs consumer | grep -i "clickhouse\|write\|error"
   ```
3. **扩容 Consumer**：修改 `deploy/.env` 中的 `CONSUMER_REPLICAS` 值，然后重启
   ```bash
   docker compose up -d --scale consumer=3
   ```
4. **监控恢复进度**：观察 Consumer Lag 是否持续下降

## DLQ 处理

### 发现大量消息进了 DLQ

检查 `{topic}-dlq` 中的错误信息，常见原因包括：数据库连接失败、字段格式不匹配、下游服务不可用。

排查和处理步骤：

1. **查看 DLQ 消息内容**：确认错误类型和来源 Topic
   ```bash
   docker compose logs consumer | grep -i "dlq\|dead.letter"
   ```
2. **分析常见原因**：
   - 数据库连接失败：检查 MySQL / ClickHouse 连接状态
   - 字段格式不匹配：通常由 Agent 版本不一致导致，确认上报数据结构
   - 序列化错误：检查 Protobuf 定义是否与 Agent 端一致
3. **修复根因**：解决底层问题后，DLQ 中的新消息将不再增加
4. **手动重放 DLQ 消息**：DLQ 消息不会自动重放，修复问题后需手动处理
   - 编写脚本从 DLQ Topic 消费并重新投递到原 Topic
   - 或根据业务需要直接丢弃过期的 DLQ 消息

## 日志位置

| 组件 | 位置 |
|------|------|
| Manager | `docker compose logs manager` |
| AgentCenter | `docker compose logs agentcenter` |
| Consumer | `docker compose logs consumer` |
| Nginx | `docker compose logs ui` |
| MySQL | `docker compose logs mysql` |
| Agent | `/var/log/mxsec-agent/agent.log` |
| 插件 | `/var/log/mxsec-agent/<plugin-name>.log` |

## 常见错误码

| 错误 | 原因 | 处理 |
|------|------|------|
| 401 Unauthorized | Token 过期或无效 | 重新登录获取 Token |
| 403 Forbidden | 权限不足 | 检查用户角色 |
| 404 Not Found | 资源不存在或 URL 错误 | 检查 API 路径 |
| 500 Internal Error | 服务端异常 | 查看 Manager 日志 |
| 502 Bad Gateway | Nginx 无法连接后端 | 检查 Manager / AgentCenter 是否运行 |
| gRPC UNAVAILABLE | Agent 无法连接 AC | 检查网络、证书、端口 |
