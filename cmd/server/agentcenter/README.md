# AgentCenter

AgentCenter 是 Matrix Cloud Security Platform 的 gRPC 服务器，负责与 Agent 进行双向流通信。

## 功能

- **接收 Agent 数据**：
  - 心跳数据（更新主机状态）
  - 基线检查结果（存储到数据库）
  - 资产数据（Phase 2）

- **下发任务和配置**：
  - 扫描任务
  - 插件配置
  - Agent 配置

- **连接管理**：
  - Agent 连接状态管理
  - 自动更新主机在线/离线状态

## 配置

配置文件路径：`configs/server.yaml`

主要配置项：

```yaml
server:
  grpc:
    host: "0.0.0.0"
    port: 6751

database:
  type: "mysql"
  mysql:
    host: "localhost"
    port: 3306
    user: "mxsec_user"
    password: "mxsec_password"
    database: "mxsec"

mtls:
  ca_cert: "certs/ca.crt"
  server_cert: "certs/server.crt"
  server_key: "certs/server.key"
```

## 运行

### 开发环境

```bash
# 1. 复制配置文件
cp configs/server.yaml.example configs/server.yaml

# 2. 修改配置（数据库连接、证书路径等）

# 3. 运行
go run ./cmd/server/agentcenter -config configs/server.yaml
```

### 生产环境

```bash
# 1. 构建
go build -o mxsec-agentcenter ./cmd/server/agentcenter

# 2. 运行
./mxsec-agentcenter -config /etc/mxsec-server/server.yaml
```

## 数据库

AgentCenter 会自动执行数据库迁移，创建以下表：

- `hosts`：主机信息
- `policies`：策略集
- `rules`：规则
- `scan_results`：检测结果
- `scan_tasks`：扫描任务

## mTLS

AgentCenter 支持 mTLS 双向认证：

1. **开发环境**：可以不配置证书（使用不安全连接）
2. **生产环境**：必须配置证书（CA、Server 证书和私钥）

证书生成脚本（待实现）：`scripts/generate-certs.sh`

## 日志

日志文件：`/var/log/mxsec-server/server.log`

- 格式：JSON（结构化日志）
- 轮转：按天轮转（`server.log.YYYY-MM-DD`）
- 保留：30天

## API

### Transfer 服务（gRPC）

```protobuf
service Transfer {
  rpc Transfer(stream PackagedData) returns (stream Command) {}
}
```

### 数据类型

- `1000`：Agent 心跳
- `8000`：基线检查结果
- `5050-5060`：资产数据（Phase 2）

## 架构

```
AgentCenter
├── main.go              # 主程序入口
├── transfer/
│   └── service.go      # Transfer 服务实现
└── service/
    └── policy.go        # 策略和规则管理服务
```

## 开发

### 添加新的数据类型处理

在 `transfer/service.go` 的 `handleEncodedRecord` 方法中添加新的 case：

```go
case 9000: // 新的数据类型
    return s.handleNewDataType(ctx, record, conn)
```

### 添加新的服务方法

在 `transfer/service.go` 中添加新的方法：

```go
func (s *Service) handleNewDataType(ctx context.Context, record *grpc.EncodedRecord, conn *Connection) error {
    // 处理逻辑
}
```

## 故障排查

### Agent 无法连接

1. 检查防火墙端口（默认 6751）
2. 检查 mTLS 证书配置
3. 查看日志：`tail -f /var/log/mxsec-server/server.log`

### 数据库连接失败

1. 检查数据库配置（host、port、user、password）
2. 检查数据库是否运行
3. 检查数据库用户权限

### 心跳数据未更新

1. 检查 Agent 是否正常连接
2. 查看日志中的错误信息
3. 检查数据库连接状态
