# 开发指南

本文档讲**怎么在本地把项目跑起来、怎么改各个模块**。

协作规则（分支、提交格式、PR 流程、发布约束、自动门禁）见根目录的
[CONTRIBUTING.md](../CONTRIBUTING.md)，那份是提 PR 前必读的，此处不重复。

## 开发环境

### 前置要求

- Go >= 1.25
- Node.js >= 18（前端开发）
- Docker >= 20.10, Docker Compose >= 2.0
- protoc（Protobuf 编译器）
- Make

### 环境搭建

```bash
# 克隆仓库
git clone https://github.com/matrixplusio/mxcwpp.git
cd mxcwpp

# 启动开发环境（带热更新）
make dev-docker-up

# 查看日志
make dev-docker-logs
```

开发环境访问地址：

| 服务 | 地址 |
|------|------|
| Manager API | http://localhost:8080 |
| UI | http://localhost:3000 |
| MySQL | localhost:3306 |

### 常用命令

```bash
make proto           # 生成 Protobuf 代码
make build-server    # 构建 Server（manager + agentcenter）
make build-consumer  # 构建 Consumer
make package-agent   # 构建 Agent（打包为 RPM/DEB）
make test            # 运行测试
make fmt             # 格式化代码
make lint            # 代码检查
```

## 数据库迁移指南

项目使用 Gorm AutoMigrate 管理数据库表结构，模型变更会在服务启动时自动同步。

### 新增字段

在对应的 model 结构体中添加字段即可。Gorm 在启动时会自动执行 `ALTER TABLE` 添加新列。

```go
// 示例：在 model.Host 中新增字段
type Host struct {
    // ... 已有字段
    Region string `gorm:"type:varchar(64);default:''" json:"region"` // 新增字段，带默认值
}
```

**注意**：新字段必须设置默认值（通过 Gorm tag 的 `default` 或使用指针类型），避免 `NOT NULL` 无默认值导致已有数据迁移失败。

### 删除字段

Gorm AutoMigrate 不会自动删除已有列。如需删除字段，需手动执行 SQL：

```sql
ALTER TABLE hosts DROP COLUMN region;
```

删除前确认该字段在代码中已无引用。

### 初始化数据

系统启动时需要预置的数据（如默认用户、默认策略等），在 `internal/server/migration/init_data.go` 的 `InitDefaultData` 函数中添加。该函数在每次启动时执行，需自行处理幂等逻辑（已存在则跳过）。

### 向后兼容原则

- 新增字段必须有默认值
- 不要修改已有字段的类型或约束，除非确认兼容
- 表结构变更需考虑回滚方案

## 前后端联调流程

### 启动开发环境

```bash
make dev-docker-up
```

该命令启动完整开发环境，包含 Manager、AgentCenter、Consumer、UI 前端及 MySQL / Redis / Kafka / ClickHouse 等基础设施服务。

### 架构说明

```
浏览器 --> Nginx(:3000) --> Vite Dev Server (UI)
                |
                +--> /api/* 反向代理 --> Manager(:8080)
```

- UI 通过 Nginx 反向代理将 `/api/*` 请求转发到 Manager:8080
- 前端修改实时热更新（Vite HMR），保存文件后浏览器自动刷新
- 后端修改通过 Air 自动重编译，代码变更后 Manager 自动重启

### 联调要点

- 前端 API 定义在 `web/src/lib/api/` 目录，新增接口时先定义类型再实现调用
- 后端接口定义后，前端可通过浏览器开发者工具的 Network 面板查看实际请求和响应
- 如遇跨域问题，检查 Nginx 配置（`deploy/` 目录下的 Docker Compose 配置）

## 插件开发指引

### 插件架构

插件是独立的可执行文件，由 Agent 以子进程方式启动。插件与 Agent 之间通过 Pipe（文件描述符 3/4）进行双向通信，使用 Protobuf 序列化消息。

### 目录结构

```
plugins/<plugin-name>/
├── main.go          # 入口
└── engine/          # 核心逻辑（部分插件有）
```

所有插件共用项目根目录的 `go.mod`，不是独立 module。当前已有 5 个插件：baseline、collector、fim、scanner、remediation。EDR/eBPF 运行时检测已内置于 agent，不再作为独立 plugin。

### 插件 SDK

插件 SDK 位于 `plugins/lib/go/`，提供 `Client` 类封装了与 Agent 的通信细节：

```go
import plugins "github.com/matrixplusio/mxcwpp/plugins/lib/go"

client, err := plugins.NewClient()
// 使用 client 接收任务、上报数据
```

### DataType 编号约定

插件上报数据时需指定 DataType 编号，各模块的编号范围如下：

| 编号范围 | 模块 | 说明 |
|----------|------|------|
| 1000-1001 | 心跳 | Agent 心跳与插件状态 |
| 3000-3002 | eBPF | 内核级事件采集 |
| 5050-5060 | 资产采集 | 主机资产信息上报 |
| 6001-6002 | FIM | 文件完整性监控 |
| 7000-7004 | Scanner | 病毒扫描结果 |
| 8000-8004 | 基线检查 | 安全基线合规检测 |
| 9000-9001 | Remediation | 漏洞修复任务与结果 |
| 9100 | 依赖安装 | 依赖安装结果（如 Tetragon） |
| 9999 | 命令回包 | Agent 命令执行结果 |

新增插件时请在上述范围之外分配编号，并在团队内协调避免冲突。

### 构建与打包

```bash
# 构建所有插件（当前架构）
make package-plugins

# 构建所有插件（amd64 + arm64）
make package-plugins-all
```

构建产物输出到 `dist/plugins/` 目录。

## 测试要求

- 核心路径覆盖率 >= 85%，整体 >= 70%
- Bug 修复必须附带回归测试
- 集成测试位于 `tests/` 目录

运行测试：

```bash
# 单元测试
go test ./... -v

# 带覆盖率
go test ./... -cover

# 指定包
go test ./internal/server/manager/... -v
```

## 沟通渠道

- **Issue**: Bug 报告和功能建议
- **Discussion**: 技术讨论和问题咨询
- **PR**: 代码贡献

感谢每一位贡献者。
