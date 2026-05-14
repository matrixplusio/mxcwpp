# Collector Plugin（资产采集插件）

> Collector Plugin 是 Matrix Cloud Security Platform 的资产采集插件，负责周期性采集主机资产信息并上报到 Server。

---

## 功能概述

Collector Plugin 作为 Agent 的子进程运行，通过 Pipe + Protobuf 与 Agent 通信，负责采集以下类型的资产信息：

### 基础采集器（Phase 2.1）

- **进程采集器（ProcessHandler）**
  - 采集所有进程信息（PID、PPID、命令行、可执行文件路径等）
  - 计算可执行文件 MD5 哈希值
  - 检测容器关联（Docker、containerd）
  - 采集间隔：1 小时

- **端口采集器（PortHandler）**
  - 采集 TCP/UDP 监听端口
  - 关联进程信息（通过 inode）
  - 检测容器关联
  - 采集间隔：1 小时

- **账户采集器（UserHandler）**
  - 采集系统账户信息（用户名、UID、GID、主目录、shell 等）
  - 检测密码策略（基于 /etc/shadow）
  - 采集间隔：6 小时

### 完整采集器（Phase 2.3，待实现）

- 软件包采集器（SoftwareHandler）
- 容器采集器（ContainerHandler）
- 应用采集器（AppHandler）
- 硬件采集器（NetInterfaceHandler、VolumeHandler）
- 内核模块采集器（KmodHandler）
- 系统服务采集器（ServiceHandler）
- 定时任务采集器（CronHandler）

---

## 项目结构

```
plugins/collector/
├── main.go                    # 插件入口
├── engine/                    # 采集引擎
│   ├── engine.go             # 引擎核心（定时采集、任务触发）
│   ├── models.go             # 数据模型（Asset 结构）
│   └── handlers/             # 采集器实现
│       ├── process.go        # 进程采集器
│       ├── port.go           # 端口采集器
│       └── user.go           # 账户采集器
└── README.md                 # 本文档
```

---

## 工作原理

### 1. 插件启动

1. 初始化插件客户端（通过 Pipe 与 Agent 通信）
2. 创建采集引擎
3. 注册采集器（进程、端口、账户）
4. 启动定时采集（每个采集器独立 goroutine）
5. 启动任务接收循环（支持 Server 触发的采集任务）

### 2. 定时采集

每个采集器按照配置的间隔（如进程采集器 1 小时）自动执行采集：

```go
// 注册采集器
collectEngine.RegisterHandler("process", time.Hour, &handlers.ProcessHandler{Logger: logger})
```

### 3. 任务触发采集

Server 可以通过 Agent 下发采集任务，触发特定类型的采集：

```json
{
  "type": "process"
}
```

### 4. 数据上报

采集完成后，数据通过 `bridge.Record` 上报到 Agent，然后由 Agent 转发到 Server：

```go
record := &bridge.Record{
    DataType:  5050, // 进程数据类型
    Timestamp: time.Now().UnixNano(),
    Data: &bridge.Payload{
        Fields: map[string]string{
            "data": string(jsonData),
        },
    },
}
client.SendRecord(record)
```

---

## 数据类型（data_type）

| data_type | 类型 | 说明 |
|-----------|------|------|
| 5050 | 进程数据 | ProcessAsset |
| 5051 | 端口数据 | PortAsset |
| 5052 | 账户数据 | UserAsset |
| 5053 | 软件包数据 | SoftwareAsset（待实现） |
| 5054 | 容器数据 | ContainerAsset（待实现） |
| 5055 | 应用数据 | AppAsset（待实现） |
| 5056 | 网卡数据 | NetInterfaceAsset（待实现） |
| 5057 | 磁盘数据 | VolumeAsset（待实现） |
| 5058 | 内核模块数据 | KmodAsset（待实现） |
| 5059 | 系统服务数据 | ServiceAsset（待实现） |
| 5060 | 定时任务数据 | CronAsset（待实现） |

---

## 数据模型

### ProcessAsset（进程资产）

```go
type ProcessAsset struct {
    Asset
    PID         string `json:"pid"`
    PPID        string `json:"ppid"`
    Cmdline     string `json:"cmdline"`
    Exe         string `json:"exe"`
    ExeHash     string `json:"exe_hash,omitempty"` // MD5 哈希值
    ContainerID string `json:"container_id,omitempty"`
    UID         string `json:"uid"`
    GID         string `json:"gid"`
    Username    string `json:"username,omitempty"`
    Groupname   string `json:"groupname,omitempty"`
}
```

### PortAsset（端口资产）

```go
type PortAsset struct {
    Asset
    Protocol    string `json:"protocol"`     // tcp/udp
    Port        int    `json:"port"`         // 端口号
    State       string `json:"state"`        // LISTEN/ESTABLISHED 等
    PID         string `json:"pid,omitempty"`
    ProcessName string `json:"process_name,omitempty"`
    ContainerID string `json:"container_id,omitempty"`
}
```

### UserAsset（账户资产）

```go
type UserAsset struct {
    Asset
    Username    string `json:"username"`
    UID         string `json:"uid"`
    GID         string `json:"gid"`
    Groupname   string `json:"groupname,omitempty"`
    HomeDir     string `json:"home_dir"`
    Shell       string `json:"shell"`
    Comment     string `json:"comment,omitempty"`
    HasPassword bool   `json:"has_password"` // 是否有密码（基于 shadow 文件）
}
```

---

## 实现细节

### 进程采集

- 遍历 `/proc` 目录，读取所有数字目录（PID）
- 读取 `/proc/{pid}/cmdline` 获取命令行
- 读取 `/proc/{pid}/exe` 获取可执行文件路径
- 读取 `/proc/{pid}/stat` 获取 PPID
- 读取 `/proc/{pid}/status` 获取 UID/GID
- 读取 `/proc/{pid}/cgroup` 检测容器关联
- 计算可执行文件 MD5（如果文件存在）

### 端口采集

- 读取 `/proc/net/tcp` 和 `/proc/net/udp` 文件
- 解析端口信息（协议、端口、状态、inode）
- 通过 inode 关联进程（遍历 `/proc/{pid}/fd/`）
- 检测容器关联（通过进程的 cgroup）

### 账户采集

- 读取 `/etc/passwd` 解析用户列表
- 读取 `/etc/shadow`（如果可读）判断是否有密码
- 读取 `/etc/group` 解析组信息
- 通过 `user.LookupId` 和 `user.LookupGroupId` 解析用户名和组名

---

## 编译和运行

### 编译

```bash
cd plugins/collector
go build -o mxsec-collector .
```

### 运行

Collector Plugin 由 Agent 自动启动，不需要手动运行。Agent 会：
1. 下载插件（如果不存在）
2. 验证插件签名（SHA256）
3. 启动插件进程（通过 Pipe 通信）

---

## 扩展采集器

要实现新的采集器，需要：

1. **实现 Handler 接口**：

```go
type Handler interface {
    Collect(ctx context.Context) ([]interface{}, error)
}
```

2. **定义资产数据结构**（在 `models.go` 中）：

```go
type YourAsset struct {
    Asset
    // 你的字段...
}
```

3. **实现采集逻辑**（在 `handlers/your_handler.go` 中）：

```go
type YourHandler struct {
    Logger *zap.Logger
}

func (h *YourHandler) Collect(ctx context.Context) ([]interface{}, error) {
    // 实现采集逻辑
    return assets, nil
}
```

4. **注册采集器**（在 `main.go` 中）：

```go
collectEngine.RegisterHandler("your_type", interval, &handlers.YourHandler{Logger: logger})
```

5. **添加 data_type 映射**（在 `models.go` 的 `GetDataType` 函数中）：

```go
case "your_type":
    return 50XX
```

---

## 注意事项

1. **性能考虑**：
   - 采集器应该避免频繁采集，使用合理的间隔
   - 大量数据采集时应该分批上报

2. **错误处理**：
   - 采集失败时应该记录日志，但不应该中断整个插件
   - 单个资产采集失败不应该影响其他资产

3. **容器检测**：
   - 容器检测基于 cgroup 文件，支持 Docker 和 containerd
   - 如果进程不在容器中，`container_id` 为空

4. **权限要求**：
   - 读取 `/proc` 目录需要 root 权限
   - 读取 `/etc/shadow` 需要 root 权限（用于判断密码）

---

## 参考文档

- [插件开发指南](../../docs/development/plugin-development.md)
- [Agent 架构设计](../../docs/design/agent-architecture.md)
- [Phase 2 开发计划](../../docs/PHASE2_PLAN.md)
