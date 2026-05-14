# 插件 SDK（Go）

本目录提供 Go 语言的插件 SDK，用于开发 Matrix Cloud Security Platform 的插件。

## 功能

插件 SDK 提供了 `Client` 结构体，封装了插件与 Agent 之间的 Pipe 通信：

- `SendRecord()`: 发送数据记录到 Agent
- `ReceiveTask()`: 从 Agent 接收任务
- `SendRecordWithRetry()`: 带重试机制的发送
- `ReceiveTaskWithTimeout()`: 带超时机制的接收
- `Flush()`: 刷新缓冲区
- `Close()`: 关闭连接

## 使用示例

```go
package main

import (
    "log"
    "time"
    
    "github.com/imkerbos/mxsec-platform/api/proto/bridge"
    "github.com/imkerbos/mxsec-platform/plugins/lib/go"
)

func main() {
    // 创建客户端（自动从文件描述符 3/4 读取 Pipe）
    client, err := plugins.NewClient()
    if err != nil {
        log.Fatalf("Failed to create client: %v", err)
    }
    defer client.Close()

    // 发送数据记录
    record := &bridge.Record{
        DataType:  8000, // 基线检查结果
        Timestamp: time.Now().UnixNano(),
        Data: &bridge.Payload{
            Fields: map[string]string{
                "rule_id": "LINUX_SSH_001",
                "status":  "fail",
                "actual":  "PermitRootLogin yes",
                "expected": "PermitRootLogin no",
            },
        },
    }
    
    if err := client.SendRecord(record); err != nil {
        log.Fatalf("Failed to send record: %v", err)
    }

    // 接收任务（阻塞等待）
    task, err := client.ReceiveTask()
    if err != nil {
        log.Fatalf("Failed to receive task: %v", err)
    }
    
    log.Printf("Received task: %+v", task)
}
```

## 通信协议

插件与 Agent 通过 Pipe（文件描述符 3/4）进行通信：

- **文件描述符 3 (rx)**: Agent → 插件（接收任务）
- **文件描述符 4 (tx)**: 插件 → Agent（发送数据）

协议格式：
```
[4 字节长度（小端序）][protobuf 序列化的数据]
```

## 错误处理

SDK 提供了以下错误处理机制：

1. **重试机制**: `SendRecordWithRetry()` 支持自动重试
2. **超时机制**: `ReceiveTaskWithTimeout()` 支持超时控制
3. **消息大小限制**: 自动限制最大消息大小（10MB），防止恶意数据

## 注意事项

1. 插件必须由 Agent 启动，Agent 会自动设置文件描述符 3/4
2. 不要在插件中手动创建文件描述符 3/4
3. 确保及时调用 `Flush()` 或 `Close()` 以刷新缓冲区
4. 所有操作都是线程安全的（使用互斥锁保护）
