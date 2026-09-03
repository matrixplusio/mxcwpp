# Protobuf 定义

本目录包含项目的 Protobuf 定义文件。

## 文件说明

- `bridge.proto`: 定义插件与 Agent 之间的通信协议
  - `Record`: 插件发送给 Agent 的数据记录
  - `Task`: Agent 发送给插件的任务

- `grpc.proto`: 定义 Agent 与 Server 之间的通信协议
  - `PackagedData`: Agent 发送给 Server 的数据包
  - `Command`: Server 发送给 Agent 的命令
  - `Transfer`: gRPC 双向流服务

## 生成 Go 代码

### 前置要求

1. 安装 `protoc`（Protocol Buffers 编译器）：
   ```bash
   # macOS
   brew install protobuf
   
   # Ubuntu/Debian
   sudo apt-get install protobuf-compiler
   
   # 或从源码编译
   # https://grpc.io/docs/protoc-installation/
   ```

2. 安装 Go 插件：
   ```bash
   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
   go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
   ```

### 生成代码

运行生成脚本：
```bash
./scripts/generate-proto.sh
```

或手动执行：
```bash
# 生成 bridge.proto
protoc --go_out=api/proto --go_opt=paths=source_relative \
  -I=api/proto api/proto/bridge.proto

# 生成 grpc.proto
protoc --go_out=api/proto --go_opt=paths=source_relative \
  --go-grpc_out=api/proto --go-grpc_opt=paths=source_relative \
  -I=api/proto api/proto/grpc.proto
```

## 数据类型说明

### 数据类型（data_type）常量

- `1000`: Agent 心跳
- `1001`: 插件状态
- `8000`: 基线检查结果
- `5050`: 进程数据
- `5051`: 端口数据
- `5052`: 账户数据
- `5053`: 软件包数据
- `5054`: 容器数据
- `5055`: 应用数据
- `5056`: 网卡数据
- `5057`: 磁盘数据
- `5058`: 内核模块数据
- `5059`: 系统服务数据
- `5060`: 定时任务数据

（更多数据类型定义在后续开发中补充）
