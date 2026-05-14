# 资产数据集成说明

本文档说明如何在 AgentCenter 的 Transfer 服务中集成资产数据处理。

## 1. 概述

资产数据通过 Collector Plugin 采集，通过 Agent 透传到 Server。Server 端的 Transfer 服务需要：
1. 接收资产数据（DataType=5050-5064）
2. 解析数据并存储到数据库

## 2. 集成步骤

### 2.1 在 Transfer 服务中初始化 AssetService

在 `internal/server/agentcenter/transfer/service.go` 的 `NewService` 函数中：

```go
func NewService(db *gorm.DB, logger *zap.Logger, cfg *config.Config) *Service {
    // ... 现有代码 ...
    
    // 初始化资产服务
    assetService := service.NewAssetService(db, logger)
    
    return &Service{
        // ... 现有字段 ...
        assetService: assetService,
    }
}
```

### 2.2 在 handleRecord 方法中添加资产数据处理

在 `internal/server/agentcenter/transfer/service.go` 的 `handleRecord` 方法中：

```go
func (s *Service) handleRecord(hostID string, record *grpcProto.EncodedRecord) error {
    dataType := record.DataType
    
    switch dataType {
    case 1000: // 心跳数据
        return s.handleHeartbeat(hostID, record.Data)
    case 8000: // 基线检查结果
        return s.handleBaselineResult(hostID, record.Data)
    case 5050, 5051, 5052: // 资产数据（进程、端口、账户）
        return s.assetService.HandleAssetData(hostID, dataType, record.Data)
    default:
        s.logger.Warn("unknown data type", zap.Int32("data_type", dataType))
        return nil
    }
}
```

## 3. 数据流程

1. **Collector Plugin** 采集资产数据（进程、端口、账户）
2. **Collector Plugin** 将数据序列化为 JSON，封装为 `bridge.Record`
3. **Agent** 将 `bridge.Record` 序列化为 protobuf，封装为 `EncodedRecord`
4. **Agent** 通过 gRPC 发送 `PackagedData`（包含 `EncodedRecord`）
5. **Transfer 服务** 接收数据，根据 `data_type` 路由到 `AssetService`
6. **AssetService** 解析数据并存储到数据库（processes、ports、asset_users 表）

## 4. 数据类型映射

- `5050`: 进程数据 → `processes` 表
- `5051`: 端口数据 → `ports` 表
- `5052`: 账户数据 → `asset_users` 表

## 5. 数据更新策略

当前实现采用**全量替换**策略：
1. 删除该主机的旧数据
2. 插入新数据

这样可以确保数据库中的数据与 Agent 端的数据一致。

## 6. 注意事项

1. 资产数据的 `host_id` 由 Transfer 服务填充（从 `PackagedData.AgentId` 获取）
2. 资产数据的 `collected_at` 字段由 Collector Plugin 填充
3. 如果数据解析失败，会记录错误日志，但不会中断其他数据的处理
