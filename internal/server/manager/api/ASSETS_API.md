# 资产数据 API 集成说明

本文档说明如何在 Manager 中注册资产数据查询 API。

## 1. 概述

资产数据 API 提供以下接口：
- `GET /api/v1/assets/processes` - 获取进程列表
- `GET /api/v1/assets/ports` - 获取端口列表
- `GET /api/v1/assets/users` - 获取账户列表

## 2. 集成步骤

### 2.1 在 Manager 主程序中注册资产 API

在 `cmd/server/manager/main.go` 或路由配置文件中：

```go
import (
    "github.com/imkerbos/mxsec-platform/internal/server/manager/api"
)

// 在路由设置中
func setupRoutes(router *gin.Engine, db *gorm.DB, logger *zap.Logger) {
    apiV1 := router.Group("/api/v1")
    
    // ... 现有路由 ...
    
    // 注册资产 API
    assetsHandler := api.NewAssetsHandler(db, logger)
    apiV1.GET("/assets/processes", assetsHandler.ListProcesses)
    apiV1.GET("/assets/ports", assetsHandler.ListPorts)
    apiV1.GET("/assets/users", assetsHandler.ListUsers)
}
```

### 2.2 在测试路由中添加资产 API

在 `internal/server/manager/api/integration_test.go` 的 `setupTestRouter` 函数中：

```go
func setupTestRouter(db *gorm.DB) *gin.Engine {
    // ... 现有代码 ...
    
    // 注册资产 API
    assetsHandler := NewAssetsHandler(db, logger)
    apiV1.GET("/assets/processes", assetsHandler.ListProcesses)
    apiV1.GET("/assets/ports", assetsHandler.ListPorts)
    apiV1.GET("/assets/users", assetsHandler.ListUsers)
    
    return router
}
```

## 3. API 接口说明

### 3.1 获取进程列表

**请求**：
```
GET /api/v1/assets/processes?host_id={host_id}&page=1&page_size=20
```

**查询参数**：
- `host_id`（可选）：主机 ID，过滤特定主机的进程
- `page`（可选）：页码，默认 1
- `page_size`（可选）：每页数量，默认 20

**响应**：
```json
{
  "code": 0,
  "data": {
    "total": 100,
    "items": [
      {
        "id": "host-001-1234",
        "host_id": "host-001",
        "pid": "1234",
        "ppid": "1",
        "cmdline": "/usr/bin/python3 app.py",
        "exe": "/usr/bin/python3",
        "exe_hash": "abc123...",
        "container_id": "",
        "uid": "1000",
        "gid": "1000",
        "username": "user",
        "groupname": "user",
        "collected_at": "2025-12-09T12:00:00Z"
      }
    ]
  }
}
```

### 3.2 获取端口列表

**请求**：
```
GET /api/v1/assets/ports?host_id={host_id}&protocol=tcp&page=1&page_size=20
```

**查询参数**：
- `host_id`（可选）：主机 ID
- `protocol`（可选）：协议类型（tcp/udp）
- `page`（可选）：页码，默认 1
- `page_size`（可选）：每页数量，默认 20

**响应**：
```json
{
  "code": 0,
  "data": {
    "total": 50,
    "items": [
      {
        "id": "host-001-tcp-8080",
        "host_id": "host-001",
        "protocol": "tcp",
        "port": 8080,
        "state": "LISTEN",
        "pid": "1234",
        "process_name": "python3",
        "container_id": "",
        "collected_at": "2025-12-09T12:00:00Z"
      }
    ]
  }
}
```

### 3.3 获取账户列表

**请求**：
```
GET /api/v1/assets/users?host_id={host_id}&page=1&page_size=20
```

**查询参数**：
- `host_id`（可选）：主机 ID
- `page`（可选）：页码，默认 1
- `page_size`（可选）：每页数量，默认 20

**响应**：
```json
{
  "code": 0,
  "data": {
    "total": 30,
    "items": [
      {
        "id": "host-001-root",
        "host_id": "host-001",
        "username": "root",
        "uid": "0",
        "gid": "0",
        "groupname": "root",
        "home_dir": "/root",
        "shell": "/bin/bash",
        "comment": "",
        "has_password": true,
        "collected_at": "2025-12-09T12:00:00Z"
      }
    ]
  }
}
```

## 4. 注意事项

1. 所有 API 都支持分页查询
2. 所有 API 都支持按 `host_id` 过滤
3. 端口 API 还支持按 `protocol` 过滤
4. 数据按 `collected_at` 降序排列（最新的在前）
