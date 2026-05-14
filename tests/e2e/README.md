# E2E 测试说明

## 概述

E2E（端到端）测试用于验证 Agent + Server + Plugin 的完整流程，包括：
- Agent 连接 Server
- 心跳上报
- 任务下发和执行
- 检测结果上报和存储
- 基线得分计算
- 资产采集流程（进程、端口、账户）

## 前置要求

1. **MySQL 数据库**：测试需要使用 MySQL 数据库（项目标准配置）
2. **数据库权限**：测试用户需要有创建表、插入、更新、删除数据的权限

## 配置测试数据库

测试通过环境变量配置数据库连接信息：

```bash
# 数据库主机（默认：127.0.0.1）
export TEST_DB_HOST=127.0.0.1

# 数据库端口（默认：3306）
export TEST_DB_PORT=3306

# 数据库用户（默认：root）
export TEST_DB_USER=root

# 数据库密码（默认：123456）
export TEST_DB_PASSWORD=123456

# 数据库名称（默认：mxsec_test）
export TEST_DB_NAME=mxsec_test
```

## 运行测试

### 运行所有 E2E 测试

```bash
go test -tags=e2e ./tests/e2e/... -v
```

### 运行特定测试

```bash
# 运行 Agent + Server + Plugin 完整流程测试
go test -tags=e2e ./tests/e2e/... -v -run TestAgentServerPluginE2E

# 运行 Baseline Plugin 测试
go test -tags=e2e ./tests/e2e/... -v -run TestBaselinePluginE2E

# 运行资产采集端到端测试
go test -tags=e2e ./tests/e2e/... -v -run TestAssetCollectionE2E
```

## 测试数据库管理

### 创建测试数据库

```sql
CREATE DATABASE IF NOT EXISTS mxsec_test CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 清理测试数据（可选）

测试运行后，如果需要清理测试数据：

```sql
USE mxsec_test;
TRUNCATE TABLE scan_results;
TRUNCATE TABLE scan_tasks;
TRUNCATE TABLE rules;
TRUNCATE TABLE policies;
TRUNCATE TABLE hosts;
```

## 注意事项

1. **测试数据库隔离**：建议使用独立的测试数据库（如 `mxsec_test`），避免影响开发/生产数据
2. **数据清理**：测试会在数据库中创建测试数据，测试完成后不会自动清理（便于调试）
3. **并发测试**：如果多个测试同时运行，确保使用不同的数据库或表前缀

## 故障排查

### 连接数据库失败

```
连接测试数据库失败: dial tcp 127.0.0.1:3306: connect: connection refused
```

**解决方案**：
- 确保 MySQL 服务已启动
- 检查 `TEST_DB_HOST` 和 `TEST_DB_PORT` 环境变量
- 检查 MySQL 用户权限

### 权限不足

```
Error 1044: Access denied for user 'xxx'@'localhost' to database 'mxsec_test'
```

**解决方案**：
- 确保测试用户有创建数据库的权限
- 或手动创建测试数据库后，确保用户有访问权限

### 表已存在错误

```
Error 1050: Table 'xxx' already exists
```

**解决方案**：
- 删除测试数据库并重新创建
- 或修改测试代码，使用 `DROP TABLE IF EXISTS` 清理旧表
