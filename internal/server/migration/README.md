# 数据库迁移说明

本目录提供数据库迁移和初始化功能。

## 功能

### 1. 数据库迁移 (`migrate.go`)

- `Migrate()`: 执行自动迁移，创建所有表结构
- `Rollback()`: 回滚数据库（删除所有表，谨慎使用）

### 2. 初始化数据 (`init_data.go`)

- `InitDefaultData()`: 从策略文件目录加载默认策略和规则，保存到数据库

## 使用方法

### 在代码中使用

```go
import (
    "github.com/imkerbos/mxsec-platform/internal/server/migration"
    "github.com/imkerbos/mxsec-platform/internal/server/model"
    "gorm.io/driver/mysql"
    "gorm.io/gorm"
    "go.uber.org/zap"
)

// 连接数据库
db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
if err != nil {
    panic(err)
}

logger := zap.NewExample()

// 执行迁移
if err := migration.Migrate(db, logger); err != nil {
    panic(err)
}

// 初始化默认数据
policyDir := "plugins/baseline/config/examples"
if err := migration.InitDefaultData(db, logger, policyDir); err != nil {
    panic(err)
}
```

### 命令行工具（可选）

可以创建一个命令行工具来执行迁移：

```go
// cmd/tools/migrate/main.go
package main

import (
    "flag"
    "fmt"
    "os"
    
    "github.com/imkerbos/mxsec-platform/internal/server/migration"
    // ... 其他导入
)

func main() {
    action := flag.String("action", "migrate", "操作: migrate, rollback, init")
    dsn := flag.String("dsn", "", "数据库连接字符串")
    policyDir := flag.String("policy-dir", "plugins/baseline/config/examples", "策略文件目录")
    flag.Parse()
    
    // ... 连接数据库和执行操作
}
```

## 注意事项

1. **迁移顺序**: 迁移会自动处理外键依赖关系
2. **初始化数据**: `InitDefaultData` 会检查数据库中是否已有数据，如果已有数据则跳过初始化
3. **策略文件格式**: 策略文件必须是 JSON 格式，符合 `plugins/baseline/engine/models.go` 中定义的 `Policy` 结构

## 数据库表结构

- `hosts`: 主机信息
- `policies`: 策略集
- `rules`: 规则
- `scan_results`: 检测结果
- `scan_tasks`: 扫描任务

详细字段定义请参考 `internal/server/model/` 目录下的模型文件。
