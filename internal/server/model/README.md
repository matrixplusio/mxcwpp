# 数据库模型说明

本目录包含所有数据库模型定义，使用 Gorm ORM。

## 模型列表

### 1. Host（主机信息）

- **表名**: `hosts`
- **主键**: `host_id` (VARCHAR(64))
- **字段**:
  - `host_id`: 主机唯一标识
  - `hostname`: 主机名
  - `os_family`: 操作系统系列（rocky、centos、debian 等）
  - `os_version`: 操作系统版本
  - `kernel_version`: 内核版本
  - `arch`: 架构（x86_64、aarch64）
  - `ipv4`: IPv4 地址列表（JSON 数组）
  - `ipv6`: IPv6 地址列表（JSON 数组）
  - `status`: 状态（online/offline）
  - `last_heartbeat`: 最后心跳时间
  - `created_at`: 创建时间
  - `updated_at`: 更新时间

### 2. Policy（策略集）

- **表名**: `policies`
- **主键**: `id` (VARCHAR(64))
- **字段**:
  - `id`: 策略唯一标识
  - `name`: 策略名称
  - `version`: 策略版本
  - `description`: 策略描述
  - `os_family`: 适用的操作系统系列（JSON 数组）
  - `os_version`: 适用的操作系统版本约束（如 ">=7"）
  - `enabled`: 是否启用
  - `created_at`: 创建时间
  - `updated_at`: 更新时间
- **关联**: 一对多关联到 `Rule`

### 3. Rule（规则）

- **表名**: `rules`
- **主键**: `rule_id` (VARCHAR(64))
- **字段**:
  - `rule_id`: 规则唯一标识
  - `policy_id`: 所属策略 ID（外键）
  - `category`: 规则类别（ssh、password、file_permission 等）
  - `title`: 规则标题
  - `description`: 规则描述
  - `severity`: 严重级别（low、medium、high、critical）
  - `check_config`: 检查配置（JSON，包含检查类型和参数）
  - `fix_config`: 修复配置（JSON，包含修复建议和命令）
  - `created_at`: 创建时间
  - `updated_at`: 更新时间
- **关联**: 多对一关联到 `Policy`

### 4. ScanResult（检测结果）

- **表名**: `scan_results`
- **主键**: `result_id` (VARCHAR(64))
- **字段**:
  - `result_id`: 结果唯一标识
  - `host_id`: 主机 ID（外键）
  - `policy_id`: 策略 ID
  - `rule_id`: 规则 ID（外键）
  - `task_id`: 任务 ID
  - `status`: 检测状态（pass/fail/error/na）
  - `severity`: 严重级别
  - `category`: 规则类别
  - `title`: 规则标题
  - `actual`: 实际值
  - `expected`: 期望值
  - `fix_suggestion`: 修复建议
  - `checked_at`: 检测时间
  - `created_at`: 创建时间
- **关联**: 多对一关联到 `Host` 和 `Rule`

### 5. ScanTask（扫描任务）

- **表名**: `scan_tasks`
- **主键**: `task_id` (VARCHAR(64))
- **字段**:
  - `task_id`: 任务唯一标识
  - `name`: 任务名称
  - `type`: 任务类型（baseline_scan）
  - `target_type`: 目标类型（all/host_ids/os_family）
  - `target_config`: 目标配置（JSON，包含主机 ID 列表或 OS 系列）
  - `policy_id`: 策略 ID
  - `rule_ids`: 规则 ID 列表（JSON 数组）
  - `status`: 任务状态（pending/running/completed/failed）
  - `created_at`: 创建时间
  - `updated_at`: 更新时间
  - `executed_at`: 执行时间

## 使用示例

```go
import (
    "github.com/imkerbos/mxsec-platform/internal/server/model"
    "gorm.io/driver/mysql"
    "gorm.io/gorm"
)

// 连接数据库
dsn := "user:password@tcp(localhost:3306)/mxsec?charset=utf8mb4&parseTime=True&loc=Local"
db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
if err != nil {
    panic(err)
}

// 自动迁移
db.AutoMigrate(&model.Host{}, &model.Policy{}, &model.Rule{}, 
               &model.ScanResult{}, &model.ScanTask{})

// 创建主机
host := &model.Host{
    HostID:        "host-001",
    Hostname:      "test-server",
    OSFamily:      "rocky",
    OSVersion:     "9.3",
    KernelVersion: "5.14.0",
    Arch:          "x86_64",
    IPv4:          model.StringArray{"192.168.1.100"},
    Status:        model.HostStatusOnline,
}
db.Create(host)

// 查询主机
var hosts []model.Host
db.Where("os_family = ?", "rocky").Find(&hosts)

// 查询策略及其规则
var policy model.Policy
db.Preload("Rules").First(&policy, "id = ?", "LINUX_SSH_BASELINE")
```

## JSON 字段说明

### StringArray

用于存储字符串数组（如 IPv4/IPv6 地址列表、OS 系列列表）。

```go
ipv4 := model.StringArray{"192.168.1.100", "10.0.0.1"}
```

### CheckConfig

检查配置，包含检查条件和规则列表：

```go
checkConfig := model.CheckConfig{
    Condition: "all", // all/any/none
    Rules: []model.CheckRule{
        {
            Type:  "file_kv",
            Param: []string{"/etc/ssh/sshd_config", "PermitRootLogin", "no"},
        },
    },
}
```

### FixConfig

修复配置，包含修复建议和命令：

```go
fixConfig := model.FixConfig{
    Suggestion: "修改配置文件",
    Command:    "sed -i 's/...' /etc/ssh/sshd_config",
}
```

### TargetConfig

目标配置，用于扫描任务：

```go
targetConfig := model.TargetConfig{
    HostIDs:  []string{"host-001", "host-002"},
    OSFamily: []string{"rocky", "centos"},
}
```

## 注意事项

1. **外键约束**: 数据库会自动创建外键约束，删除策略前需要先删除相关规则
2. **JSON 字段**: MySQL 5.7+ 和 PostgreSQL 都支持 JSON 类型
3. **时间字段**: 使用 `time.Time` 类型，Gorm 会自动处理时间戳转换
4. **索引**: 在常用查询字段上已添加索引（如 `host_id`、`rule_id`、`policy_id`）
