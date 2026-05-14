# Baseline Plugin 示例规则

本目录包含 Baseline Plugin 的示例规则文件，用于演示和测试基线检查功能。

## 规则文件列表

### 1. ssh-baseline.json
SSH 安全配置基线，包含以下规则：
- `LINUX_SSH_001`: 禁止 root 远程登录
- `LINUX_SSH_002`: 禁止空密码登录
- `LINUX_SSH_003`: SSH 端口配置检查

### 2. password-policy.json
密码策略基线，包含以下规则：
- `LINUX_PASS_001`: 密码最大有效期检查
- `LINUX_PASS_002`: 密码最小长度检查

### 3. file-permissions.json
关键文件权限基线，包含以下规则：
- `LINUX_FILE_001`: `/etc/passwd` 文件权限检查
- `LINUX_FILE_002`: `/etc/shadow` 文件权限检查
- `LINUX_FILE_003`: `/etc/ssh/sshd_config` 文件权限检查

### 4. sysctl-security.json
内核安全参数基线，包含以下规则：
- `LINUX_SYSCTL_001`: IP 转发禁用检查
- `LINUX_SYSCTL_002`: SYN Cookie 防护检查

### 5. service-status.json
系统服务状态基线，包含以下规则：
- `LINUX_SERVICE_001`: SSH 服务运行状态检查
- `LINUX_SERVICE_002`: 时间同步服务运行状态检查（chronyd 或 ntpd）

## 使用方法

### 1. 测试单个规则文件

```bash
# 使用 go run 直接运行 baseline plugin（需要先实现测试脚本）
# 或者通过 Agent 下发任务进行测试
```

### 2. 集成到 Agent

这些规则文件可以通过以下方式使用：
1. **Server 下发**：Server 端读取这些 JSON 文件，通过 gRPC 下发给 Agent
2. **本地测试**：在开发阶段，可以直接读取这些文件进行测试

### 3. 规则格式说明

每个规则文件遵循以下结构：

```json
{
  "id": "策略集ID",
  "name": "策略集名称",
  "version": "版本号",
  "description": "描述",
  "os_family": ["适用的OS系列"],
  "os_version": "版本约束（如 >=7）",
  "enabled": true,
  "rules": [
    {
      "rule_id": "规则ID",
      "category": "规则分类",
      "title": "规则标题",
      "description": "规则描述",
      "severity": "严重级别（low/medium/high/critical）",
      "check": {
        "condition": "条件组合（all/any/none）",
        "rules": [
          {
            "type": "检查器类型",
            "param": ["参数列表"]
          }
        ]
      },
      "fix": {
        "suggestion": "修复建议",
        "command": "修复命令（可选）"
      }
    }
  ]
}
```

## 检查器类型

示例规则使用了以下检查器类型：

- `file_exists`: 检查文件是否存在
- `file_kv`: 检查配置文件键值对
- `file_permission`: 检查文件权限
- `file_line_match`: 检查文件行匹配（支持正则）
- `sysctl`: 检查内核参数
- `service_status`: 检查服务状态
- `command_exec`: 执行命令检查（示例规则中未使用，但测试中已覆盖）

## 注意事项

1. **OS 匹配**：规则文件中的 `os_family` 和 `os_version` 用于匹配目标主机，只有匹配的主机才会执行这些规则
2. **条件组合**：`check.condition` 支持 `all`（全部通过）、`any`（任一通过）、`none`（全部不通过）
3. **正则匹配**：`file_kv`、`file_line_match`、`command_exec`、`sysctl` 的期望值支持正则表达式
4. **文件路径**：示例规则中的文件路径（如 `/etc/ssh/sshd_config`）是 Linux 标准路径，在不同发行版中可能略有差异

## 扩展规则

可以根据实际需求创建新的规则文件，参考现有示例规则的格式和结构。
