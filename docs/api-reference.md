# API 参考文档

> 最后更新：2026-06-09 | 适用版本：v2.x

## 概览

- **Base URL**:
  - `/api/v1` — v1 业务 API（向后兼容）
  - `/api/v2` — v2 多租户 / 配置中心 / mode / MSSP / SOAR 等新功能
- **认证方式**: JWT Bearer Token（公开接口除外）
- **请求头**: `Authorization: Bearer <token>`，`Content-Type: application/json`
- **OpenAPI 规范**: 见 [`docs/openapi/openapi.yaml`](openapi/openapi.yaml)（包含 v1+v2 全部端点的标准定义，是本文档的权威来源）

**统一响应格式**：

```json
{
  "code": 0,
  "message": "success",
  "data": {}
}
```

**分页参数**（适用于列表接口）：`page`（页码，默认 1）、`page_size`（每页数量，默认 20）

---

## 公开接口（无需认证）

### 健康与监控

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查（Docker healthcheck 用） |
| GET | `/api/v1/health` | API 健康检查（含版本信息、组件状态） |
| GET | `/metrics` | Prometheus 指标 |

### Agent 与插件下载

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/agent/install.sh` | Agent 安装脚本 |
| GET | `/agent/uninstall.sh` | Agent 卸载脚本 |
| GET | `/api/v1/plugins/download/:name` | 下载插件包 |
| GET | `/api/v1/agent/download/:pkg_type/:arch` | 下载 Agent 包 |
| GET | `/api/v1/agent/update-check` | Agent 更新检查 |
| GET | `/api/v1/dependency/download/:name` | 下载依赖包 |

### Kubernetes 审计

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/kube/audit-webhook/:cluster_token` | K8s 审计 Webhook 回调 |

### AgentCenter 内部接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/internal/ac/register` | AC 注册 |
| POST | `/api/v1/internal/ac/heartbeat` | AC 心跳 |
| DELETE | `/api/v1/internal/ac/deregister` | AC 注销 |

### 站点配置（公开）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/system-config/site` | 获取站点配置 |

---

## 认证

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/auth/login` | 用户登录 |
| POST | `/api/v1/auth/logout` | 用户登出 |
| GET | `/api/v1/auth/me` | 获取当前用户信息 |
| POST | `/api/v1/auth/change-password` | 修改密码（需认证） |

**登录示例**：

请求：
```json
{"username": "admin", "password": "admin123"}
```

响应：
```json
{"code": 0, "data": {"token": "eyJhbG...", "user": {"username": "admin", "role": "admin"}}}
```

---

## 服务发现

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/discovery/agentcenter` | 获取健康的 AC 实例列表 |

---

## Dashboard

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/dashboard/stats` | 统计概览（主机数、通过率、风险数等） |

---

## 主机管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/hosts` | 主机列表 |
| GET | `/api/v1/hosts/status-distribution` | 主机状态分布 |
| GET | `/api/v1/hosts/risk-distribution` | 主机风险分布 |
| POST | `/api/v1/hosts/restart-agent` | 重启 Agent |
| GET | `/api/v1/hosts/restart-records` | Agent 重启记录 |
| GET | `/api/v1/hosts/:host_id` | 主机详情 |
| GET | `/api/v1/hosts/:host_id/metrics` | 主机监控指标 |
| GET | `/api/v1/hosts/:host_id/risk-statistics` | 主机风险统计 |
| GET | `/api/v1/hosts/:host_id/plugins` | 主机插件列表 |
| PUT | `/api/v1/hosts/:host_id/tags` | 更新主机标签 |
| PUT | `/api/v1/hosts/:host_id/business-line` | 更新主机业务线 |
| DELETE | `/api/v1/hosts/:host_id` | 删除主机 |
| POST | `/api/v1/hosts/batch-delete` | 批量删除主机（上限 100，支持 force 参数） |
| POST | `/api/v1/hosts/batch-update-tags` | 批量更新标签（append/replace 模式，上限 100） |
| POST | `/api/v1/hosts/batch-update-business-line` | 批量更新业务线（上限 100） |

---

## 策略组管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/policy-groups` | 策略组列表 |
| GET | `/api/v1/policy-groups/:id` | 策略组详情 |
| GET | `/api/v1/policy-groups/:id/statistics` | 策略组统计 |
| POST | `/api/v1/policy-groups` | 创建策略组 |
| PUT | `/api/v1/policy-groups/:id` | 更新策略组 |
| DELETE | `/api/v1/policy-groups/:id` | 删除策略组 |

---

## 策略管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/policies` | 策略列表 |
| GET | `/api/v1/policies/:policy_id` | 策略详情 |
| GET | `/api/v1/policies/:policy_id/statistics` | 策略统计 |
| POST | `/api/v1/policies` | 创建策略 |
| PUT | `/api/v1/policies/:policy_id` | 更新策略 |
| DELETE | `/api/v1/policies/:policy_id` | 删除策略 |
| POST | `/api/v1/policies/batch/enable` | 批量启用或禁用策略 |
| POST | `/api/v1/policies/batch/delete` | 批量删除策略 |
| POST | `/api/v1/policies/batch/export` | 批量导出策略 |
| GET | `/api/v1/policies/export` | 导出全部策略 |
| GET | `/api/v1/policies/:policy_id/export` | 导出单个策略 |
| POST | `/api/v1/policies/import` | 导入策略 |

---

## 规则管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/policies/:policy_id/rules` | 策略下的规则列表 |
| POST | `/api/v1/policies/:policy_id/rules` | 在策略下创建规则 |
| GET | `/api/v1/rules/:rule_id` | 规则详情 |
| PUT | `/api/v1/rules/:rule_id` | 更新规则 |
| DELETE | `/api/v1/rules/:rule_id` | 删除规则 |

---

## 扫描任务

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/tasks` | 任务列表 |
| GET | `/api/v1/tasks/:task_id` | 任务详情 |
| GET | `/api/v1/tasks/:task_id/checks` | 任务检查项明细（按规则聚合，支持 `?result=pass\|fail`） |
| GET | `/api/v1/tasks/:task_id/host-status` | 任务主机执行状态 |
| POST | `/api/v1/tasks` | 创建扫描任务 |
| POST | `/api/v1/tasks/:task_id/run` | 执行任务 |
| POST | `/api/v1/tasks/:task_id/cancel` | 取消任务 |
| DELETE | `/api/v1/tasks/:task_id` | 删除任务 |

---

## 基线检查结果

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/results` | 检查结果列表 |
| GET | `/api/v1/results/detail` | 检查结果详情 |
| GET | `/api/v1/results/host/:host_id/score` | 主机基线得分 |
| GET | `/api/v1/results/host/:host_id/summary` | 主机基线摘要 |
| GET | `/api/v1/results/host/:host_id/export` | 导出主机基线结果 |

---

## 基线修复

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/fix/fixable-items` | 可修复项列表 |
| POST | `/api/v1/fix-tasks` | 创建修复任务 |
| GET | `/api/v1/fix-tasks` | 修复任务列表 |
| GET | `/api/v1/fix-tasks/:task_id` | 修复任务详情 |
| GET | `/api/v1/fix-tasks/:task_id/results` | 修复结果 |
| GET | `/api/v1/fix-tasks/:task_id/host-status` | 修复任务主机状态 |
| POST | `/api/v1/fix-tasks/:task_id/cancel` | 取消修复任务 |
| DELETE | `/api/v1/fix-tasks/:task_id` | 删除修复任务 |

---

## 用户管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/users` | 用户列表 |
| GET | `/api/v1/users/:id` | 用户详情 |
| POST | `/api/v1/users` | 创建用户 |
| PUT | `/api/v1/users/:id` | 更新用户 |
| DELETE | `/api/v1/users/:id` | 删除用户 |

---

## 资产管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/assets/overview` | 资产概览 |
| GET | `/api/v1/assets/history` | 资产历史 |
| GET | `/api/v1/assets/statistics` | 资产统计 |
| GET | `/api/v1/assets/relations` | 资产关系 |
| GET | `/api/v1/assets/status` | 采集状态 |
| GET | `/api/v1/assets/top` | TopN 资产 |
| GET | `/api/v1/assets/processes` | 进程列表 |
| GET | `/api/v1/assets/ports` | 端口列表 |
| GET | `/api/v1/assets/users` | 用户列表 |
| GET | `/api/v1/assets/software` | 软件列表 |
| GET | `/api/v1/assets/containers` | 容器列表 |
| GET | `/api/v1/assets/apps` | 应用列表 |
| GET | `/api/v1/assets/network-interfaces` | 网卡列表 |
| GET | `/api/v1/assets/volumes` | 卷列表 |
| GET | `/api/v1/assets/kmods` | 内核模块列表 |
| GET | `/api/v1/assets/services` | 系统服务列表 |
| GET | `/api/v1/assets/crons` | 定时任务列表 |
| GET | `/api/v1/assets/export` | 资产导出 |
| GET | `/api/v1/assets/sbom` | SBOM 导出 |

---

## 报表

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/reports/stats` | 报表统计 |
| GET | `/api/v1/reports/baseline-score-trend` | 基线评分趋势 |
| GET | `/api/v1/reports/check-result-trend` | 检查结果趋势 |
| GET | `/api/v1/reports/task/:task_id` | 任务报告 |
| GET | `/api/v1/reports/task/:task_id/host/:host_id` | 任务主机详情报告 |
| GET | `/api/v1/reports/task/:task_id/executive` | 基线执行摘要报告 |
| GET | `/api/v1/reports/top-failed-rules` | 失败最多的规则 |
| GET | `/api/v1/reports/top-risk-hosts` | 风险最高的主机 |
| GET | `/api/v1/reports/antivirus` | 病毒查杀报告 |
| GET | `/api/v1/reports/vulnerability` | 漏洞报告 |
| GET | `/api/v1/reports/kube` | 容器安全报告 |
| GET | `/api/v1/reports/edr` | EDR 检测报告 |
| GET | `/api/v1/reports/antivirus/:task_id/executive` | 病毒查杀执行摘要 |
| GET | `/api/v1/reports/vulnerability/executive` | 漏洞执行摘要 |
| GET | `/api/v1/reports/remediation/executive` | 修复执行摘要 |
| GET | `/api/v1/reports/kube/executive` | 容器安全执行摘要 |
| GET | `/api/v1/reports/edr/executive` | EDR 检测执行摘要 |
| GET | `/api/v1/reports/generated` | 已生成报告列表 |
| GET | `/api/v1/reports/generated/:id` | 已生成报告详情 |
| DELETE | `/api/v1/reports/generated/:id` | 删除已生成报告 |

---

## 业务线管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/business-lines` | 业务线列表 |
| GET | `/api/v1/business-lines/:id` | 业务线详情 |
| POST | `/api/v1/business-lines` | 创建业务线 |
| PUT | `/api/v1/business-lines/:id` | 更新业务线 |
| DELETE | `/api/v1/business-lines/:id` | 删除业务线 |

---

## 系统配置

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/system-config/kubernetes-image` | 获取 K8s 镜像配置 |
| PUT | `/api/v1/system-config/kubernetes-image` | 更新 K8s 镜像配置 |
| PUT | `/api/v1/system-config/site` | 更新站点配置 |
| POST | `/api/v1/system-config/upload-logo` | 上传 Logo |
| GET | `/api/v1/system-config/alert` | 获取告警配置 |
| PUT | `/api/v1/system-config/alert` | 更新告警配置 |

---

## 通知管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/notifications` | 通知渠道列表 |
| GET | `/api/v1/notifications/:id` | 通知渠道详情 |
| POST | `/api/v1/notifications` | 创建通知渠道 |
| PUT | `/api/v1/notifications/:id` | 更新通知渠道 |
| DELETE | `/api/v1/notifications/:id` | 删除通知渠道 |
| POST | `/api/v1/notifications/test` | 测试通知发送 |

---

## 告警管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/alerts` | 告警列表 |
| GET | `/api/v1/alerts/statistics` | 告警统计 |
| GET | `/api/v1/alerts/edr-statistics` | EDR 告警统计 |
| GET | `/api/v1/alerts/:id` | 告警详情 |
| POST | `/api/v1/alerts/:id/resolve` | 解决告警 |
| POST | `/api/v1/alerts/:id/ignore` | 忽略告警 |
| POST | `/api/v1/alerts/batch/resolve` | 批量解决告警 |
| POST | `/api/v1/alerts/batch/ignore` | 批量忽略告警 |
| POST | `/api/v1/alerts/batch/delete` | 批量删除告警 |
| GET | `/api/v1/alerts/:id/context` | 告警溯源上下文 |

### 告警白名单

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/alerts/whitelist` | 白名单列表 |
| POST | `/api/v1/alerts/whitelist` | 创建白名单 |
| PUT | `/api/v1/alerts/whitelist/:id` | 更新白名单 |
| DELETE | `/api/v1/alerts/whitelist/:id` | 删除白名单 |

---

## 审计日志

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/audit-logs` | 审计日志列表 |

---

## 组件管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/components` | 组件列表 |
| POST | `/api/v1/components` | 创建组件 |
| GET | `/api/v1/components/plugin-status` | 插件同步状态 |
| GET | `/api/v1/components/:id` | 组件详情 |
| DELETE | `/api/v1/components/:id` | 删除组件 |
| GET | `/api/v1/components/:id/versions` | 组件版本列表 |
| POST | `/api/v1/components/:id/versions` | 发布新版本 |
| GET | `/api/v1/components/:id/versions/:version_id` | 版本详情 |
| PUT | `/api/v1/components/:id/versions/:version_id/set-latest` | 设为最新版 |
| DELETE | `/api/v1/components/:id/versions/:version_id` | 删除版本 |
| POST | `/api/v1/components/:id/versions/:version_id/packages` | 上传安装包 |
| DELETE | `/api/v1/packages/:id` | 删除安装包 |
| POST | `/api/v1/components/agent/push-update` | 推送 Agent 更新 |
| POST | `/api/v1/components/plugins/sync-latest` | 同步全部插件到最新版 |
| POST | `/api/v1/components/plugins/broadcast` | 广播插件配置 |
| GET | `/api/v1/components/push-records` | 推送记录列表 |
| GET | `/api/v1/components/push-records/:id` | 推送记录详情 |

---

## 运维巡检

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/inspection/overview` | 巡检概览 |

---

## 检测规则管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/detection-rules` | 检测规则列表 |
| GET | `/api/v1/detection-rules/categories` | 规则分类 |
| GET | `/api/v1/detection-rules/mitre-ids` | MITRE ATT&CK ID 列表 |
| GET | `/api/v1/detection-rules/statistics` | 规则统计 |
| GET | `/api/v1/detection-rules/:id` | 规则详情 |
| POST | `/api/v1/detection-rules` | 创建检测规则 |
| PUT | `/api/v1/detection-rules/:id` | 更新检测规则 |
| DELETE | `/api/v1/detection-rules/:id` | 删除检测规则（内置规则不可删除） |
| POST | `/api/v1/detection-rules/:id/toggle` | 启用或禁用规则 |

---

## 威胁情报

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/threat-intel/stats` | IOC 统计 |
| GET | `/api/v1/threat-intel/iocs` | IOC 列表 |
| POST | `/api/v1/threat-intel/check` | IOC 查询 |
| POST | `/api/v1/threat-intel/sync` | 触发情报同步 |
| GET | `/api/v1/threat-intel/sync-status` | 同步状态 |
| GET | `/api/v1/threat-intel/sync-history` | 同步历史 |

---

## 网络阻断

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/network-block/rules` | 阻断规则列表 |
| POST | `/api/v1/network-block/rules` | 创建阻断规则 |
| POST | `/api/v1/network-block/rules/:id/remove` | 移除阻断规则 |
| DELETE | `/api/v1/network-block/rules/:id` | 删除阻断规则 |

---

## 依赖管理

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/hosts/dependency/install` | 安装依赖 |
| POST | `/api/v1/hosts/dependency/status` | 查询依赖状态 |

---

## Kubernetes 容器安全

### 集群管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/kube/clusters` | 集群列表 |
| POST | `/api/v1/kube/clusters` | 创建集群 |
| GET | `/api/v1/kube/clusters/:id` | 集群详情 |
| PUT | `/api/v1/kube/clusters/:id` | 更新集群 |
| DELETE | `/api/v1/kube/clusters/:id` | 删除集群 |
| GET | `/api/v1/kube/clusters/:id/nodes` | 集群节点列表 |
| GET | `/api/v1/kube/clusters/:id/pods` | 集群 Pod 列表 |
| GET | `/api/v1/kube/clusters/:id/workloads` | 集群工作负载列表 |
| POST | `/api/v1/kube/clusters/:id/regenerate-token` | 重新生成审计 Token |
| PUT | `/api/v1/kube/clusters/:id/gcp-config` | 更新 GCP 配置 |
| DELETE | `/api/v1/kube/clusters/:id/gcp-config` | 删除 GCP 配置 |

### 容器告警

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/kube/alarms` | 容器告警列表 |
| POST | `/api/v1/kube/alarms/:id/process` | 处理告警 |
| POST | `/api/v1/kube/alarms/batch-process` | 批量处理告警 |
| POST | `/api/v1/kube/alarms/batch-ignore` | 批量忽略告警 |

### 安全事件

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/kube/events` | 安全事件列表 |
| POST | `/api/v1/kube/events/:id/handle` | 处理安全事件 |

### 基线检查

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/kube/baseline` | 基线检查列表 |
| GET | `/api/v1/kube/baseline/:id` | 基线检查详情 |
| POST | `/api/v1/kube/baseline/detect` | 执行基线检查 |

### 基线规则

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/kube/baseline-rules` | 基线规则列表 |
| GET | `/api/v1/kube/baseline-rules/export` | 导出基线规则 |
| POST | `/api/v1/kube/baseline-rules/import` | 导入基线规则 |
| POST | `/api/v1/kube/baseline-rules/validate-expression` | 验证检查表达式 |
| GET | `/api/v1/kube/baseline-rules/expression-templates` | 表达式模板列表 |
| POST | `/api/v1/kube/baseline-rules/expression-templates` | 创建表达式模板 |
| PUT | `/api/v1/kube/baseline-rules/expression-templates/:id` | 更新表达式模板 |
| DELETE | `/api/v1/kube/baseline-rules/expression-templates/:id` | 删除表达式模板 |
| GET | `/api/v1/kube/baseline-rules/:id` | 基线规则详情 |
| POST | `/api/v1/kube/baseline-rules` | 创建基线规则 |
| PUT | `/api/v1/kube/baseline-rules/:id` | 更新基线规则 |
| DELETE | `/api/v1/kube/baseline-rules/:id` | 删除基线规则 |
| PUT | `/api/v1/kube/baseline-rules/:id/toggle` | 启用或禁用规则 |

### 基线告警

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/kube/baseline-alerts` | 基线告警列表 |
| POST | `/api/v1/kube/baseline-alerts/:id/ignore` | 忽略基线告警 |
| POST | `/api/v1/kube/baseline-alerts/batch-ignore` | 批量忽略基线告警 |

### 容器白名单

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/kube/whitelist` | 白名单列表 |
| POST | `/api/v1/kube/whitelist` | 创建白名单 |
| PUT | `/api/v1/kube/whitelist/:id` | 更新白名单 |
| DELETE | `/api/v1/kube/whitelist/:id` | 删除白名单 |

### 容器安全统计

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/kube/stats/summary` | 统计摘要 |
| GET | `/api/v1/kube/stats/alarm-trend` | 告警趋势 |

---

## FIM 文件完整性监控

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/fim/policies` | FIM 策略列表 |
| POST | `/api/v1/fim/policies` | 创建 FIM 策略 |
| GET | `/api/v1/fim/policies/:id` | FIM 策略详情 |
| PUT | `/api/v1/fim/policies/:id` | 更新 FIM 策略 |
| DELETE | `/api/v1/fim/policies/:id` | 删除 FIM 策略 |
| GET | `/api/v1/fim/tasks` | FIM 任务列表 |
| POST | `/api/v1/fim/tasks` | 创建 FIM 任务 |
| GET | `/api/v1/fim/tasks/:id` | FIM 任务详情 |
| POST | `/api/v1/fim/tasks/:id/run` | 执行 FIM 任务 |
| GET | `/api/v1/fim/events` | FIM 事件列表 |
| GET | `/api/v1/fim/events/stats` | FIM 事件统计 |
| GET | `/api/v1/fim/events/:id` | FIM 事件详情 |

---

## 系统监控

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/monitor/host` | 主机监控 |
| GET | `/api/v1/monitor/services` | 服务监控 |
| GET | `/api/v1/monitor/service-alerts` | 服务告警列表 |
| POST | `/api/v1/monitor/service-alerts/:id/ack` | 确认服务告警 |

---

## 配置备份

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/system/backups` | 备份列表 |
| POST | `/api/v1/system/backups` | 创建备份 |
| GET | `/api/v1/system/backup-config` | 备份配置 |
| PUT | `/api/v1/system/backup-config` | 更新备份配置 |
| GET | `/api/v1/system/backups/:id/download` | 下载备份 |
| POST | `/api/v1/system/backups/:id/restore` | 恢复备份 |
| DELETE | `/api/v1/system/backups/:id` | 删除备份 |

---

## 病毒查杀

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/antivirus/tasks` | 扫描任务列表 |
| POST | `/api/v1/antivirus/tasks` | 创建扫描任务 |
| GET | `/api/v1/antivirus/tasks/:id` | 扫描任务详情 |
| DELETE | `/api/v1/antivirus/tasks/:id` | 删除扫描任务 |
| POST | `/api/v1/antivirus/tasks/:id/cancel` | 取消扫描任务 |
| GET | `/api/v1/antivirus/results` | 扫描结果列表 |
| GET | `/api/v1/antivirus/results/:id` | 扫描结果详情 |
| POST | `/api/v1/antivirus/results/:id/quarantine` | 隔离文件 |
| POST | `/api/v1/antivirus/results/:id/ignore` | 忽略结果 |
| POST | `/api/v1/antivirus/results/:id/delete-file` | 删除文件 |
| GET | `/api/v1/antivirus/statistics` | 病毒查杀统计 |
| GET | `/api/v1/antivirus/virus-db/status` | 病毒库状态 |
| GET | `/api/v1/antivirus/virus-db/history` | 病毒库更新历史 |
| POST | `/api/v1/antivirus/virus-db/sync` | 触发病毒库同步 |

---

## 文件隔离箱

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/quarantine/files` | 隔离文件列表 |
| GET | `/api/v1/quarantine/files/:id` | 隔离文件详情 |
| POST | `/api/v1/quarantine/files/:id/restore` | 恢复文件 |
| DELETE | `/api/v1/quarantine/files/:id` | 删除隔离文件 |
| POST | `/api/v1/quarantine/files/batch-delete` | 批量删除隔离文件 |
| GET | `/api/v1/quarantine/statistics` | 隔离箱统计 |

---

## 漏洞管理

| 方法 | 路径 | 说明 |
|------|------|------|
| GET | `/api/v1/vulnerabilities` | 漏洞列表 |
| POST | `/api/v1/vulnerabilities/:id/ignore` | 忽略漏洞 |
| POST | `/api/v1/vulnerabilities/sync` | 触发漏洞库同步 |
| POST | `/api/v1/vulnerabilities/scan` | 触发漏洞扫描（支持 scope=global/hosts/business_line） |
| GET | `/api/v1/vulnerabilities/scan-status` | 扫描状态 |
| GET | `/api/v1/vulnerabilities/scan-history` | 扫描历史 |
| GET | `/api/v1/vulnerabilities/scan-tasks` | 定向扫描任务列表 |
| GET | `/api/v1/vulnerabilities/scan-tasks/:task_id` | 定向扫描任务进度 |
| GET | `/api/v1/vulnerabilities/:id/advice` | 修复建议 |
| POST | `/api/v1/vulnerabilities/:id/patch` | 修复漏洞 |
| POST | `/api/v1/vulnerabilities/:id/verify` | 验证修复 |
| GET | `/api/v1/vulnerabilities/stats/remediation` | 修复统计 |
| GET | `/api/v1/vulnerabilities/stats/trend` | 修复趋势 |

---

## 漏洞修复任务

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/remediation-tasks` | 创建修复任务 |
| GET | `/api/v1/remediation-tasks` | 修复任务列表 |
| GET | `/api/v1/remediation-tasks/stats` | 修复任务统计 |
| GET | `/api/v1/remediation-tasks/:id` | 修复任务详情 |
| POST | `/api/v1/remediation-tasks/:id/confirm` | 确认修复任务 |
| POST | `/api/v1/remediation-tasks/:id/cancel` | 取消修复任务 |
| POST | `/api/v1/remediation-tasks/:id/retry` | 重试修复任务 |
| POST | `/api/v1/remediation-tasks/:id/verify` | 验证修复任务 |
| POST | `/api/v1/remediation-tasks/batch` | 批量创建修复任务 |
| POST | `/api/v1/remediation-tasks/batch-confirm` | 批量确认修复任务 |
| POST | `/api/v1/remediation-tasks/batch-retry` | 批量重试修复任务 |
| POST | `/api/v1/remediation-tasks/batch-cancel` | 批量取消修复任务 |

---

## 数据迁移

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v1/system/migration/test-connection` | 测试迁移连接 |
| POST | `/api/v1/system/migration/jobs` | 启动迁移任务 |
| GET | `/api/v1/system/migration/jobs` | 迁移任务列表 |
| GET | `/api/v1/system/migration/jobs/:id` | 迁移任务详情 |
| POST | `/api/v1/system/migration/jobs/:id/cancel` | 取消迁移任务 |

---

## 内存威胁 (EDR-3)

memfd_exec / 进程镂空 / shellcode 注入 / LSASS dump 检测.

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/v1/memory-threats` | 内存威胁事件列表 (filter: host_id / status / severity / kind) |
| GET  | `/api/v1/memory-threats/stats` | 24h 聚合统计 (by_threat_type / severity / open / critical_open) |
| PUT  | `/api/v1/memory-threats/:id/resolve` | 标记一条威胁为已处理 |

---

## AD / LDAP 域控审计 (EDR-4)

7 条规则: DCSync / Kerberoasting / 暴力破解 / 非工时 RDP / 特权分配 / 高权限组成员添加 / 攻击工具执行.

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/v1/ad-audit/events` | 原始 AD 审计事件列表 (filter: kind / username / source_ip) |
| GET  | `/api/v1/ad-audit/alerts` | 命中规则的告警列表 (filter: rule_id / status) |
| GET  | `/api/v1/ad-audit/stats` | 24h 统计 (total / by_kind / top_failed_users) |

---

## Rootkit / DKOM 检测 (C2)

DKOM 隐藏 PID / 内核模块 / 端口 / LD_PRELOAD 异常 / /proc 不一致.

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/v1/rootkit/findings` | 已发现 Rootkit 异常列表 (filter: host_id / status) |
| POST | `/api/v1/rootkit/scan` | 触发一台主机扫描 (body: {host_id}); 返回最近一次扫描快照 |
| POST | `/api/v1/rootkit/findings/:id/resolve` | 标记一条 finding 为已处理 (body: {note}) |

---

## 蜜罐传感器 (C1)

SSH / HTTP 蜜罐 + 文件诱饵, 命中即告警 (合法备份工具白名单).

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/v1/v2/honeypot/sensors` | 已部署传感器列表 (按租户隔离) |
| POST | `/api/v1/v2/honeypot/sensors` | 部署传感器 (body: {host_id, kind, bind_addr}) |
| POST | `/api/v1/v2/honeypot/sensors/:id/stop` | 停止/删除一个传感器 |
| GET  | `/api/v1/v2/honeypot/events` | 蜜罐命中告警事件 (filter: sensor_id / kind / src_ip) |

---

## VEX 漏洞利用性声明 (B7)

CycloneDX VEX 1.5 + CSAF 2.0 标准. 4 状态: not_affected / affected / fixed / under_investigation.

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/v1/vex/:product_id?version=X.Y.Z` | 完整 VEX 文档 (JSON) |
| GET  | `/api/v1/vex/:product_id/statements` | CVE 声明列表 |
| GET  | `/api/v1/vex/:product_id/cyclonedx?version=X.Y.Z` | 下载 CycloneDX VEX 1.5 |
| GET  | `/api/v1/vex/:product_id/csaf?version=X.Y.Z` | 下载 CSAF 2.0 |

---

## v2 多租户与平台管理

### 系统模式（observe / protect）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/v2/system/mode` | 当前租户的模式（observe/protect） |
| GET  | `/api/v2/admin/tenants/modes` | 列出全部租户的模式（超管） |
| POST | `/api/v2/admin/tenants/:id/mode` | 切换租户模式（超管） |

### 租户管理（超管）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/v2/admin/tenants` | 租户列表 |
| GET  | `/api/v2/admin/tenants/:id` | 租户详情 |
| POST | `/api/v2/admin/tenants` | 创建租户 |
| POST | `/api/v2/admin/tenants/:id/suspend` | 暂停租户 |
| POST | `/api/v2/admin/tenants/:id/resume` | 恢复租户 |

### 配置变更审批

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/v2/config/change-requests` | 提交配置变更请求 |
| GET  | `/api/v2/config/change-requests` | 变更请求列表 |
| GET  | `/api/v2/config/change-requests/sensitivity` | 配置项敏感度定义 |
| GET  | `/api/v2/config/change-requests/:id` | 变更请求详情 |
| POST | `/api/v2/config/change-requests/:id/approve` | 审批通过 |
| POST | `/api/v2/config/change-requests/:id/reject` | 审批拒绝 |
| POST | `/api/v2/config/change-requests/:id/cancel` | 撤销请求 |

### MSSP 控制台（多租户托管）

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/v2/mssp/dashboard` | MSSP 总览面板 |
| GET  | `/api/v2/mssp/child-tenants` | 子租户列表 |
| POST | `/api/v2/mssp/child-tenants` | 创建子租户 |
| GET  | `/api/v2/mssp/child-tenants/:id` | 子租户详情 |
| POST | `/api/v2/mssp/child-tenants/:id/suspend` | 暂停子租户 |
| POST | `/api/v2/mssp/child-tenants/:id/resume` | 恢复子租户 |
| GET  | `/api/v2/mssp/alerts` | 跨租户告警视图 |

### 其它 v2 子领域

以下 v2 端点详见 OpenAPI 规范（[`docs/openapi/openapi.yaml`](openapi/openapi.yaml)）：

- `/api/v2/threat-intel/*` — 威胁情报 IOC 管理与匹配
- `/api/v2/sbom/*` — SBOM 软件物料清单 + 差异比对
- `/api/v2/kube/clusters/*` — K8s 集群基线、Admission 接入
- `/api/v2/soar/*` — SOAR 剧本编排与执行
- `/api/v2/honeypot/*` — 蜜罐 v2 接口（含 sensor / events）
- `/api/v2/microseg/*` — 微隔离策略生成与下发

---

## 错误码

| HTTP 状态码 | 说明 |
|------------|------|
| 200 | 成功 |
| 400 | 参数错误 |
| 401 | 未认证 / Token 过期 |
| 403 | 权限不足 |
| 404 | 资源不存在 |
| 500 | 服务器内部错误 |
