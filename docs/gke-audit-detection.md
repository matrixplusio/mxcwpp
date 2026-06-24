# GKE 审计检测设计与接入

**状态**: 真集群验证通过 + 规则修复 | **已验证**: csc5002-public-uat / uat-k8s-cluster-01（2026-06-18）

---

## 1. GKE 审计的三个硬约束

1. **webhook 路径在 GKE 不可用**：GKE 控制面由 Google 托管，无法配置 apiserver `--audit-webhook` / audit policy。GKE 审计**只能走 GCP Cloud Audit Logs → Pub/Sub** 这一条。webhook 路径仅对自管集群有效。
2. **Data Access 日志默认关**：GCP 默认只开 Admin Activity（写操作）。读操作类检测（如 Secret get/list，K8S-004）需显式开启 Data Access 审计日志（有日志量成本）。本次仅开 Admin Activity。
3. **请求体覆盖**：实测 GKE Admin Activity 日志**包含完整 `protoPayload.request`**（如 Pod spec 的 `securityContext.privileged`），依赖请求体的规则可正常工作。

---

## 2. 接入链路（GCP 侧，gcloud）

```
GKE Cloud Audit Logs (Admin Activity)
  → Log Router sink (filter: resource.type=k8s_cluster AND cluster_name=<集群> AND logName=.../activity)
  → Pub/Sub topic
  → subscription
  → 平台 gcppubsub consumer（SA key，pubsub.subscriber）
  → transform → ProcessAuditEvents → detector → kube_alarms
```

GCP 资源（项目内，可逆）：
- Pub/Sub topic + subscription
- Log Router sink + 授其 writerIdentity `roles/pubsub.publisher`
- 消费 SA `mxcwpp-pubsub-consumer`（subscription 级 `roles/pubsub.subscriber`）+ JSON key

平台配置：`PUT /api/v1/kube/clusters/:id/gcp-config { projectId, subscription, credentialsJson }` → `UpdateGCPConfig` 动态拉起 consumer（无需重启）。

> 前端暂无 GCP Pub/Sub 配置 UI（属新 UI 重构遗留缺口，后端 API 已具备）。

---

## 3. 真集群验证结论（2026-06-18）

| 项 | 结果 |
|----|------|
| 管道端到端 | ✅ 8452 audit 事件经 Pub/Sub 落库 + 检测 |
| 请求体存在 | ✅ Pod create 含完整 spec（privileged 等） |
| K8S-003（cluster-admin 绑定） | ✅ 真集群活动触发 |
| **K8S-006（SA Token）误报** | ❌→✅ 修复（见下） |

### 关键发现：K8S-006 误报炸（983 条）
原逻辑「UserAgent 不在白名单 + SA 用户 → 告警」在真集群彻底失效——kyverno / prometheus-operator / victoria-metrics 等合法 operator 的自定义 UserAgent 全部命中，产生 983 条误报。

**修复**：弃用 UserAgent 白名单，改判 Token 盗用的真实信号：
- SA Token 来自**集群外公网源 IP**（正常 workload 均为私网 IP），或
- SA Token 经**人类/脚本客户端**调用（kubectl/curl/python/wget 等）

合法 operator（私网 IP + 自有 UA）不再误报。

---

## 4. 检测规则（14 条）

| ID | 规则 | 严重度 | 依赖字段 |
|----|------|--------|---------|
| K8S-001 | kubectl exec 进入容器 | high | subresource=exec |
| K8S-002 | hostNetwork/hostPID Pod | critical | request.spec |
| K8S-003 | ClusterRole 绑定高权限 | critical | request.roleRef |
| K8S-004 | 访问 Secret（需 Data Access 日志） | medium | verb+resource |
| K8S-005 | 特权容器 | critical | request.spec |
| K8S-006 | SA Token 疑似盗用（已重做） | high | sourceIP/userAgent |
| K8S-007 | 容器内反弹 Shell | critical | request.command |
| K8S-008 | 挂载宿主机敏感路径 | critical | request.spec.volumes |
| K8S-009 | port-forward 端口转发 | high | subresource=portforward |
| K8S-010 | attach 接入容器 | high | subresource=attach |
| K8S-011 | 注入 ephemeral container | high | subresource=ephemeralcontainers |
| K8S-012 | 删除 Event（反取证） | high | verb+resource=events |
| K8S-013 | 匿名访问 API Server | critical | user=system:anonymous |
| K8S-014 | 篡改准入 Webhook 配置 | critical | resource=*webhookconfigurations |

规则匹配由 `detector_test.go` 确定性单测覆盖（含 K8S-006 误报回归用例）。

---

## 5. 本轮限制 / 后续

- **K8S-004（Secret 读）未验**：Data Access 日志未开。需要时开启 `container.googleapis.com` 的 DATA_READ 审计日志。
- **impersonation 检测缺失**：transform 未提取 `impersonatedUser`，无法检测 `--as` 提权。后续在 transform + 规则补充。
- **前端 GCP 配置 UI 缺口**：当前经 API 配置；待补集群详情页 + Pub/Sub 配置表单。
- 运行时 syscall 级（Falco/eBPF）检测属主机 EDR，非本审计模块。
</content>
