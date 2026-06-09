# 微服务边界重构计划 (A7 / A8 / A9)

**状态**: 设计 + 接口骨架 (本 PR 落)
**实际迁移**: 后续 PR 逐域展开 (每域单独 PR)

## 背景

审计发现 6 微服务 (Manager / AgentCenter / Consumer / Engine / VulnSync / LLMProxy) 边界穿透:

| 违规 | 文件 | 严重度 |
|---|---|---|
| Consumer → engine/ (anomaly/baseline/celengine/storyline/kube) | `internal/server/consumer/router.go:19-22` | 严重 |
| Manager → engine/kube | `manager/biz/kube_baseline_check.go` 等 7 处 | 严重 |
| Manager → vulnsync/advisory | `manager/biz/vuln_scanner.go` 等 4 处 | 严重 |
| Manager → llmproxy | `manager/api/alert_analysis.go` | 严重 |
| Manager → agentcenter/service | `manager/biz/task_scheduler.go` 等 7 处 | 严重 |
| Manager → consumer/gcppubsub | `manager/router/router.go:16` | 中 |
| Consumer → engine/kube (k8s audit) | `consumer/gcppubsub/manager.go:11` | 中 |
| VulnSync 调度双份 | `vulnsync/scheduler.go` + `manager/biz/{nvd,redhat,cnnvd,exploit}_sync.go` | 高 |
| `manager/biz/` 65 个 `.go` 平铺 | `manager/biz/` | 中 |

## A7 Consumer→engine 反向 import 清

**目标**: Consumer 进程只跑 Kafka 幂等写入, 不跑检测.

**步骤** (后续 PR):

1. 新建 `internal/server/engine/consumer/` 目录, 把 Consumer 当前注册 engine 的路由迁过来.
2. `cmd/server/engine/main.go` 注册同样的 KafkaConsumer 路由 (ConsumerGroup `mxsec-engine`).
3. `consumer/router.go` 删 `engine/anomaly`, `engine/baseline`, `engine/celengine`, `engine/storyline` import.
4. `consumer/gcppubsub/manager.go` 删 `engine/kube` import, K8s Audit 走 Engine 进程消费.
5. 部署文档加入: 升级时需先升 Engine (新 ConsumerGroup), 再升 Consumer (移除旧逻辑).

**验证**: 启动 Engine 进程, `mxsec-engine` ConsumerGroup 出现在 Kafka, 同时 Consumer 进程 binary size 减半.

## A8 Manager→engine/kube + vulnsync 改 gRPC

**目标**: Manager 通过 gRPC 调 Engine / VulnSync / LLMProxy.

**步骤**:

1. 定义 proto:
   - `api/proto/engine/engine.proto` — Kube Baseline Check / Anomaly Query 接口
   - `api/proto/vulnsync/vulnsync.proto` — 漏洞同步触发 / 查询接口
   - `api/proto/llmproxy/llmproxy.proto` — Chat / Summarize 接口
2. 各服务进程启 gRPC server (Engine:50051, VulnSync:50052, LLMProxy:50053).
3. `internal/server/manager/client/` 包 (本 PR 已落骨架) 注入到 Manager 的 biz/api, 替换直接 import.
4. 部署 mTLS 证书 (共用 internal-ca, 服务名 SAN).

**接口骨架**: 本 PR 已建 `internal/server/manager/client/`:

```go
// EngineClient 抽象 Engine 跨进程调用.
type EngineClient interface {
    KubeBaselineCheck(ctx context.Context, clusterID string) (*KubeBaselineResult, error)
    QueryAnomaly(ctx context.Context, hostID string, window time.Duration) ([]Anomaly, error)
}

// VulnSyncClient 抽象 VulnSync.
type VulnSyncClient interface {
    TriggerSync(ctx context.Context, source string) error
    LookupAdvisory(ctx context.Context, cve string) (*Advisory, error)
}

// LLMProxyClient 抽象 LLMProxy.
type LLMProxyClient interface {
    Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error)
    SummarizeIncident(ctx context.Context, incidentID string) (string, error)
}
```

后续 PR 实现 gRPC 版本, 旧 inproc 版本作 fallback (开发/测试可用).

## A9 manager/biz/ 拆子包

**目标**: 65 个 `.go` 按域拆 6 子目录:

| 子包 | 文件清单 | 数量 |
|---|---|---|
| `biz/vuln/` | `vuln_*.go` (14) + `cnnvd_sync.go` / `exploit_sync.go` / `redhat_sync.go` / `nvd_sync.go` / `nvd_metadata.go` / `nvd_cpe_test.go` / `nvd_sync_test.go` / `mitre_cve.go` / `osv_cache_adapter.go` / `fixed_version_lookup.go` | 24 |
| `biz/kube/` | `kube_*.go` (9) + `kube_client.go` + `kube_sync.go` | 11 |
| `biz/remediation/` | `remediation_*.go` (7) | 7 |
| `biz/report/` | `pdf*.go` (6) + `report*.go` | ~8 |
| `biz/precheck/` | `precheck_*.go` (3) + `image_scanner.go` | 4 |
| `biz/misc/` (临时) | `notification.go` / `metrics.go` / `cn_official_stub.go` / `score.go` | 5 |

**策略**: 每子包独立 PR, 避免一次性 import 风暴.

**示范**: 后续 PR 先做 `biz/pdf/` (最孤立, 调用方少), 验证迁移流程后再展开其它域.

## 时间预估

| 子项 | 预估工 |
|---|---|
| A7 Consumer→engine 拆 | 1 周 (含部署 doc + 灰度方案) |
| A8 gRPC 化 | 1.5 周 (3 proto + 实现 + mTLS) |
| A9 biz 拆 6 子包 | 2 周 (一域 2~3 天) |

合计 ~4.5 周 = Sprint 6 全部.
