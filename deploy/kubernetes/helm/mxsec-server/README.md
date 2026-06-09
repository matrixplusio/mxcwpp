# mxsec-server Helm Chart

mxsec 服务端 6 微服务 + UI 的 Helm 部署 (Chart v0.1.0, appVersion 2.0.0)。

## 架构

```
client
  │
  ├─→ ingress → manager (HTTP/gRPC API)
  │
  ├─→ NodePort → agentcenter (Agent gRPC 入口)
  │
  └─→ ingress → ui
                 │
                 └─→ manager
                       │
                       ├─→ MySQL (chart 不包含, 外部依赖)
                       ├─→ Redis
                       ├─→ Kafka
                       ├─→ ClickHouse
                       │
                       ├─→ engine        (Kafka 消费 + 检测)
                       ├─→ consumer      (Kafka → CH/MySQL 多源管道)
                       ├─→ vulnsync      (15 漏洞源)
                       └─→ llmproxy      (多 LLM 网关)
```

## 前置准备

### 1. 基础设施 (chart 不包含)

- MySQL 8.0+
- Redis 6.2+
- Kafka 3.x
- ClickHouse 23.x (可选, 不装时 Dashboard 走 0)

### 2. KMS KEK Secret (强制)

```sh
# 生成 KEK
go run ./cmd/tools/kms-gen-kek
# → 输出 base64

kubectl create secret generic mxsec-kms \
  --from-literal=MXSEC_KMS_KEK_V1='<base64>'
```

### 3. 基础设施凭证 Secret

```sh
kubectl create secret generic mxsec-mysql \
  --from-literal=username=mxsec \
  --from-literal=password='<...>'

kubectl create secret generic mxsec-redis \
  --from-literal=password='<...>'

kubectl create secret generic mxsec-clickhouse \
  --from-literal=username=default \
  --from-literal=password='<...>'

# LLM keys (可选)
kubectl create secret generic mxsec-llm-keys \
  --from-literal=openai-api-key='sk-...' \
  --from-literal=anthropic-api-key='sk-ant-...'
```

## 部署

```sh
# 默认安装 (6 微服务 + UI)
helm install mxsec ./deploy/kubernetes/helm/mxsec-server

# 自定义 values
helm install mxsec ./deploy/kubernetes/helm/mxsec-server \
  -f my-values.yaml

# 升级
helm upgrade mxsec ./deploy/kubernetes/helm/mxsec-server \
  -f my-values.yaml

# 卸载
helm uninstall mxsec
```

## 关键 values

| Key | 默认 | 说明 |
|---|---|---|
| `global.imageRegistry` | `ghcr.io/imkerbos` | 镜像仓库前缀 |
| `global.imageTag` | `2.0.0` | 镜像 tag |
| `kms.enabled` | `true` | 是否注入 KMS KEK (强制) |
| `manager.replicaCount` | 2 | manager 副本数 |
| `agentcenter.replicaCount` | 3 | AC 副本数 |
| `agentcenter.agentService.nodePort` | 30751 | Agent 连接 NodePort |
| `engine.config.defaultMode` | observe | observe / protect |
| `engine.replicaCount` | 2 | engine 副本数 |
| `vulnsync.config.sources` | 15 源全开 | 漏洞源开关 |

## Agent 部署

Agent 走独立 chart (`deploy/kubernetes/helm/mxsec-agent`):

```sh
helm install mxsec-agent ./deploy/kubernetes/helm/mxsec-agent \
  --set server.host=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}') \
  --set server.port=30751
```

## 注意事项

- **observe → protect 切换**: 需经 6 闸门 admission (UI /mode 面板)
- **K8s 1.25+**: 用 PodSecurityStandards 替代 PodSecurityPolicy
- **NetworkPolicy**: 推荐部署后用 mxsec 微隔离 Phase 2 推荐策略自动生成
- **多租户**: 单 chart 实例支持多租户; 默认租户 `t-default`
- **OTel**: `observability.otel.enabled=true` 注入 OTLP 端点

## 后续

- subchart dependencies (bitnami mysql/redis/kafka)
- HPA + PodDisruptionBudget 模板
- mxctl helm-renderer (一键生成 values + apply)
- ServiceMesh (Istio) 注入 annotations
