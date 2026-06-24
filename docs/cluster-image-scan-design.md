# 容器集群镜像扫描设计（in-cluster / trivy-operator）

**状态**: 设计确认，实现中 | **目标集群**: GKE | **最后更新**: 2026-06-18

---

## 1. 定位与原则

- **manager = 聚合 / 编排 / 展示层**，不亲自拉镜像、不在控制面跑扫描。
- **trivy-operator = 集群内扫描引擎**，跑在目标集群内，读 node 已拉镜像（containerd），**不重拉**。
- **k8s API Server = 解耦总线**，`VulnerabilityReport` CRD 是结果契约。
- manager 与 trivy 无直连；二者通过目标集群 API Server 解耦。

对比已废弃方案：早期"trivy 装进 manager 镜像 + 中心拉取每个镜像扫描"已撤销——大集群带宽爆炸、冲击控制面、私有 Registry 认证复杂。
> 注：manager 镜像仍保留 trivy 二进制，仅用于**手动扫单镜像 / Registry 中心化扫描**（CI 式），与集群扫描无关。

---

## 2. 数据流

```
trivy-operator (目标集群内)
   │ watch workload → 起 scan Job → 扫 node 已拉镜像
   │ 结果写 CR: VulnerabilityReport (aquasecurity.github.io/v1alpha1, namespaced)
   ▼
k8s API Server / etcd
   ├──(Pull) manager client-go LIST CRD ──┐
   └──(Push) operator webhook POST report ┤→ 统一解析 parseVulnReport()
                                          ▼
                          MySQL: image_scans(source=cluster, cluster_id) + image_vulnerabilities
                                          ▼
                                   前端 image-scan 页
```

- **Pull**：manager 定时 + 按需 LIST CRD 同步落库。稳、可控、扛 manager 宕机。
- **Push**：trivy-operator `OPERATOR_WEBHOOK_BROADCAST_URL` 扫完 POST report 到 manager 端点（token 鉴权）。准实时。
- 两通道复用同一 `parseVulnReport()` 解析（CR 结构一致）。

---

## 3. 每集群生命周期状态机（`kube_scanners` 表）

```
NotInstalled ─install→ Installing ─ok→ Ready ─drift/crash→ Degraded
     ▲                      │fail              │
     └── Uninstalling ◄─────┴──(rollback)      └─sync→ Ready(lastSyncAt/reportCount)
```

`kube_scanners` 字段：cluster_id(uniq)、state、operator_version、image_registry(覆盖)、webhook_enabled、last_sync_at、last_report_count、last_error。

---

## 4. 各阶段设计

### 4.1 部署（双路径安装）
- **路径 A 自动**：我方 kubeconfig 有集群写权限 → client-go server-side apply 内嵌 manifest（v0.24.0）。
- **路径 B 兜底**：只读 / air-gap → `GET .../scanner/manifest` 导出渲染后 YAML，客户自行 `kubectl apply`。
- **预检**：k8s 版本、我方权限（能否建 CRD/ClusterRole）、`trivy-system` ns 是否已被占、是否已存在 operator。
- **镜像地址可配**：`image_registry` 覆盖默认 `ghcr.io/...`，支持 air-gap 私有 registry 镜像重写。
- 安装时把 manager 外部可达 URL + per-cluster token 注入 operator ConfigMap（启用 Push）。

### 4.2 配置
- 本轮默认值：排除 `kube-system` 等系统 ns、周期重扫 24h（operator 默认）、**Standalone trivy 模式**。
- ClientServer 共享 DB 模式 → 下轮（规模化）。

### 4.3 触发
- operator 事件驱动（workload 变更自动扫 + 周期重扫），manager 不亲自调。
- 按需重扫：后续支持（删 report / 打 annotation）。

### 4.4 结果返回
- Pull：`SyncReports(clusterID)` LIST CRD（分页 continue token）→ 批量 upsert，事务内先清本集群旧 `source=cluster` 记录再写入快照。
- Push：`POST /api/v1/kube/scanner/report-webhook/:cluster_token` 接收单 report，token 校验后 upsert。
- workload 删除 → report 消失 → Pull 快照覆盖自动清理。

### 4.5 运行 / 健康
- `Status(clusterID)`：operator deployment ready 副本数 + 状态机 state + lastSyncAt + reportCount + lastError。
- 漂移检测：operator 被外部卸载/崩溃 → status 反映 Degraded。

### 4.6 卸载
- 按序删 operator + CRD + ns（删 CRD 级联清集群内 report；我方 DB 副本保留历史）。
- 撤 webhook 配置、置状态 NotInstalled。

### 4.7 安全 / 合规
- operator 与我方 kubeconfig 双 least-privilege；webhook token 鉴权；审计装/卸/同步操作；漏洞数据出集群→数据驻留合规说明。

---

## 5. 本轮范围（核心生命周期）

✅ 状态机表、预检、双路径安装、镜像地址可配、Pull 同步、Push webhook、状态/健康、卸载、定时同步、前端面板。
⏳ 下轮：ClientServer 共享 DB、operator 升级路径、Prometheus 健康抓取、按需重扫、WATCH 准实时。

---

## 6. 关键接口

| 方法 | 端点 | 说明 |
|------|------|------|
| POST | `/api/v1/kube/clusters/:id/scanner/install` | 自动安装 |
| GET | `/api/v1/kube/clusters/:id/scanner/manifest` | 导出 manifest（兜底） |
| GET | `/api/v1/kube/clusters/:id/scanner/status` | 状态/健康 |
| POST | `/api/v1/kube/clusters/:id/scanner/sync` | 按需 Pull 同步 |
| DELETE | `/api/v1/kube/clusters/:id/scanner` | 卸载 |
| POST | `/api/v1/kube/scanner/report-webhook/:cluster_token` | Push 接收（token 鉴权，无 JWT） |
</content>
</invoke>
