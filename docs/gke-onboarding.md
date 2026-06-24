# GKE 集群接入指南（容器镜像扫描）

**适用**: 把 GKE 集群接入矩阵云安全平台并启用集群内镜像漏洞扫描（trivy-operator）
**已验证**: csc5002-public-uat / uat-k8s-cluster-01 / asia-east2 / k8s 1.34（2026-06-18，Pull 闭环通）

---

## 0. 背景：为什么不能直接用 gcloud 生成的 kubeconfig

`gcloud container clusters get-credentials` 生成的 kubeconfig 依赖 **exec auth plugin**（`gke-gcloud-auth-plugin`）动态取 token。平台 manager 容器内**没有 gcloud / 该插件**，无法使用这种 kubeconfig。

**必须**为平台单独创建一个 **ServiceAccount + 长效 token**，拼成不依赖外部插件的**静态 kubeconfig**。这是 GKE（及任何托管 k8s）接入第三方平台的标准做法。

---

## 1. 前置

```bash
# 操作者本机需要 gcloud + kubectl + auth-plugin
gcloud components install gke-gcloud-auth-plugin
export USE_GKE_GCLOUD_AUTH_PLUGIN=True

# 取管理员上下文（仅操作者用，用于创建 SA / 安装 operator）
gcloud config set project <PROJECT_ID>
gcloud container clusters get-credentials <CLUSTER> --region <REGION>
```

预检集群：
```bash
kubectl version            # 确认 k8s 版本
kubectl get nodes          # 节点
# 确认非 Autopilot（Autopilot 对 scan Job 有额外限制）
gcloud container clusters describe <CLUSTER> --region <REGION> --format='value(autopilot.enabled)'
```

---

## 2. 创建平台接入凭证（最小权限 SA + 静态 kubeconfig）

### 2.1 最小权限 RBAC（推荐）
平台只读 + 同步漏洞报告；operator 由运维手动安装（见 §3 路径 B）。

```yaml
# mxcwpp-scanner-rbac.yaml
apiVersion: v1
kind: Namespace
metadata: { name: mxcwpp-system }
---
apiVersion: v1
kind: ServiceAccount
metadata: { name: mxcwpp-scanner, namespace: mxcwpp-system }
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata: { name: mxcwpp-scanner-readonly }
# 全资源只读（get/list/watch，无任何写权）。
# 安全态势扫描需要读 RBAC / NetworkPolicy / 各类工作负载等，故采用全只读；
# 仅需镜像漏洞同步(不跑基线)时可收窄为 pods/workloads/vulnerabilityreports。
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: { name: mxcwpp-scanner-readonly }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: mxcwpp-scanner-readonly }
subjects:
  - { kind: ServiceAccount, name: mxcwpp-scanner, namespace: mxcwpp-system }
---
# 长效 token（k8s 1.24+ 不再自动签发 SA token，需显式建 Secret）
apiVersion: v1
kind: Secret
metadata:
  name: mxcwpp-scanner-token
  namespace: mxcwpp-system
  annotations: { kubernetes.io/service-account.name: mxcwpp-scanner }
type: kubernetes.io/service-account-token
```

```bash
kubectl apply -f mxcwpp-scanner-rbac.yaml
```

> **全生命周期档（可选）**：若要平台**一键自动安装/卸载** operator，把 ClusterRole 换成 `cluster-admin`（平台需建 CRD/ClusterRole/Deployment）。代价是平台持集群最高权 + 长效 token，按安全策略评估。

### 2.2 拼静态 kubeconfig
```bash
ENDPOINT=$(gcloud container clusters describe <CLUSTER> --region <REGION> --format='value(endpoint)')
TOKEN=$(kubectl -n mxcwpp-system get secret mxcwpp-scanner-token -o jsonpath='{.data.token}' | base64 -d)
CA=$(kubectl -n mxcwpp-system get secret mxcwpp-scanner-token -o jsonpath='{.data.ca\.crt}')

cat > mxcwpp-kubeconfig.yaml <<EOF
apiVersion: v1
kind: Config
clusters:
  - name: <CLUSTER>
    cluster:
      server: https://${ENDPOINT}
      certificate-authority-data: ${CA}
contexts:
  - name: mxcwpp
    context: { cluster: <CLUSTER>, user: mxcwpp-scanner, namespace: mxcwpp-system }
current-context: mxcwpp
users:
  - name: mxcwpp-scanner
    user: { token: ${TOKEN} }
EOF

# 验证（应能读、不能写）
KUBECONFIG=mxcwpp-kubeconfig.yaml kubectl get nodes
KUBECONFIG=mxcwpp-kubeconfig.yaml kubectl auth can-i create deployments.apps   # 期望 no
```

---

## 3. 安装集群内扫描器（trivy-operator）

operator 跑在集群内，扫 node 已拉镜像（**不重拉**），结果写 `VulnerabilityReport` CRD。

### 路径 A：平台一键安装（需 cluster-admin 档凭证）
平台 → 镜像扫描页 → 选集群 → **部署扫描器**。底层 server-side apply 内嵌 manifest。

### 路径 B：运维 manifest 手动安装（配最小权限档）
```bash
# 从平台导出渲染后的 manifest（含 air-gap 镜像重写、可选 Push webhook 注入）
curl -H "Authorization: Bearer <JWT>" \
  "https://<MANAGER>/api/v1/kube/clusters/<ID>/scanner/manifest?image_registry=<可选私有registry>" \
  -o trivy-operator.yaml

# 用管理员上下文安装（CRD 较大，用 server-side apply 避免注解超限）
kubectl apply --server-side -f trivy-operator.yaml
kubectl -n trivy-system rollout status deploy/trivy-operator
```

> **air-gap**：operator/trivy/trivy-db 镜像默认来自 `mirror.gcr.io/aquasec` 与 `ghcr.io/aquasecurity`。`image_registry` 参数会整体重写为客户私有 registry（需提前镜像 `trivy-operator`、`trivy`、`trivy-db`、`trivy-java-db`）。

---

## 4. 平台接入集群 + 同步

```bash
# 注册集群（kubeConfig 传 §2.2 生成的静态 kubeconfig 内容）
curl -X POST -H "Authorization: Bearer <JWT>" -H "Content-Type: application/json" \
  -d "$(jq -n --arg n '<CLUSTER>' --arg a 'https://<ENDPOINT>' --rawfile kc mxcwpp-kubeconfig.yaml \
        '{name:$n, apiServer:$a, kubeConfig:$kc}')" \
  https://<MANAGER>/api/v1/kube/clusters

# 查扫描器状态（自动探测外部安装的 operator）
curl -H "Authorization: Bearer <JWT>" https://<MANAGER>/api/v1/kube/clusters/<ID>/scanner/status

# 按需 Pull 同步漏洞报告（定时同步默认每 5min 兜底）
curl -X POST -H "Authorization: Bearer <JWT>" https://<MANAGER>/api/v1/kube/clusters/<ID>/scanner/sync
```

结果落 `image_scans`(source=cluster) + `image_vulnerabilities`，前端镜像扫描页按集群过滤查看。

### 结果返回两通道
- **Pull**（默认）：平台定时 + 按需 LIST CRD。稳、扛 manager 宕机。
- **Push**（准实时）：需 manager 有**公网可达** ExternalURL；安装时把 webhook URL 注入 operator，扫完主动 POST。dev 本机不可达故仅 prod 生效。

---

## 5. 卸载 / 清理

```bash
# 平台卸载（cluster-admin 档）：DELETE /api/v1/kube/clusters/<ID>/scanner
# 或手动：
kubectl delete -f trivy-operator.yaml          # 删 operator + CRD（级联清集群内 report）
kubectl delete -f mxcwpp-scanner-rbac.yaml      # 删平台接入 SA/RBAC
```

---

## 6. 已验证结论（UAT，2026-06-18）

| 项 | 结果 |
|----|------|
| 最小权限静态 kubeconfig 接入 | ✅ 平台探到 v1.34.7-gke，只读生效 |
| operator manifest 安装(16 节点) | ✅ rollout 成功 |
| 集群内自动扫描 | ✅ 生成 57 份 VulnerabilityReport |
| Pull 同步落库 | ✅ 57 镜像 / 6291 条 CVE |
| Push（webhook） | ⏳ 需公网 manager，prod 验 |
</content>
