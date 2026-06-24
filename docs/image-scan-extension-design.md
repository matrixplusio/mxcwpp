# 镜像扫描方式扩展设计

**状态**: 设计确认，分阶段实现 | **最后更新**: 2026-06-18

---

## 1. 全景：四种扫描方式

| 方式 | 模型 | 状态 |
|------|------|------|
| ① 手动单镜像 | 中心拉取 + trivy | 已有(端点在) |
| ② 集群跑中工作负载 | in-cluster trivy-operator(不重拉) | 已做 |
| ③ Registry 仓库批量 | 中心拉取 + trivy | 本设计 |
| ④ CI/CD 构建期门禁 | 中心拉取 + trivy（外部调用） | 本设计 |
| ⑥ 定时重扫 | 调度 → 中心拉取 | 本设计 |

①③④⑥ 都属「中心拉取」：没有目标集群可放 operator，必须由平台侧拉镜像 + trivy 扫。

---

## 2. 架构：独立 scanner 服务（决策 B）

trivy 引擎**不放 manager**（避免压控制面 + 安装脆弱），独立成微服务 `mxcwpp-scanner`：

```
manager (enqueue)                      scanner worker(s)  [trivy]
   │ 写 scan_jobs(pending)                │ 轮询认领 pending job
   ▼                                      │ 拉镜像 + trivy 扫
 MySQL scan_jobs  ◄─────────────────────┤ 写 image_scans/image_vulnerabilities
   ▲                                      │ 标记 done/failed
   └─ manager 读结果 → 前端                ▼
```

- **解耦总线 = DB 任务队列**（`scan_jobs` 表），与平台现有 task_scheduler(DB+Redis 锁) 一致风格。
- scanner 可多副本水平扩，各自原子认领 job（`UPDATE ... WHERE status='pending' LIMIT 1` + Redis 锁兜底）。
- scanner 容器自带 trivy；trivy DB(OCI)首次/周期自动拉取。
- manager 不跑 trivy，只编排 + 展示。

### scan_jobs 表
`id, type(image/registry_image), image, registry_id, source(manual/registry/ci/scheduled), cluster_id?, status(pending/running/done/failed), result_scan_id, error, attempt, claimed_by, claimed_at, created_at, updated_at`

---

## 3. ③ Registry 仓库接入

- 模型 `ImageRegistry`(已有) + `ScanRegistry`(列 catalog 已有)。
- **认证补全**：新增 `type`(basic/gcr/gar/acr)；
  - basic → user/pass（Harbor/Docker，已有）
  - gcr/gar → SA JSON（注入 `GOOGLE_APPLICATION_CREDENTIALS`）
  - acr → SP（user=appId, pass=secret，basic 即可）
- 流程：扫仓库 → 列镜像 → **逐镜像 enqueue scan_jobs(source=registry)** → scanner 消费。
- 前端：仓库管理页（增删改 + 凭证 + 类型）+ 触发扫描 + 镜像扫描页按 source/registry 筛选。

## 4. ⑥ 定时重扫

- `RescanPolicy` 表：`id, scope(registry/all), registry_id?, cron_expr, enabled, last_run_at, next_run_at`。
- 复用 `ScanScheduler`(robfig/cron)：到点 → enqueue（registry 全扫 / 存量镜像重扫）。
- trivy DB 更新后重扫捕获新披露 CVE（scanner 扫时 DB 已是最新）。
- 集群镜像重扫由 operator 自身周期(24h) + 我们每 5min Pull 兜底覆盖，不在此调度。

## 5. ④ CI/CD 门禁

- **API Token 子系统**（CI 非交互，不能走 JWT 验证码）：
  - `api_tokens` 表：`id, name, token_hash(sha256), prefix, scopes, expires_at, last_used_at, created_by, revoked`
  - token 形如 `mxsk_<random>`；中间件识别前缀 → 查 hash → 注入 scope 身份（与 JWT 中间件并列）
  - 管理 UI：签发(只显一次)/吊销/列表
- **同步扫描 API**：`POST /api/v1/images/scan/sync { image, fail_on }`（API Token 鉴权）→ enqueue + 等待结果（轮询/超时）→ 返回 `{ scan, criticalCnt, highCnt, passed }`
- **门禁阈值** `fail_on`: e.g. `critical>=1` 或 `high>=5`；passed=false 时 CLI 非零退出。
- **CLI**（或文档化 curl）：`mxcwpp-scan --image X --fail-on critical --token mxsk_...` → 调 API → exit code 卡构建。

---

## 6. 分阶段实现

| 阶段 | 内容 |
|------|------|
| **S1** | scan_jobs 模型 + scanner 服务(cmd/server/scanner, trivy, 轮询认领→扫→落库) + manager enqueue 基础 + compose 接入 |
| **S2** | ③ Registry：认证补全 + 扫仓库 enqueue + 前端仓库管理 UI |
| **S3** | ⑥ RescanPolicy + cron 调度入队 |
| **S4** | ④ API Token 子系统 + 同步扫描 API + CLI/阈值门禁 |

每阶段：fmt/lint/test → 验证 → 提交。S1 是地基，先做。

---

## 6.5 漏洞数据架构：引擎分开，数据层富化（不为统一而统一）

容器(镜像)漏洞与 Linux(host)漏洞**本质不同**，匹配引擎**保持独立**，只在数据/富化层统一：

| | Host(Linux) | 镜像 |
|---|---|---|
| 来源 | agent 采集已装 OS 包 | trivy 解层：OS 包 + 语言依赖(npm/pip/maven/go...) |
| 范围 | 基本只 OS 包 | OS 包 + **应用语言生态依赖** |
| 匹配引擎 | **vulnsync**(含信创/CNNVD) | **trivy + trivy-db**(Aqua 在镜像/语言生态最强) |

**决策**：
- **不做"统一匹配"**（不把镜像匹配搬到 vulnsync）——会重造 trivy 多年打磨的镜像匹配轮子、高概率覆盖率更差、拖垮镜像扫描质量。各用所长。
- **统一只在富化/数据层**：scanner 落库时把镜像 CVE 按 `cve_id` **交叉关联到 `vulnerabilities` 表**(VulnID)，叠加 EPSS/KEV/CNNVD/信创/confidence。UI 对 host/镜像漏洞呈现一致富化数据。
- vulnsync 组件角色：host 匹配引擎 + **全局漏洞富化权威** +（air-gap 可选）托管 trivy-db OCI 分发，让 scanner 从私有 registry 拉 trivy-db。

> trivy-db：1.1GB OCI artifact，scanner 容器本地缓存(`/root/.cache/trivy`，持久卷)，默认源 `mirror.gcr.io/aquasec/trivy-db`，~24h 自动更新。air-gap 需镜像到私有 registry + `--db-repository` 配置。

## 7. 安全 / 运维
- API Token 仅存 hash，明文只签发时显示一次；支持吊销 + 过期。
- scanner 与 manager 同 DB；scanner 无需对外端口（纯 DB 队列消费）。
- registry 凭证 KMS 加密存储（复用 ImageRegistry 现有加密）。
- 扫描并发/超时可配；job 失败重试上限 + 死信。
</content>
