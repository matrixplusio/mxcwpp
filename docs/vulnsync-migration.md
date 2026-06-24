# VulnSync 解耦迁移计划

**分支**: `kerbos/refactor-vulnsync-decouple`（从 dev）
**目标**: 让 OS advisory 同步严格按 `architecture.md` L154-163 走 —— VulnSync 拉源 → Kafka `mxcwpp.vuln.advisory` → Manager 消费匹配主机漏洞。废弃 manager 进程内 `syncCoreAdvisories` 自拉路径。

---

## 背景：为什么要迁

当前实际运行**偏离文档架构**：

- 文档：VulnSync 拉 11+ 源 + 融合 → Kafka → Manager/Engine 消费匹配。
- 现实：真正产数据（~265 万 advisory_packages + host_vuln）的是 manager 的 `syncCoreAdvisories()` → `advisory.Coordinator`，**进程内自拉 + 匹配 + 写库**，完全绕过 Kafka 和 VulnSync 服务。独立 VulnSync 服务用的是 `vulnsync/sources/` metadata-only 源池（无 fixed_version，redhat 走已 404 Hydra），Engine consumer 是 noop 占位，Manager 不消费 advisory topic。

### 决定性约束：两套源池质量不同

| 源池 | 用途 | 质量 |
|---|---|---|
| `internal/server/vulnsync/advisory/` | manager Coordinator 用 | CSAF/Security-Tracker，**带 NEVRA + fixed_version + OS gate**，能精确版本比对（prod 验证）|
| `internal/server/vulnsync/sources/` | 独立 VulnSync 服务用 | **仅 CVE/severity/CVSS 元数据**，无 fixed_version，无法匹配主机 |

→ 直接切到独立 VulnSync 服务 = host_vuln 匹配归零、全面漏报。必须先把 `advisory/` 高质量源接入 VulnSync。

---

## 已定决策（用户确认）

1. **迁移策略**：直接切，先补源池（不长期双跑灰度）。
2. **源池合并**：`advisory/` 源**下沉到 VulnSync 服务**，废弃 `vulnsync/sources/` metadata-only 那套。
3. **matcher 位置**：留在消费侧（Manager）。主机软件清单在 manager DB，不跨服务 RPC。文档 L160 明确"Manager 消费匹配"。
4. **手动触发**：manager 侧 5 个 advisory 同步 HTTP API 改为**触发 VulnSync 拉取**（不直接删，保留管理员手动同步体验）。

---

## 执行步骤（含验证门）

### S1 — VulnSync 发"可匹配"的富 advisory
- VulnSync scheduler 改用 `advisory/` 高质量源（redhat CSAF / debian / ubuntu / rocky / alpine / osv）替代 `sources/` metadata-only 源。
- 扩 Kafka `Advisory` 消息 schema：带上 `AffectedPkgs`（含 PkgName + FixedVersion + Introduced/LastAffected 范围）+ `OSFamily/OSMajor` gate（即把 `advisory.Advisory` 的匹配关键字段完整序列化进 Kafka，而非现 `sources.Advisory` 的 metadata-only 平铺字段）。
- publisher 发富 advisory。废弃 `vulnsync/sources/` 死源。
- 全史首跑逻辑（stash@{0} 的 `since=time.Time{}`）迁入 VulnSync 拉取。
- **验证门**：VulnSync 跑一轮，抓 Kafka topic 样本 → 富字段非空、覆盖 RHSA/Debian/USN。

### S2 — Manager 加 advisory consumer
- manager 起 Kafka consumer（独立 ConsumerGroup）消费 `mxcwpp.vuln.advisory`。
- 反序列化 → 复用 `advisory/matcher.Match(advisory, host软件清单)` + `cleanup` → 写 `host_vulnerabilities`，幂等。
- **验证门（红线）**：新路径产出的 host_vuln 与旧 `syncCoreAdvisories` 自拉**集合比对等价**。不等价**不允许进 S3**（商业级不漏报）。

### S3 — 拆 manager 自拉路径
- 删 `syncCoreAdvisories`，收敛 **7 个触发入口**的 advisory 段：
  - 定时：TaskScheduler（日 SyncOnly / 周 ScanAll）、ScanScheduler（DB cron）
  - HTTP：`/vulnerabilities/sync`、`/vulnerabilities/scan`、`/vulnerabilities/advisory-sync`、`/vuln-data-sources/:id/sync`、SBOM import
  - 5 个手动 API 改为触发 VulnSync 拉取（决策 4）。
- 保留弱耦合部分：OSV PURL 语言包扫描（`SyncByPURLs`）、威胁情报（KEV/EPSS/ExploitDB）、NVD/MITRE/CNNVD 元数据 enrich。
- **验证门**：`make fmt && make lint && make test` 全过；7 入口无空转。

---

## 关键代码坐标

- VulnSync 入口：`cmd/server/vulnsync/main.go`（registerAll 注册 10 driver，SourceSchedule 硬编码 L126-137）
- VulnSync scheduler：`internal/server/vulnsync/scheduler.go`
- 高质量源池：`internal/server/vulnsync/advisory/`（coordinator.go / matcher.go / source.go / redhat.go 等）
- 富 advisory 类型：`advisory.Advisory`（source.go:36-65，含 AffectedPkgs[]PkgFix + OS gate）
- Kafka topic：`internal/server/common/kafka/topics.go:27`（`mxcwpp.vuln.advisory`，DataType 12001-12099，retention 30d，partition key `source:source_id`）
- 现 Kafka 消息类型：`sources.Advisory`（source.go:30-51，metadata-only，**待扩**）
- publisher：`internal/server/vulnsync/publisher/publisher.go`
- Engine consumer（noop 占位）：`internal/server/engine/consumer.go:197`
- manager 自拉：`internal/server/manager/biz/vuln_scanner.go:680`（syncCoreAdvisories），调用点 L90/L404
- matcher：`internal/server/vulnsync/advisory/matcher.go:24`
- cleanup：`internal/server/vulnsync/advisory/cleanup.go`

## 进度
- [x] 评估 + 决策锁定
- [x] S1 源池补齐 + schema 扩展（wire 契约 advisory/message.go；scheduler/publisher/main 改驱动 advisory.Source；删 sources/ 死源）
- [x] S2 dev：Coordinator.IngestAdvisories（复用 merge/upsert/bulk 写路径）+ manager AdvisoryConsumer（批+主机缓存+cleanup 节流）+ main 接线 + 单测（匹配/跳已修复/幂等）
- [x] S2 红线门工具：`cmd/tools/advisory-replay-verify`（读 advisory_packages 重组富 advisory → IngestAdvisories 写隔离 sqlite → 与真实库 host_vuln 对拍，真库只读）
- [ ] **S2 红线门结论待定**：dev 库**无 OS-advisory host_vuln 基线**（全部 3596 条 host_vuln = OSV/GHSA 语言包路径；OS advisory 路径产 0），且主机全 offline → **无法在 dev 对拍**。
  - replay 工具已验证新路径行为正常：147499 advisory → 48414 vuln / 48333 OS-advisory host_vuln 对，matcher 无异常、wire round-trip 保真、不崩。
  - 真正等价对拍需「有 OS-advisory host_vuln 的环境」→ **建议跑 prod 只读副本**（prod 有真实 RHEL/Debian 主机）。
- [x] S3 拆自拉 + 入口收敛：删 `syncCoreAdvisories`+`loadKnownRHSAAdvisoryIDs`；SyncOnly 去 advisory 自拉段（改 enrich-only）；VulnSync 加 `POST /sync`+`Scheduler.TriggerNow`；advisory-sync API 改 HTTP 触发 VulnSync（`vuln.vulnsync_url` 配置）。build/test/fmt/lint 全过。
  - 实测 7 入口为夸大：真实 OS-advisory 自拉只 1 处（SyncOnly），doScanAll 早已不自拉；其余 API 只做 enrich/OSV，未动。

## 上线前必办（prod 红线对拍）
S3 已删自拉，但 prod 等价对拍尚未跑。**部署前**用 `cmd/tools/advisory-replay-verify -mysql-dsn <prod只读>` 对拍：only_old=0 才放行。

## S2 红线门发现（重要）
dev `host_vulnerabilities` 全部来自 OSV/GHSA 语言包匹配，OS advisory 路径在 dev 产 0 host_vuln（dev 主机是语言包容器，非 RHEL/Debian OS 包）。等价对拍需 prod 只读数据。
代码层等价已由「IngestAdvisories 复用 Sync 同一 merge/upsert/bulk」+ 单测 + replay 规模行为保证。

## S2 范围裁剪（同 S1）
- OSV/语言包路径不动（PURL 驱动，留 manager）。
- enrich（NVD/KEV/EPSS）不动。
- 等价仅针对 OS 厂商 advisory（rhsa/rocky/usn/debian/alpine/centos）产出的 host_vuln。
