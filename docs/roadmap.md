# 路线图与交付状态

> **这份文档是交付状态的唯一权威来源。** 与代码或其它文档冲突时以本文档为准，
> 并当场修正落后的那一份。
>
> 最后核实：2026-08-04
>
> 本仓库公开。涉及具体部署环境的迁移步骤、主机规模与运维细节不在此文档，
> 留在 `local-reports/`（不入库）。
>
> 接手开发前请先读 `local-reports/session-handoff-20260804.md`——
> 那里有禁区清单（哪些同名包不能删）、接线新检测的停止条件，以及环境与工具坑。

---

## 一、平台规模（实测，非估算）

| 维度 | 数量 |
|------|------|
| 后端服务 | 7（manager / agentcenter / consumer / engine / vulnsync / llmproxy / scanner）|
| 检测能力（Stage）| 14 定义，**11 已接线，2 缺输入，1 未接线** |
| Agent 插件 | 12 |
| 前端页面 | 83 |
| 基线策略 | 30 个 / 614 条规则 |
| 内置 CEL 检测规则 | 259 |

> 「未接线」= 有构造器但从未接入流水线。清单见 `internal/server/engine/capability.go`，
> 有 `make test` 门禁校验清单与代码一致。**不要按未接线的代码去理解线上行为。**

## 二、能力交付状态

平台已交付的能力域：

- Linux 基线合规（等保 2.0 三级 / CIS）、中间件基线、K8s 容器基线
- 漏洞管理（情报同步 / 匹配 / 修复下发 / 陈旧核对）
- EDR 事件采集与 CEL 检测、行为基线引擎（BDE）
- FIM 文件完整性、资产采集、报表与 PDF 导出
- RBAC（action 级 + 自定义角色）、安全审计
- 事件运营闭环（Case 生命周期 / 值班表 / 处置审批与回滚）
- 检测工程（规则生命周期、标注语料回放）
- ML 异常检测（分档治理，见 §五）
- SOC 态势感知大屏

各能力的接线状态以 `internal/server/engine/capability.go` 为准，有 `make test` 门禁校验。

---

## 三、进行中 / 未完成

### 5.1 ML 治理（约 70%）

已做：漂移与投毒防护、精确率口径（仅人工研判）、升档门槛、模型持久化与版本回滚、
`ranking` 档、按主机配额训练采样、阈值可配。

**未做（4 项，全部卡在同一个前提：缺标注的主机指标时序语料）**：

- 攻击回放标注
- 时间切分验证（train/test 按时间分割）
- recall 测量
- PR / F1 曲线

> 这四项**不要用其它数据凑**。检测规则那套回放语料是进程/文件事件，
> 不覆盖主机指标时序；拿它充数只会得到一个看起来有 recall 的假数字。

### 5.2 检测工程

标注语料目前 21 样本 / 8 个 ATT&CK 技术，覆盖面偏小。
回放只覆盖 CEL 规则，未覆盖 sequence / IOC / 行为引擎。

`UncoveredTechniques()` 已接门禁（2026-08-04）：清单在
`internal/server/engine/celengine/replay/testdata/required_techniques.json`，
列的是**今天确实被语料覆盖**的 8 项技术。删语料、改标注、或规则改到某类技术
不再被测到，`TestRequiredTechniquesRemainCovered` 会失败。
清单里不写还没覆盖的技术——长期红的门禁等于没有门禁。

**已知覆盖缺口**（是「没测过」，不是「测过没问题」）：

| 技术 | 现状 |
|------|------|
| T1548.003 Sudo 提权滥用 | `priv_escalation` 检测器覆盖，**回放语料没有样本** |
| T1078 Valid Accounts | `abnormal_login` 覆盖，语料无样本；且它按主机画像判，不适合进 CEL 回放 |
| T1014 Rootkit / T1574.006 LD_PRELOAD | `rootkit` 检测器覆盖，语料无样本 |
| T1046 网络服务发现 | `port_scan` 覆盖（需 Redis 聚合），语料无样本 |
| T1105 下载即执行（curl/wget 管道到 shell）| **无检测、无语料** |
| T1562.001 关闭安全工具 | **无检测、无语料** |
| T1136.001 创建本地账号 | **无检测、无语料** |
| T1486 勒索加密 | **无检测、无语料** |

前四行补的是语料（检测已有，只是没被回放测到）；后四行要先有规则。
两者都卡在同一个前提：得有人逐技术标注样本（见 §六「需前置条件」）。

### 5.3 未接线代码

2026-08-03 清理了一批：删掉 `engine/honeypot`（空 Detector，对 7020-7029 段事件
无条件产 critical 告警，接上即刷屏）、`stage_kube`（永远返回 nil alerts 的旁路）、
`engine/ml` 与 `stage_ml`（与在跑的 `engine/anomaly` 重复）、`engine/scheduler`
（零调用方，实际跑的是 `agentcenter/scheduler`）、`stage_audit` 与 `manager/biz/audit`
（死生产者-死消费者配对；在跑的是 `internal/server/audit`）。

2026-08-13 `storyline` 转为未接线。engine 曾装配 `StorylineStage`，但从不调
`StartFlush`——事件只堆在内存 map 里（上限 10000 story × 500 待刷事件），永不落库、
不产 Alert、不推 Kafka，纯占内存。攻击故事线的聚合与落库一直由 consumer 进程独占，
那里才有 `SetClickHouse` + `SetEventsTarget` + `StartFlush` 的完整接线。
重新接线前必须先解决双写与写入目标路由。

2026-08-20 更正：`abnormal_login` 与 `brute_force` 已改标 `starved`——Stage 确实接进了
流水线，但它们读的 `fields["log_msg"]` 在全系统没有任何生产者（agent 侧无日志采集，
事件面只有 eBPF 的进程/文件/网络/DNS 四类），因此 `Ingest` 永不执行，
`host_login_profile_states` 恒空，三个 learning/graduated/suppressed 指标恒为 0，
上线至今零告警。恢复它需要新增日志采集管道（agent 采集 + DataType + consumer 路由），
属新增能力而非修复。以下是当初接线时的记录，其中"阻塞已解除"的判断只对流水线一侧成立：

2026-08-04 接线 `abnormal_login`，Stage 侧不再有未接线项。它的两个阻塞都已解除：
冷启动刷屏由每主机学习期治住（默认 7 天且 ≥10 次登录，两个条件都满足才退出），
画像落 `host_login_profile_states`（启动恢复 + 5 分钟 checkpoint），重启后学习期不重来。
学习期是静默的，`mxcwpp_engine_abnormal_login_hosts_learning / _hosts_graduated /
_suppressed_total` 三个指标一并导出，并配了「8 天无一台毕业」的告警——
否则「一切正常」和「检测没生效」在告警面上都是零条。
接线同时收窄了事件面：`pam_unix(sudo:session)` / `(cron:session)` 等本地会话不再当登录，
它们的量比真实登录高几个数量级，会让主机靠噪声凑够样本毕业。

2026-08-04 删掉 `biz/mlmodel` 与 `model/ml_model.go` 的 3 张表：它分发的是 ONNX/TFLite
模型文件，而全仓库没有任何东西能加载——agent、plugins、server 都没有推理运行时，
go.mod 也没有相关依赖，proto 里没有 manifest 字段，agent 侧没有下载器。
「接线」实际要先造 agent 推理运行时（CGO + 跨发行版编译），分发是那之后的最后一环，
不是接一条路由的事。真做 agent 侧推理时按那时的接口重写这 253 行，比现在养着它便宜。
`ml_model_specs` / `ml_model_subscriptions` / `ml_model_deployment_status` 三张表
在已部署环境里留着（零路由，必为空），不做 DROP。

2026-09-03 蜜罐（C1）改标未接线，社区反馈发现。三段链路全断：

- **agent 侧**：`internal/agent/edr/honeypot`（SSH/HTTP 假回应监听器，296 行）与
  `internal/agent/edr/canary`（诱饵文件哈希巡检）都是零 importer，agent 任何入口
  都不构造它们，端口从未监听过——所以"扫蜜罐端口没告警"不是告警缺失，是没端口。
- **事件面**：文件诱饵另有一套在 `plugins/avscanner`，插件内接线完整
  （`NewHoneypotManager` → `Deploy` → `Run` → DataType 7020 上报），但 consumer
  router 没有 7020 分支，事件进 DLQ；对应的 `engine/honeypot` Detector 已于
  2026-08-03 因"无条件产 critical"删除，两头都没了。
- **server 侧**：`api/honeypot.go` 的 events 查 `alerts.source='honeypot'`，全系统
  无生产者，恒空；sensors 聚合 `HoneypotDeploymentRecord`，写入口
  `biz/honeypot.RecordDeployment` 零调用方（agent 没有回报端点），`CreateSensor`
  只写一条 DB 记录，不下发任何命令。

README 两份已从 :white_check_mark: 改标 :construction:。恢复需要五件事，缺一不可：
agent 装配 + 配置开关（默认关，绑定端口是攻击面）、7020 路由与告警分级
（原 Detector 无条件 critical 正是它被删的原因）、部署回报端点、以及端到端验证
（判据是有 alert 产出，不是端口 listen）。

2026-09-03 把"有没有接线"变成构建期能看见的事实。上一条蜜罐是社区反馈才发现的，
说明靠人读代码找不出这类缺陷，于是改成机器查：`TestNoUndeclaredUnwiredPackages`
以 linux 视角枚举全部包，`internal/` 与 `pkg/` 下没有任何导入者的包必须登记在
`internal/deploy/testdata/unwired-packages.tsv` 并写明原因，否则构建失败；
已经接线却还留在清单里的同样失败，防止清单慢慢失真。

首次扫描得 38 个零导入包，其中已能定性的：

- `manager/init` 与 `manager/setup` 是同名同签名的两份 `Initialize`，manager 实际
  走后者。这正是 AC 两个同步调度器静默缺失数月的同一种形状——改错文件不会有任何
  报错。待删除。
- `manager/handler` 的 GraphQL endpoint 从未在 router 注册，它与依赖的 `biz/graphql`
  一并悬空。
- `pkg/util/worker`（A10 审计修复引入的统一 RunLoop）与 `pkg/util/strutil` 无任何引用。
- `llmproxy/{quota,cache,audit}` 属服务骨架未完成（`Version 0.1.0-skeleton`）；
  在 quota 接入之前，LLM 调用没有花费上限。
- `common/mode/gate`（observe→protect 的 6 门槛准入）是**有意**未接线：切换入口随
  多租户管理面一并移除，只余 GET 查询。

其余 27 个（`edr/{clamav,elfparse,fanotify,forensics,lsm,npatch,quarantine,rootkit,weakpass}`、
`biz/{sbom,soar,hunting,imagescan,npatch,pocvalidation}`、`engine/{adaudit,microseg,rollout,ruleimport,replay}`
等）尚未定性，清单里标为"待确认：接线或删除"。**上一条里"biz 层仅剩
`biz/honeypot.RecordDeployment` 这一处"的说法据此作废**——biz 下共有 7 个零导入包。

同日补了三处测试盲区，并在其中一处查出真缺陷：

- `internal/common/compressor`（gRPC Snappy 压缩，agent↔server 全量流量经过它）
  把 `sync.Pool` 的归还标记放在被复用的对象上。读到 EOF 之后再读一次——`io.Reader`
  允许的调用序列——会二次入池，同一个 reader 被两个流取走，各自 `Reset` 到不同数据源；
  写入侧重复 `Close` 同理。现改为一次性句柄借用池中对象，归还且仅归还一次。
  5 个用例含 `-race` 并发还原校验。
- `internal/common/signing`（Ed25519）与 agent 的 `verifySignature`：插件二进制执行前
  的唯一关卡，放行一次伪造签名等于全机群任意代码执行。补了篡改、异己密钥、空签名与
  八种畸形输入的拒绝用例。
- `TestProductionBuildRequiresSigningKey` 钉住 `scripts/build.sh` 的构建期闸门：
  公钥为空时 `verifySignature` 会跳过整道校验且只留一条 Warn，这条 fail-open 分支
  可以接受的唯一理由就是生产构建缺 `SIGN_PUBLIC_KEY` 时直接失败。

---

## 四、未经验证的部分

**不要把下列内容当成已验证。**

| 项 | 状态 |
|----|------|
| Agent 装机链路（`install.sh` → systemd → 真机启动）| **从未在真实 Linux 机器验证**。只有单测 |
| Kafka → detector 事件通路 | 本地容器网络限制，未跑通 |
| 前端交互行为 | 只验了页面可加载、接口字段匹配、i18n key 存在；**没有浏览器实际点击验证** |
| ML recall | 完全没有测量（见 §5.1）|

---

## 五、目录与文档规范

### 目录约定

| 目录 | 用途 |
|------|------|
| `cmd/` | 各服务与工具入口，一个子目录一个二进制 |
| `internal/agent/` | Agent 侧代码 |
| `internal/server/` | 服务端，按服务再分子包 |
| `internal/common/` | 跨端共享库 |
| `internal/deploy/` | 部署产物与**门禁测试**（路由清单、告警覆盖、文档同步等）|
| `plugins/` | Agent 插件，每个可独立编译 |
| `web/` | 前端（Next.js）。**没有 `ui/`**——Vue 版已下线 |
| `deploy/` | 编排、配置模板、证书与部署脚本 |
| `docs/` | 对外文档，受门禁校验 |
| `local-reports/` | 本地评估报告，**gitignore，不入库** |

不入库的：`.scratch/`、`.superpowers/`、`local-reports/`、
`*.bck.yml`（golangci migrate 的备份，旧配置在 git 历史里可回溯）。

### 文档与代码同步

改动与文档的对应关系见 [CLAUDE.md · 文档实时同步](../CLAUDE.md)。
其中有门禁的部分由 `internal/deploy/docs_sync_test.go` 在 `go test` 中强制：

| 门禁 | 拦什么 |
|------|--------|
| `TestDocLinksResolve` | 文档里指向仓库内但不存在的路径 |
| `TestRoadmapNumbersMatchReality` | 本文档的规模数字与代码实际不符 |
| `TestArchitectureDocCoversAllServices` | 新增服务未写进架构文档 / CLAUDE.md |
| `TestConfigKeysDocumented` | 配置模板里的节未写进配置文档 |
| `TestBaselinePolicyCountMatchesDoc` | 基线策略数量与 README 声明不符 |
| `TestClaudeMdReferencesExist` | CLAUDE.md 引用了不存在的文档 |
| `TestRoadmapExistsAndIsDated` | 本文档缺失或没有核实日期 |

这些门禁跑在 `make test` 里。提交前必须跑——
门禁只有在有人真去跑、且失败时不放行，才起作用。

## 六、待办清单（backlog）

> 标「需前置条件」的，等的不是工时。

### 需决策

| 项 | 说明 |
|----|------|
| agent 侧 ML 推理 | 目前没有任何推理运行时（agent / plugins / server 皆无，go.mod 无依赖）。要做的是运行时本身，模型分发是它之后的事——`biz/mlmodel` 已按此删除，见 §5.3 |

### 需前置条件

| 项 | 卡在哪 |
|----|--------|
| ML recall / 时间切分 / PR·F1 / 攻击回放标注 | **缺标注的主机指标时序语料**。要人去标数据，不是写代码 |
| 检测语料扩充 | 当前 21 样本 / 8 技术。缺口清单已列在 §5.2，逐技术标注要人做 |

### 需要真实环境

| 项 | 说明 |
|----|------|
| Agent 装机链路验证 | 需真实 Linux 靶机走完 `install.sh` → systemd → 启动 |
| Kafka → detector 通路 | 本地容器网络限制，未跑通 |
| 前端交互验证 | 已验页面可加载、接口字段匹配、i18n key 齐全；交互行为需浏览器实际点击 |
| `abnormal_login` 真实误报面 | 无从评估：该能力标 `starved`，输入字段无生产者，真实机群零样本。当初"头 7 天全静默"的预期恰好与故障表现一致，掩盖了它从未生效这一事实；语料测试能过是因为测试手工构造了真实环境不存在的字段。待日志采集管道落地后重新评估 |

### 工程债

`UncoveredTechniques()` 未接门禁已于 2026-08-04 接上（见 §5.2）。
以下为 2026-08-27 一次全量告警核验后登记，按投入产出排序。

#### 一、误报治理

一次覆盖全部存量告警的逐条核验显示：告警面几乎全部由误报构成，
且集中在少数几个根因上。以下按「消掉的告警量 ÷ 改动量」排序。

**FP-1　FIM 基线只建不更（占告警面绝大多数，无代码改动无法收敛）**

链路事实：
- 首扫落地本地基线 `plugins/fim/engine/engine.go:53-70` → `baseline.Save`，
  路径 `/var/lib/mxcwpp/fim/baselines/<policy_id>.json`（`baseline.go:14`）
- 后续每轮只读不写：`engine.go:48` 加载，`engine.go:73` 比对，比对分支内**无任何 Save**
- 服务端的 `fim_baselines` / `fim_baseline_entries` 只在首扫快照（DataType 6004）时写入
  （`agentcenter/transfer/service.go:2949`），且**从不回流 Agent**
- 下发基线的 DataType 6003 **只有接收方**（`plugins/fim/main.go:95`），全仓无发送方
- 控制台「确认变更」声明了 `UpdateBaseline bool`（`api/fim_events.go:425-429`）
  但方法体从未读取它（`fim_events.go:432-470`），前端仍在传（`web/src/lib/api/fim.ts:49`）

后果：凡相对首扫快照发生过一次差异的文件，此后每轮扫描永远判 `changed`，
逐日事件集合完全一致。这是 §5 那张「静默失效」清单的又一例——
UI 上有「确认变更」按钮，点了不报错，但基线不动。

方案（三选一，建议 A）：

| 方案 | 改动 | 代价 |
|------|------|------|
| **A. 确认即写回** | 补 6003 发送方；`ConfirmFIMEvent` 读取 `UpdateBaseline`，按确认的 (host, path) 更新 Agent 本地基线 | 中。要打通服务端→Agent 的基线下发链路，但该链路的接收侧已存在 |
| B. Agent 侧自更新 | 每轮扫描后把本轮结果写回本地基线 | 小。但等于放弃"未经确认的变更要持续告警"这一语义，安全上退步 |
| C. 服务端去重 | 对连续多轮相同的 (host, path, hash) 只在首轮产生事件 | 小。治标，事件量不降，只压告警 |

附带缺陷：`engine.go:176` 的 size 比较缺少 hash/mode 那样的「基线侧为空则跳过」保护
（对照 `engine.go:169`、`engine.go:182`），基线条目 size 为 0 时对任何非空文件恒判变更。

验证：连续两轮扫描的事件路径集合应基本不相交（除真实变更）。

**FP-2　scan-detector 的 CIDR 白名单机制已具备但从未使用（零代码）**

`celengine/scan_detector.go:87-112` 已实现从 `alert_whitelists.source_ip_cidr` 加载
可信来源，`scan_detector.go:67-83` 每分钟热加载，命中即 return（`scan_detector.go:141-143`）。
现网白名单记录全是 `exe` 维度，CIDR 维度为空。

方案：把已知的内网扫描器 / 资产测绘源写进 `alert_whitelists.source_ip_cidr`。
**纯配置动作，不需要改代码。** 建议同时在部署文档里写明这一步。

**FP-3　自动调优的四道闸挡掉了绝大多数误报模式**

`manager/scheduler/auto_tuning.go` 每 6 小时按 `(rule_id, exe)` 聚合近 7 天被
resolve/ignore 的告警生成白名单建议。四个过滤条件叠加后覆盖面极窄：

| 闸 | 位置 | 挡掉的模式 |
|----|------|-----------|
| `source = 'detection'` | `auto_tuning.go:65` | FIM 告警完全不进聚合 |
| `severity == "critical"` 跳过 | `auto_tuning.go:82` | 注释理由是"真威胁不应被自动豁免"，但硬编码 critical 的规则失真恰恰落在这里 |
| `exe == ""` 跳过 | `auto_tuning.go:85` | **所有网络类规则**——eBPF 网络事件只有 `comm` 没有 `exe`（`collector/ebpf.go:756-762`），故 `exe` 恒空 |
| `maxRisk >= 70` 跳过 | `auto_tuning.go:118` | 组内一条高分即整组放弃 |

第三道闸是明确的半修缺陷：白名单**匹配**侧已做 `exe` 缺失回落 `comm`
（`celengine/whitelist.go:249-251`），**建议生成**侧没做。

方案：
1. `extractExeBasename` 回落 `comm`，与 whitelist.go 对齐（小，收益最大）
2. critical 与高 risk 的组不要直接丢弃，改为产出「疑似规则失真」建议交人审
   ——保留人审关口即可，不必自动豁免
3. FIM 类告警按 `(rule_id, file_path)` 而非 `(rule_id, exe)` 单独聚合

**FP-4　"外连"类 CEL 规则缺 `event_type` 约束**

`configs/rules/builtin-rules.yaml` 中命名为"外连"的规则只判 `remote_port`，
不判事件方向；而 `tcp_accept` 事件的 `remote_port` 是客户端临时源端口。
入站类规则本身写法是对的（显式 `event_type == "tcp_accept" && local_port == ...`），
出站类照抄即可。

注意：`direction` 字段**未暴露给 CEL**（变量声明 `celengine/engine.go:180-185`、
激活白名单 `engine.go:453` 均不含），规则里写 `direction` 会编译失败。
因此方案是加 `event_type == "tcp_connect" &&` 前缀，而不是引入 `direction` 变量——
改动更小，且与既有入站规则写法一致。

对照：Agent 侧同类规则（`configs/agent-rules/MXEDR-0080/0012/0081/0082`）
写法本就正确（`event_type: tcp_connect` + 私网 CIDR 排除），不需要动。

验证：入站事件不再命中；构造 `tcp_connect` 事件仍命中。

**FP-5　UDP IPv6 分支 remote_addr 解析错误**

`udp_send` 走 IPv6 分支时（`collector/bpf/network.c:296-329`），从 `msg->msg_name`
取出的对端地址被解成 `6000::/3` 段的非法 IPv6（`ffff:ffff` 结尾），真实对端是回环地址。
疑为读取 16 字节地址时的偏移或字节序错误。pid 与端口字段本身正确。

影响：地址错 → 规则里的私网 CIDR 排除失效 → 本机 loopback 通信被判成公网外连。

验证：本机 IPv6 UDP socket 发往回环地址，`remote_addr` 应为回环地址。

**FP-6　文件规则正则未锚定根路径**

`engine/intrusion/rootkit.go:48-51` 的 `/etc/systemd/system/.*\.service` 未锚定开头，
`/tmp/` 下的同名子路径同样命中——内核更新时 dracut 在 `/tmp` 建临时 initramfs 目录，
会全量触发 rootkit/后门告警。同类写法见 `configs/agent-rules/MXEDR-0032`（有尾锚无头锚）。

方案：加 `^` 锚定。改动一行，风险极低。

**FP-7　检测规则缺自身动作豁免**

平台自身的运维动作会触发检测规则：升级时备份 agent 二进制命中攻击链序列规则；
agent 插件访问云厂商元数据服务命中「无文件执行 + 外联」序列规则。

现状是三处各管一段、互不复用：
- `biz/fim_escalation.go:37-50` `fimSelfPaths`——只作用于 FIM 告警层
- `engine/pipeline.go:211-217` `agentSelfExePrefixes`——只按 EDR 事件的 `exe` 过滤
- FIM 采集层无任何自身路径排除（`plugins/fim/engine/scanner.go:174-183` 只吃策略的 exclude）

方案：抽一个公共的自身资产判据（自身二进制路径、插件进程名、安装目录），
在 CEL 求值、序列规则求值、FIM 采集三处统一引用。

**FP-8　缺少 fleet-wide 命中率守卫**

一条规则在同一时间窗内对每台在线主机各命中一次，是规则失真的典型特征，当前无自动降级。

方案：窗口内统计 `命中主机数 ÷ 在线主机数`，超阈值则该规则本轮降级并聚合成单条，
标记「疑似规则失真」。在线主机数可复用检测侧已有的主机快照缓存。

风险：真实的大范围事件（蠕虫、供应链投毒）同样是全量命中。
因此**只能降级 + 聚合，不能丢弃**，且必须保留一条聚合告警。

**FP-9　网络事件上的 `exe` 规则永不命中**

eBPF 网络事件只提供 `comm`，不提供 `exe`（`collector/ebpf.go:756-762`）。
`builtin-rules.yaml` 中若干在网络 data_type 上使用 `exe` 的规则因此恒不命中，
属静默失效（编译通过、运行无错、永远零命中）。白名单侧做了回落，规则侧没有。

方案：要么在网络事件里补 `exe`（需 Agent 侧解析 `/proc/<pid>/exe`），
要么把这些规则改用 `comm`。选后者则需同步修订规则文档中的字段可用性说明。

附带：procfs 降级路径的网络事件 `pid` 恒为 0 且无 `comm`（`collector/procnet.go:128`），
该路径产生的告警无进程归属。

#### 二、其它

| 项 | 缺陷 | 影响 |
|----|------|------|
| celengine 进程树无有效回收 | `进程树定期清理` 每轮回收的节点数远小于同期新增，节点总数单调增长，清理条件形同虚设 | 常驻内存持续膨胀，突破 `GOMEMLIMIT` 后 GC 死亡螺旋表现为 CPU 打满。判据看 `nodes` 是否收敛，不是看 RSS |
| `host_vulnerabilities.resurfaced_at` 未写入 | 状态可以翻成 `resurfaced`，但该时间戳字段始终为 NULL | 无法按时间维度分析复现，只能退回看 `updated_at` |
| 修复回执落 DLQ | agent 上报的修复结果按 `host_vuln_id` 关联，关联不到即整条转 DLQ；同一 `vulnerabilities` 行并发 UPDATE 会触发死锁（`remediation/vuln_patch.go`）| 修复状态对不上账，已修的漏洞可能被判回未修 |

#### 三、蜜罐（C1）接线

2026-09-03 社区反馈发现三段链路全断（断点详见 §5.3）。README 已改标 :construction:，
但能力本身仍欠。恢复要五件事，缺一不可——只做前两件会得到「端口开着但不产告警」，
只做第三件会得到「无条件 critical 刷屏」，都比现状更糟：

| 步骤 | 内容 | 判据 |
|------|------|------|
| 1 | agent 装配 `edr/honeypot`（SSH/HTTP 监听器）与 `edr/canary`（诱饵巡检） | 进程实际 listen，不是编译过 |
| 2 | 配置开关，**默认关**——绑定端口本身是攻击面，且与业务端口可能撞车 | 关时零监听、零资源占用 |
| 3 | consumer 补 DataType 7020 路由 + 告警分级 | 7020 不再进 DLQ；原 `engine/honeypot` 因无条件产 critical 被删，重做必须按命中类型分级 |
| 4 | agent 侧部署回报端点，接上 `biz/honeypot.RecordDeployment` | sensors 列表出真实记录，不再恒空 |
| 5 | 端到端验证 | **判据是有 alert 产出**，不是端口 listen、不是日志无报错 |

文件诱饵那套（`plugins/avscanner` 内）插件侧已完整，卡的只有第 3 步；
网络蜜罐则 1-5 全欠。两者可拆开做，先做文件诱饵成本最低。

### 漏洞情报：跨发行版标签污染（已根治，存量待回填）

CVE 的 `source` 与 `fixed_version` 是 CVE 级塌缩值。合并多来源 advisory 时，
此前只按 confidence 挑赢家，**不看该 advisory 是否匹配到本环境的主机** ——
一条毫不相关的 debian advisory 能把 rpm 主机的修复版本标成 deb 版本，
运维照着修根本修不掉。

已完成：

| 项 | 改动 |
|----|------|
| P0（早先上生产）| 清理侧加覆盖性守卫；修复闸以 precheck 的主机真值为准 |
| **P1 根治** | `mergeByConfidence` 引入覆盖性判据：匹配到主机的 advisory 优先于 confidence 更高但不适用的（`coordinator.go` `betterMetadata`）|
| **P2 展示** | 漏洞详情页的受影响主机表新增「当前版本 / 适用修复版本」两列，取 per-host 的 `matchedFixedVersion` 而非 CVE 级塌缩值 |

**存量数据待回填**：`host_vulnerabilities` 共 15468 行，其中只有 264 行
（1.7%）填了 `matched_fixed_version`。该字段只在 advisory 同步路径写入，
历史行需要重跑一次同步才会补上。在那之前，详情页对多数主机显示「—」——
这是如实的「未知」，好过继续显示一个可能错误的塌缩值。

验证方式：重跑同步回填后，debian 标签挂在 rpm 主机上的链应归零，
详情页对 rpm 主机显示 el9 版本而不是 deb 版本。

> 更彻底的长期方案：`host_vulnerabilities` 落地每主机匹配到的 source 与
> fixed_version（该表已有 current_version），下游全读 per-host 真值，
> 彻底摆脱 CVE 级塌缩。

> 部署与升级相关的前置条件见 `local-reports/roadmap-internal.md`（不入库）。

---

## 七、文档维护约定

- 本文档在**每次任务完成或受阻时**更新，与代码同一个提交。
- 「状态」一栏只写核实过的结论，不写计划或预期。
- 未验证的事情写进 §七，**不要在正文里描述成已完成**。
- 文档链接失效、基线策略数量对不上、CLAUDE.md 引用不存在的文档，
  都会被 `internal/deploy/docs_sync_test.go` 在构建时拦下。
