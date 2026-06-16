# mxsec v2.0 进度（核实版）

**最后更新**: 2026-06-16
**口径**: 逐行对**实际代码**核实（9 模块并行审计），不信文档自述。本文件为**唯一事实源**，取代 `v2-todo-progress.md`。
**按业务系统逐套收口看 [systems-catalog.md](systems-catalog.md)**（本文件是架构分层视图，catalog 是系统视图，数据同源）。

## 图例（按"能不能跑"分级）

- ✅ **可用** — 代码完整 + 已接线 + 可端到端跑（部分有测试）
- 🟢 **完整未验证** — 代码全 + 已接线，但无测试 / 未实跑
- ⚪ **已实现未接线** — 代码完整但**零调用方 / 零路由 / 未注入 pipeline** → 编译过，运行时永远跑不到。⚠️ **v2 最大隐患，商业级不可交付**
- 🟡 **部分** — 接口在，实现缺一截，或数量未达标
- 🔴 **stub / 占位 / 仅设计**
- ❌ **不存在**
- ✂️ **已决策不做**（多租户相关，停止演进）

---

## ⚠️ 关键风险：已实现未接线清单（最该先收口）

这些代码写完了、能编译，但没有任何调用方/路由/pipeline 注入，运行时不会被触发。"看起来完成"但实际跑不到：

| 模块 | 项 | 位置 | 缺口 |
|---|---|---|---|
| M2 | Agent 主进程级隔离箱 | `internal/agent/edr/quarantine/` | `NewManager` 全仓零调用 |
| M2 | Anti-Rootkit Scanner | `internal/agent/edr/rootkit/` | 未注入 edr engine，不产 3006 事件 |
| M2 | 新版 fanotify Watcher | `internal/agent/edr/fanotify/` | 未被 collector 引用（collector 用简版） |
| M3 | 9 个检测 stage | `engine/stage_{anomaly,kube,ml,intrusion,abnormal_login,webshell,revshell_priv,rootkit,honeypot}.go` | 生产 pipeline 只注入 6 个（`cmd/server/engine/main.go`），这 9 个没注入 |
| M4 | 微隔离整包 Phase1/2/3 | `engine/microseg/` | 零路由零调用方 |
| M4 | imagescan secret/dockerfile/license | `manager/biz/imagescan/` | 零 import（仅 CVE 走 image_scanner.go 真实接入） |
| M4 | Admission Webhook Handler | `manager/api/admission/` | Handler 未注册到 router |
| M5/M7 | NPatch + privilege eBPF | `agent/edr/npatch/bpf/*.c`、`collector/bpf/privilege.c` | C 源真实但**未生成 bindings/.o，未加载**（M5 跑 afpacket，M7 卡 go generate） |
| M8 | quarantine.Manager / honeypot.Service | `agent/edr/quarantine/`、`manager/biz/honeypot/` | dead code，无调用方 |
| M9 | billing 3 worker | `manager/biz/billing/` | 未接线启动 |

**另一类断裂**：M8 **restore 全链路断**（插件 engine / Server engine / antivirus 下发三处都无 restore 分支 → "还原"只改 Server DB，Agent 上隔离文件永不还原 → EICAR 端到端闭环必失败）。

---

## ✂️ 多租户：已决策不做（一企业一租户）

tenant 层已侵入 **108 个 model** 的 scope + 全查询，硬拆成本高 → **冻结保留、停止演进**，不投入高级特性：

- 多租户骨架（保留，冻结）— `internal/server/common/tenant/`
- MSSP 多 Region + 父子租户（代码已有，冻结/重评）— `manager/biz/mssp/`、`manager/biz/federation/`
- 100 租户压测 — 砍（单租户 5w 主机性能目标可保留）
- mxctl 多 Region 智能调度 — 砍
- 计费引擎 + Quota + 月账单（代码已有但未接线）— 冻结/重评（属 SaaS 计费）
- Kafka topic 租户化 — 砍

---

## 数字订正（文档旧值 → 实测）

| 项 | 旧标 | 实测 |
|---|---|---|
| ATT&CK 规则 | 119 | **257**（`configs/rules/builtin-rules.yaml`） |
| 基线规则总数 | 390 | **450**（生产集，排除 examples/intl） |
| RASP DataType 段 | 4100-4109 | **4000-4099** |
| EDR eBPF 事件 | "8 类型" | 4 大类 / 9 内核 subtype，无独立 DNS hook |
| 漏洞扫描状态机 | "6 态" | **4 态**（pending/running/success/failed） |
| Advisory 解析器 | 17 | **11**（信创 4 个还是 stub） |
| VulnSync 源 | 15 | 15 个 Name() 但 OSV/CNNVD 占位，实际可用 ~13 |
| 生产 pipeline stage | "13" | **6** 注入（文件 16 个） |
| CIS Docker / K8s | 30 / 60 | 29 / 61 |

---

## 模块状态（核实后）

### 模块 1: Server 微服务架构
- ✅/🟢: 6 微服务骨架、API v1/v2 并存、AuditLog、KMS 信封加密、KubeConfig/GCP 加密、Helm chart、Redis Sentinel(代码支持默认关)
- 🟢(原 ❌，已落地): 配置中心审批工作流(API+Worker+UI)、Canary v2(分批+自动回滚)、5 外发连接器、计费/Quota/月账单、计量上报、OpenAPI+Go/Py/Java SDK、MSSP 父子租户
- 🟡: OTel(**仅 engine 1/6 服务，非"全链路"**)、多租户骨架(✂️冻结)、灾备脚本(未实跑)、viper(仅 engine 接入，其余 5 服务未接、热重载未挂)
- ❌ backlog: Kafka 租户化✂️、MySQL GTID、MirrorMaker✂️、容量推荐引擎、异地灾备演练

### 模块 2: Agent 端
- ✅: eBPF 进程/网络/文件采集(bindings 齐)、SelfProtect(DUMPABLE/NNP/PTRACE/ELF SHA，**已集成 main.go**)、Watchdog 双进程互保(**已集成**)、/metrics:9101
- 🟢: EDR 内核、心跳配置下发、av-scanner、多架构构建(含 loong64)、garble+UPX 脚本
- ⚪: 隔离箱、Anti-Rootkit Scanner、新 fanotify(见上风险清单)
- 🟡: Java RASP(premain jar 非 .so)、CPU/内存 3 档降级
- 🔴/❌: privilege.c bindings 未生成、Windows/AIX/非root、DMI 指纹、离线探测

### 模块 3: 检测引擎
- ✅(已注入生产 pipeline): CEL、Sequence、Storyline、Falco/Sigma 导入、RASP Java、DataType 3005/3006/RASP stage 接入、容器逃逸 T1611
- ⚪(代码全但生产 pipeline 没注入): Anomaly、KubeAudit、ML、入侵六件套、Honeypot
- 🟢(原 ❌，已落地): STIX/TAXII 客户端、SOAR Playbook、**Agent 端自动响应真实下发**(SOAR→AC gRPC→Agent SIGKILL/quarantine 完整链路)
- 🟡/❌: ATT&CK 257 条(超 200，但无红队评估)、≥10k EPS benchmark 无达标证据、namespace BDE、Storyline→IOC、多源情报自动入库

### 模块 4: K8s / 容器
- ✅: KubeAudit Stage、K8s 基线(3122 行 + 路由 + 测试)、PSS(3 profile)、容器逃逸 T1611、CVE 镜像扫描(Trivy)
- ⚪: 微隔离 Phase1/2/3、imagescan secret/dockerfile/license、Admission Handler(见风险清单)
- 🟢: Helm server+agent chart
- 🟡: Docker CIS 29 条、K8s CIS 61 条(目标 120)、License 扫描、KMS+KubeConfig 集成
- ❌: 镜像 Webshell YARA、自研补丁库、CI 三 plugin、短生命周期 Pod 指纹、hubble 自动应用

### 模块 5: 漏洞模块
- ✅: 定向扫描+reconcile、修复闭环 RemediationTask、EPSS、弱口令检测器(真实非占位)、漏洞-主机-包关联、SBOM CycloneDX(原 ❌ 实已做)
- 🟡: VulnSync(OSV/CNNVD 占位)、信创 4 源(sources 真/advisory stub)、NPatch 30 规则(元数据，跑 afpacket)、PoC 框架(29 条非 50)、风险大盘(偏薄)
- 🔴: 扫描状态机(实 4 态非 6)、NPatch eBPF(17 C 源未接线加载)
- ❌: NPatch 延迟 benchmark、灰度修复 1k 主机实测、漏洞-进程动态关联、弱口令库 10w(实 770)、NPatch hot-reload/UI

### 模块 6: 基线 / 合规
- ✅: Baseline 引擎(10 checker)、file_line_expr、K8s 80 func 检查、并发 worker 池、任务调度
- 🟢: 各规则集(等保 RHEL40/Ubuntu30、CIS-RHEL40、中间件50、Windows30、信创60、K8s61) — 原 ❌ 多项实已落地
- 🔴(✅虚高，实不存在): **主机基线 CEL Checker**、**修复 pre/verify/rollback 字段**(只有 command+重启)、弱口令 detector(空占位)
- ❌(✅虚高): **等保 docx 导出**(只有 md/excel/pdf)
- 🟡: 中间件 110 条(目标 160，缺 RabbitMQ)、数据库基线(缺 DB2)、K8s 目标 120 实 61
- ❌: 修复完整链、CSV/Word/趋势图导出、差异扫描 last_status、5000 台性能验收

### 模块 7: 运行时 EDR
- ✅: Storyline、Mode Resolver 4 级、6 闸门(G4 回放占位)、DegradationLevel 0-3、Watchdog、SelfProtect、privilege/rootkit **Server 端 stage 已接 pipeline**
- 🟢: ELFIntegrityMonitor、privilege.c BPF 源、3005/3006 常量、Python audit hook(原 ❌ 实已注册)、Anti-LD_PRELOAD(未主动调)
- 🟡: IForest 真(MLStage 未实例化、ONNX 仅注释)、RASP(PHP 纯 SDK 无 Zend ext、Java premain jar)、Node RASP(JS SDK)
- ❌: privilege bindings/.o 未生成、PrivilegeCollector 不存在、Anti-Rootkit scanner 未 wire(不产 3006)、零真实响应下发(全 alert_only)、反 dump(MADV_DONTDUMP/THP_DISABLE 全缺)、kallsyms 内核校验、三档订阅、性能验收

### 模块 8: 病毒 / 反勒索
- ✅: avscanner 诱饵+inotify(唯一真接线的反勒索)
- 🟢: scanner 插件(clamscan/YARA，无测试)、clamd socket、EICAR 自检、freshclam 分发(在跑，SLA 4h≠10min)
- ⚪/🟡: 插件级 quarantine(无加密无 restore)、Agent 主进程级 quarantine(dead)、honeypot Policy+12 白名单(dead)、Server↔Agent quarantine 集成(下发真但 **restore 断**)、UI 隔离箱(restore/delete 通，无 analyze)
- 🔴/❌: 三档扫描(custom 名不副实)、EICAR 端到端闭环(restore 断必失败)、avscanner fanotify(skeleton)、YARA 勒索家族规则(几乎为零，WebShell 38 条)
- **死代码/坏页**: `ui/.../VirusScan/Quarantine.vue` 调未注册端点(404)，应删；三套反勒索诱饵并存互不引用

### 模块 9: 多租户 / 配置 / 部署 / CI
- ✅: mxctl 部署、AutoMigrate(advisory lock 防死锁，108 model)、viper(engine)、build.sh xc 信创全栈
- 🟢(原 ❌，已落地): 配置中心(API+Worker+UI，worker 已启动)、OpenAPI(68 路径)、Helm 端到端 chart、Docker Compose v2(7 服务)
- 🟡: Go/Py/Java SDK(各 ~200 行未发布)、systemd+KMS(KMS 完整，app unit 缺 EnvironmentFile 注入 KEK)
- ✂️: 多租户骨架(冻结)、100 租户压测、多 Region 调度、计费引擎(孤立骨架)
- ❌: 信创 OS 4 内核实测(只有交叉编译能力)

---

## 进度推进规则

1. 每完成一项 → 本文档对应状态升级 + commit；状态以**代码实测**为准（接线了才算"可用"）
2. ⚪ 已实现未接线项是收口优先级最高的——把"写了"变"能跑"
3. PR 标题前缀对应模块编号：`feat(M1-1c)` / `feat(M5-3)`
4. 多租户(✂️)项不再投入，新需求按"一企业一租户"重评
