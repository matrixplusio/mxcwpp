# mxcwpp 系统目录（按业务系统）

**最后更新**: 2026-06-16
**用途**: 按**功能系统**（非架构分层）归类，供逐系统收口。每系统标：范围 / 入口 / 状态 / 待清理（脏数据·死代码·未接线·未做）。
**配套**: 架构分层进度见 [v2-todo.md](v2-todo.md)；核实方法见 memory。

## 状态图例
✅ 可用（接线+可跑） · 🟢 完整未验证 · ⚪ 已实现未接线（编译过但跑不到） · 🟡 部分 · 🔴 stub · ❌ 无 · ✂️ 已砍

## 收口优先级建议
1. **接线类**（⚪→可跑，性价比最高）：检测引擎 9 stage、容器 microseg/imagescan/admission、漏洞 NPatch/privilege eBPF、病毒 restore
2. **脏数据·死代码清理**：见各系统「待清理」+ 文末汇总
3. **未做 backlog**：按业务优先级排

---

# A. 检测与响应

## 1. EDR 运行时系统
- **范围**: eBPF 采集（进程/网络/文件）、故事线、行为基线、内存马、自保护
- **入口**: UI `EDR` `Storyline` `Anomaly` `BDE` | API `/edr` `/events` `/anomalies` `/storyline` `/bde` | 后端 `agent/edr/collector` `engine/storyline` `engine/anomaly`
- **状态**: ✅ eBPF 采集(bindings 齐)、Storyline、Mode Resolver、6 闸门(G4 回放占位)、DegradationLevel 0-3
- **待清理**:
  - ⚪ Anti-Rootkit Scanner、新 fanotify Watcher 未接线（不产事件）
  - 🟡 ML：IForest 真但 MLStage 未实例化、ONNX 仅注释
  - 🔴 privilege eBPF bindings 未生成（卡 Linux go generate）
  - ❌ 反 dump(MADV_DONTDUMP/THP_DISABLE)、kallsyms 内核校验、三档订阅
  - 数字订正：eBPF 实 4 大类/9 subtype（非"8 类型"）

## 2. FIM 文件完整性系统
- **范围**: 文件基线、变更监控、策略、任务
- **入口**: UI `FIM` | API `/fim` `/fim/baselines` `/fim/policies` `/fim/tasks` `/fim/events` | 后端 `manager/api/fim_*.go` `plugins/fim/`
- **状态**: 后端真实（4 api + 插件 engine）
- **待清理**:
  - 🟡 **fim_events 4 行测试脏数据**（base64 文件名 + 不匹配 watch_paths，UI 显示无害告警）→ 走运维 SQL 清
  - 待核实：插件 engine 完整度、fanotify vs inotify（本系统未深核，列为首批逐系统对象）

## 3. 基线/合规系统
- **范围**: 基线检查引擎 + 规则库（等保/CIS/中间件/Windows/信创）+ 修复
- **入口**: UI `Baseline` `Inspection` | API `/baseline` `/baseline-rules` `/baseline-alerts` `/baseline-score-trend` | 后端 `plugins/baseline/` `manager/biz`(kube_baseline)
- **状态**: ✅ 引擎(10 checker)、file_line_expr、K8s 80 func、并发 worker 池；✅ 规则库**全量入库**(递归加载 config 全树)；✅ 内置/自定义隔离(builtin 字段，启动同步永不覆盖用户规则)；✅ 修复命令全补 + **VM 实测三类基线(系统/应用/通用)安全可自动修规则全生效**
- **入库机制**: 每次启动幂等 upsert(新增 JSON 重启即入库) + reconcile(JSON 移除的内置规则自动删) + 一次性 builtin 回填；删整个策略文件需配 DB 清理(无整策略 reconcile)
- **VM 验证(2026-06-16, rocky9 rhel + ubuntu24, break→fix→rescan 闭环)**:
  - 系统基线: dengbao-rhel 38/40、cis-rhel8 37/40、cis-centos 33/34、dengbao-ubuntu 29/30、cis-ubuntu 23/24
  - 应用/中间件(rocky9 部署真实例): nginx 12/12、postgresql 10/10、mysql 13/14、apache 11/12、tomcat 10/12、redis 8/10、kafka 5/10、mongodb 8/10
  - 通用基线(原 examples, 13 策略): SSH/sysctl/口令/账户/审计/文件权限/服务/cron/横幅/网络/secureboot/SELinux/文件完整性——可自动修全生效
  - 剩余 fail 全为：分区/挂载类(manual)、TLS/SASL/ACL/证书/业务判断/SELinux策略(需 PKI 或集群设置)、故意排除(X卸载/PAM/PasswordAuth 锁死或破坏风险)
- **范围调整**: 砍信创 6 OS + oracle/sqlserver(商业) + intl(PCI/NIST/HIPAA,与cis/dengbao重复)，只做 CentOS/RHEL/Ubuntu/Rocky + 开源中间件；cis/ 独立重写去 Elkeid 衍生(自有 CIS_* 规则组)；examples→general 通用基线
- **待清理**:
  - 🟡 cis-debian(17条)无 debian VM 未验证(ubuntu 主机 os_family≠debian)；apache/tomcat 规则做了 OS 双路径(httpd/apache2)
  - ❌ 等保 docx 导出、5000 台性能验收

## 4. 漏洞管理系统
- **范围**: 漏洞情报同步、扫描、状态机、修复闭环、SBOM、NPatch、PoC
- **入口**: UI `VulnList` `VulnRemediation` `VulnBulletins` `VulnDataSources` | API `/vulnerabilities` `/fix-tasks` `/advisory-sync` | 后端 `vulnsync/` `manager/biz/{npatch,sbom,pocvalidation,remediation}`
- **状态**: ✅ 定向扫描+reconcile、修复闭环 RemediationTask、EPSS、弱口令检测器、漏洞-主机-包关联、SBOM CycloneDX
- **待清理**:
  - 🔴 **扫描状态机实 4 态**（非文档"6 态"）
  - 🔴 NPatch eBPF 17 C 源未生成 bindings/未加载（跑 afpacket）
  - 🟡 VulnSync OSV/CNNVD 占位、信创 advisory 4 源 stub、PoC 框架 29 条(非 50)
  - 数字订正：解析器 11(非 17)、源可用 ~13、弱口令库 770 行(非 10w)
  - ❌ NPatch 延迟 benchmark、灰度修复 1k 实测、NPatch hot-reload/UI

## 5. 病毒/反勒索系统
- **范围**: 文件查杀(clamav/YARA)、隔离箱、诱饵、病毒库分发
- **入口**: UI `Virus` `Whitelist` | API `/antivirus` | 后端 `plugins/scanner` `plugins/avscanner` `agent/edr/quarantine` `manager/biz/honeypot`
- **状态**: ✅ avscanner 诱饵+inotify(唯一真接线)；🟢 clamd socket、EICAR 自检、freshclam 分发(SLA 4h≠10min)
- **待清理**:
  - 🔴 **restore 全链路断**（三处都无 restore 分支 → "还原"只改 Server DB，Agent 文件永不还原 → EICAR 闭环必失败）⚠️ 本系统头号问题
  - ⚪ Agent 主进程级 quarantine、honeypot Policy+白名单 = dead code
  - 🟡 插件级 quarantine 无加密无 restore
  - **死页**: `ui/src/views/VirusScan/{index,Quarantine}.vue`（路由实际指向 `Virus/Quarantine.vue`，VirusScan/ 下文件疑似 404 死页）→ 待删
  - **重复**: 三套反勒索诱饵并存互不引用（avscanner / honeypot / edr canary）
  - 🟡 YARA 勒索家族规则几乎为零（WebShell 38 条）

## 6. 容器/K8s 安全系统
- **范围**: 准入控制、镜像扫描、微隔离、K8s 审计、基线、PSS
- **入口**: UI `Kube` | API `/clusters` `/kube/audit-webhook` | 后端 `engine/kube` `engine/microseg` `manager/biz/imagescan` `manager/api/admission`
- **状态**: ✅ KubeAudit Stage、K8s 基线(3122 行+路由+测试)、PSS、容器逃逸 T1611、CVE 镜像扫描(Trivy)
- **待清理**:
  - ⚪ **微隔离整包 Phase1/2/3**(零路由)、**imagescan secret/dockerfile/license**(零 import)、**Admission Handler**(未注册路由) ⚠️ 三大未接线
  - 🟡 Docker CIS 29、K8s CIS 61(目标 120)
  - ❌ 镜像 Webshell YARA、自研补丁库、CI 三 plugin、hubble 自动应用

## 7. 检测引擎/规则系统
- **范围**: Pipeline、CEL、Sequence、ATT&CK 规则、RASP、入侵检测、Falco/Sigma 导入
- **入口**: UI `Detection` `Policies` `PolicyGroups` | API `/detection-rules` | 后端 `engine/` `engine/celengine` `engine/rasp` `engine/intrusion` `engine/ruleimport`
- **状态**: ✅ 生产 pipeline 注入 **6 stage**(CEL/Sequence/Storyline/Privilege/AntiRootkit/RASP)、Falco/Sigma 导入；ATT&CK **257 条**(订正自 119)
- **待清理**:
  - ⚪ **9 个 stage 未注入生产 pipeline**：Anomaly/KubeAudit/ML/入侵六件套/Honeypot（代码全，跑不到）⚠️ 本系统头号问题
  - 数字订正：生产 stage 6(非"13")、RASP DataType 4000-4099(非 4100)
  - ❌ ATT&CK 红队评估≥70%、≥10k EPS benchmark、namespace BDE、Storyline→IOC

## 8. 告警系统
- **范围**: 告警生成/聚合/通知/处置
- **入口**: UI `Alerts` | API `/alerts` `/alarms` `/baseline-alerts` | 后端 `engine/celengine`(AlertGenerator) `manager/api/alerts`
- **状态**: ✅ 告警 upsert(幂等)、CEL AlertGenerator
- **待清理**: 待逐系统核实通知渠道/降噪/去重完整度

## 9. 威胁狩猎系统 (Hunting)
- **范围**: MQL 查询、威胁狩猎
- **入口**: UI `Hunting` | 后端 `server/hunting/mql` `manager/biz/hunting`
- **状态**: 🟢 MQL 引擎存在（有测试）
- **待清理**: 未深核，列为逐系统对象

## 10. 威胁情报系统 (ThreatIntel)
- **范围**: STIX/TAXII 订阅、IOC
- **入口**: UI `ThreatIntel` | 后端 `vulnsync/ti/stix_taxii.go` `manager/biz/threat_intel`
- **状态**: 🟢 STIX/TAXII 2.1 客户端真实(262 行)
- **待清理**: ❌ 多源订阅自动入库链路未找到、VT/微步/奇安信 多源未接

## 11. 响应处置系统
- **范围**: 主机隔离、SOAR Playbook、Agent 自动响应(kill/quarantine)
- **入口**: UI `HostIsolation` | API `/hosts/:id/isolate` | 后端 `manager/biz/soar` `agentcenter/commandsub` `agent/edr/rule`
- **状态**: 🟢 **完整链路真实**(SOAR→AC gRPC→Agent SIGKILL/quarantine)，含闸门+熔断
- **待清理**: 🟡 各检测 stage 输出 `alert_only`，真实下发链路在但默认不触发；未端到端实跑验证

---

# B. 资产与可视

## 12. 资产/指纹系统
- **范围**: 主机、进程、端口、软件、容器、应用、定时任务、SBOM、业务线、标签
- **入口**: UI `Hosts` `AssetFingerprint` `BusinessLines` | API `/assets` `/apps` `/containers` `/crons` `/files` `/business-lines` | 后端 `manager/api/assets.go` `manager/biz/sbom`
- **状态**: ✅ 资产 CRUD+导出、SBOM、业务线/标签批量
- **待清理**: 🟡 资产大盘统计偏薄；assets export 已修(format 校验提前)；按系统核实采集完整度

## 13. 仪表盘/监控系统
- **范围**: 总览大盘、Prometheus 指标、OTel、健康
- **入口**: UI `Dashboard` `Monitoring` | API `/dashboard` `/health` `/metrics` | 后端 `manager/api/dashboard.go` `common/observability`
- **状态**: ✅ Dashboard、Prometheus 指标、健康检查
- **待清理**: 🟡 **OTel"全链路"虚高**——实仅 engine 1/6 服务、无自动埋点；A1 OTel 生产关 insecure 未做

---

# C. 平台支撑

## 14. 用户/权限/认证系统
- **范围**: 登录(自适应验证码+可信设备)、JWT(黑名单)、RBAC 纵向越权、用户管理
- **入口**: UI `Users` `Rbac` | API `/auth` `/captcha` `/change-password` `/rbac` | 后端 `manager/api/auth*.go` `manager/api/permission_enforce.go`
- **状态**: ✅ 登录风控、JWT 黑名单(批4)、RBAC EnforceWritePermissions、账户锁。**本会话已修测试债+nil-db**
- **待清理**: 基本干净；批4 安全头/登录限流默认关(config 灰度开)

## 15. 配置中心系统
- **范围**: 配置变更审批工作流(CRUD+审批+Worker+变更记录)
- **入口**: UI `ConfigChange` | API `/config/change-requests` | 后端 `manager/api/config_change_request.go` `manager/biz/config_change_worker.go`
- **状态**: 🟢 API+Worker+UI 三层齐全，worker 已启动（原文档误标"缺"）
- **待清理**: 缺端到端验证；🟡 viper 热重载只 engine 接入，其余 5 服务未接

## 16. 模式/灰度系统
- **范围**: 观察/防御模式 4 级覆盖 + 6 准入闸门
- **入口**: UI `Mode` | API `/system/mode` `/tenants/:id/mode` | 后端 `common/mode` `common/mode/gate`
- **状态**: ✅ Mode Resolver 4 级、6 闸门(G4 回放占位)
- **待清理**: G4 回放闸门占位 return Passed

## 17. 审计系统
- **入口**: UI `AuditLog` | API `/audit-logs` | 后端 `model/audit_log.go` `manager/middleware/audit.go`
- **状态**: ✅ AuditLog model + 中间件双写(MySQL/CH)
- **待清理**: 基本干净

## 18. 系统设置
- **范围**: 功能开关、组件管理、站点配置、备份配置
- **入口**: UI `System` | API `/feature-flags` `/components` `/backup-config` `/backups` | 后端 `manager/api/{system_config,components}.go`
- **状态**: ✅ feature-flags、组件上传/下载、站点配置
- **待清理**: 🟡 备份脚本未实跑/恢复演练

---

# D. 后端基础设施（无直接 UI）

## 19. 数据采集管道
- **范围**: Agent↔AC gRPC、mTLS 一机一证信任链、Kafka、Consumer
- **入口**: 后端 `agentcenter/` `consumer/` `common/certissue` `common/kafka`
- **状态**: ✅ mTLS 信任链(批1)、AC 抗 DoS(批4)、Kafka(已修双重 prefix)、enroll 限流(本会话)
- **待清理**: T2 Kafka 修复待 prod 部署；🟡 Kafka 租户化✂️

## 20. 外发集成系统
- **范围**: 5 连接器(Syslog/Splunk HEC/Elastic/SLS/QRadar)
- **入口**: 后端 `manager/biz/outbound`
- **状态**: 🟢 5 连接器有真实发送逻辑（原文档误标 ❌）
- **待清理**: 未端到端验证；Splunk HEC 批量缓冲

## 21. LLM 辅助系统
- **范围**: llmproxy 网关、告警分析、prompt 隔离、数据出境管控
- **入口**: 后端 `llmproxy/` `manager/api/alert_analysis.go`
- **状态**: ✅ 内部认证+prompt 隔离+脱敏+出境默认关(批4)
- **待清理**: 基本干净

## 22. Agent 自保护系统
- **范围**: SelfProtect、Watchdog、ELF 完整性、反调试、反 LD_PRELOAD
- **入口**: 后端 `agent/edr/antidebug`
- **状态**: ✅ SelfProtect、Watchdog 双进程互保、ELFIntegrityMonitor（均已集成 main.go）
- **待清理**: 🟢 Anti-LD_PRELOAD 已实现未主动调；garble/UPX 未实测体积

## 23. 部署/运维系统
- **范围**: mxctl、Helm、Docker Compose、KMS、备份/灾备
- **入口**: 后端 `cmd/tools/mxctl` `deploy/`
- **状态**: ✅ mxctl、AutoMigrate(advisory lock)、KMS 信封加密、Helm/Compose v2 chart
- **待清理**: 🟡 systemd app unit 缺 EnvironmentFile 注入 KEK；信创 4 内核未实测；灾备演练未做

---

# E. 已砍

## 24. ✂️ 多租户 / MSSP / 计费
- 一企业一租户。tenant 层侵入 108 model scope → **冻结保留停止演进**（非删）。
- 砍/重评：MSSP 父子租户、100 租户压测、多 Region 调度、计费引擎+Quota、Kafka 租户化。

---

# 待清理汇总（脏数据·死代码，跨系统）

| 类型 | 项 | 处置 |
|---|---|---|
| 死页 | `ui/src/views/VirusScan/{index,Quarantine}.vue` | 核实后删（路由用 Virus/Quarantine） |
| 死代码 | quarantine.Manager / honeypot.Service / billing 3 worker / rootkit.Scanner / 新 fanotify | 接线 或 删 |
| 脏数据 | fim_events 4 行测试数据 | 运维 SQL 清 |
| 重复 | 三套反勒索诱饵 | 收敛到一套 |
| 断链 | 病毒 restore 全链路 | 补 restore 分支 |
| 虚高 | 主机基线 CEL/修复字段/等保 docx（不存在却标 ✅） | 文档已订正，功能按需补 |

> 注：以上不在本轮删除——按用户"一套一套来"逐系统处理。
