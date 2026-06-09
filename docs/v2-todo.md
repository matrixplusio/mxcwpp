# mxsec v2.0 重构进度总览

**最后更新**: 2026-06-07
**当前阶段**: MVP 收尾 + M1 推进
**总进度**: 110/185 ≈ 60%

图例:
- ✅ 完成 (生产可用 + 已验证)
- 🟢 完成 (代码 ok, 未验证)
- 🟡 部分 (骨架 + 接口 + 部分实现)
- 🔴 仅设计/文档
- ❌ 未开始

---

## 模块 1: Server 微服务架构 (12/25)

| 状态 | 项 | PR | 备注 |
|---|---|---|---|
| ✅ | 6 微服务骨架 (manager/ac/consumer/engine/vulnsync/llmproxy) | 已合 | cmd/server/*/main.go |
| ✅ | 多租户骨架 (tenant_id + Middleware + Hook) | 已合 | internal/server/common/tenant/ |
| ✅ | mTLS AC↔Manager | 已合 | |
| ✅ | API v1/v2 并存 | 已合 | |
| ✅ | OTel 全链路 | 已合 | internal/server/common/observability/ |
| 🟢 | viper 配置统一 (engine 接入) | 已合 PR67 | manager/ac/consumer/vulnsync/llmproxy 待接入 |
| ✅ | 审计 AuditLog model | 已合 | |
| 🟢 | KMS envelope encryption | PR #83 | internal/server/common/kms/ |
| 🟢 | KubeConfig + GCPCredentials 加密 | PR #83 | model hook |
| 🟡 | 灾备备份脚本 (xtrabackup + CH BACKUP) | PR #89 | 实际跑/恢复演练未做 |
| 🟡 | ConfigChangeRequest model | PR #89 | API + Worker + UI 缺 |
| 🟢 | Helm chart mxsec-server | PR #84 | helm lint pass, K8s 实测未做 |
| ❌ | Kafka topic 租户化 `t.{tenant}.mxsec.agent.*` | | |
| ❌ | MySQL 主从 GTID 复制 | | |
| ❌ | Redis Sentinel | | |
| ❌ | Kafka MirrorMaker 2 异地 | | |
| ❌ | CanaryRollout v2 (5%→25%→100% 自动回滚) | | |
| ❌ | 配置中心 v1 审批工作流 (Manager API + Worker + UI) | | |
| ❌ | 容量推荐引擎 | | |
| ❌ | MSSP 多 Region + 父子租户 | | |
| ❌ | 5 种外发连接器 (Syslog/Splunk HEC/Elastic Bulk/SLS/QRadar) | | |
| ❌ | 计费引擎 + Quota + 月账单 | | |
| ❌ | OpenAPI 3.0 schema + Go/Python/Java SDK | | |
| ❌ | 计量与用量上报 | | |
| ❌ | 异地灾备演练 (RPO≤5min/RTO≤30min) | | |

## 模块 2: Agent 端 (6/20)

| 状态 | 项 | PR | 备注 |
|---|---|---|---|
| ✅ | Plugin 框架 (plugins/lib/) | 已合 | |
| ✅ | EDR 内核 18K LOC | 已合 | internal/agent/edr/ |
| ✅ | eBPF 进程/网络/文件采集 | 已合 | bpf/ {process,network,file}.c |
| ✅ | 心跳 + 配置下发 | 已合 | |
| 🟢 | av-scanner 插件脚手架 | 已合 | plugins/avscanner/ |
| 🟢 | 多架构构建 (amd64/arm64) | 已合 | scripts/build.sh |
| 🟡 | Agent 隔离箱 (主进程级) | PR #92 | internal/agent/edr/quarantine/ |
| 🟡 | Anti-Rootkit Scanner 4 类 | PR #86 | internal/agent/edr/rootkit/ |
| 🟡 | 自我加固 (DUMPABLE/NNP/PTRACE_TRACEME/ELF SHA) | PR #90 | main.go 未集成 |
| 🟡 | garble + UPX 构建脚本 | PR #90 | 未实测体积/CPU |
| 🔴 | Watchdog 双进程互保 | PR #90 skeleton | 仅 API 契约 |
| 🔴 | Java RASP libmxsec_rasp.so | PR #86 设计 | 实现是 C/C++ 工程 |
| 🔴 | fanotify watcher | PR #92 skeleton | 当前 fallback inotify |
| ❌ | privilege.c bpf2go 生成 bindings + collector glue | PR #85 BPF 源 | 待 Linux 跑 go generate |
| ❌ | Windows Server 2019/2022 | | |
| ❌ | AIX 7.2 | | |
| ❌ | 信创 Kylin V10 ARM64 实测 | PR #91 文档 | |
| ❌ | LoongArch64 实测 | PR #91 文档 | |
| ❌ | 非 root 模式 | | |
| ❌ | CPU/内存 3 档主动降级 (pause→stop→suicide) | | |
| ❌ | DMI 硬件指纹 Agent ID | | |
| ❌ | Canary cohort hash 阶梯放量 | | |
| ❌ | Agent /metrics 9100 Prometheus 暴露 | | |
| ❌ | 多 region fallback (内外网双链路) | | |
| ❌ | 主机离线探测 (ARP/Ping/Nmap) | | |

## 模块 3: 检测引擎 (14/25)

| 状态 | 项 | PR | 备注 |
|---|---|---|---|
| ✅ | Pipeline 13 stage 骨架 | 已合 | internal/server/engine/stage_*.go |
| ✅ | CEL 引擎 | 已合 | engine/celengine/ |
| ✅ | Sequence 序列检测 | 已合 | |
| ✅ | Storyline 故事线 | 已合 | engine/storyline/ |
| ✅ | Anomaly 异常 | 已合 | |
| ✅ | KubeAudit Stage | 已合 | |
| ✅ | ML IForest + MLStage | 已合 | |
| ✅ | 入侵六件套 (brute/login/webshell/revshell/priv/rootkit) | 已合 | engine/intrusion/ |
| ✅ | Honeypot 服务端 | 已合 | engine/honeypot/ |
| 🟢 | RASP Java read-only (内存马) | 已合 | engine/rasp/ |
| 🟢 | RASP PHP 17 危险函数 | 已合 | rasp/php.go |
| 🟢 | RASP Python PEP 578 audit + 反弹 shell | 已合 | rasp/python.go |
| ✅ | Falco/Sigma → CEL 导入 | 已合 | engine/ruleimport/ |
| 🟢 | ATT&CK 规则 119 条 | PR #81 | configs/rules/builtin-rules.yaml |
| ❌ | ATT&CK 200 条 + 红队评估 ≥70% | | |
| ❌ | namespace 维度 BDE (容器异常学习) | | |
| ❌ | STIX/TAXII 客户端 (VT/微步/奇安信) | | |
| ❌ | Playbook SOAR 编排引擎 | | |
| ❌ | Agent 端自动响应 (kill/suspend/quarantine 真实下发) | | |
| ❌ | DataType 3005 (privilege) Pipeline Stage 接入 | | |
| ❌ | DataType 3006 (rootkit) Pipeline Stage 接入 | | |
| ❌ | DataType 4100-4109 (RASP) Pipeline Stage 接入 | | |
| ❌ | Engine Pipeline 性能 benchmark (≥10k EPS) | | |
| ❌ | Storyline 故事线 → IOC 自动生成 | | |
| ❌ | 多源威胁情报订阅自动入库 | | |

## 模块 4: K8s / 容器 (8/20)

| 状态 | 项 | PR | 备注 |
|---|---|---|---|
| ✅ | Admission Webhook v1 (5 策略) | 已合 | |
| ✅ | Image Scan: CVE + Secret + Dockerfile lint | 已合 | manager/biz/imagescan/ |
| ✅ | 微隔离 Phase 1 FlowCollector | 已合 | engine/microseg/flow.go |
| 🟢 | 微隔离 Phase 2 NetworkPolicy 推荐 (dry-run) | 已合 | engine/microseg/recommend.go |
| ✅ | KubeAudit Stage | 已合 | |
| ✅ | K8s 基线规则 (CIS 部分) | 已合 | |
| 🟢 | mxsec-server Helm chart | PR #84 | |
| 🟢 | mxsec-agent Helm chart (DaemonSet) | 已合 | |
| ❌ | 微隔离 Phase 3 enforce + Cilium/Calico 集成 | | |
| ❌ | 镜像 Webshell YARA | | |
| ❌ | 自研补丁库替代 Trivy DB (5w+ 漏洞) | | |
| ❌ | Docker CIS 四维 (runtime/container/image/host) | | |
| ❌ | K8s CIS 80 → 120 条 (v1.27) | | |
| ❌ | CI 三 plugin (GitLab Runner/Jenkins/GitHub Actions) | | |
| ❌ | License 扫描 | | |
| ❌ | 短生命周期 Pod 指纹 (UUID hash) | | |
| ❌ | KMS + KubeConfig 加密集成到 Helm | 部分 | KMS 已实, Helm Secret 已配 |
| ❌ | Pod Security Standards 配置 | | |
| ❌ | NetworkPolicy 自动应用 (Cilium hubble 集成) | | |
| ❌ | runtime 容器逃逸检测 (T1611) | | |

## 模块 5: 漏洞模块 (11/20)

| 状态 | 项 | PR | 备注 |
|---|---|---|---|
| ✅ | VulnSync 15 源 (NVD/OSV/RedHat/Ubuntu/Debian/Alpine/SUSE/CISA KEV/EDB/EPSS/...) | 已合 | vulnsync/sources/ |
| ✅ | 17 个 Advisory 解析器 | 已合 | vulnsync/advisory/ |
| ✅ | 扫描状态机 6 态 | 已合 | |
| ✅ | 定向扫描 + reconcile | 已合 | |
| 🟢 | NPatch 30 规则 | PR #88 | manager/biz/npatch/ |
| ✅ | 风险中心大盘 | 已合 | |
| ✅ | 修复闭环 RemediationTask | 已合 | |
| ✅ | EPSS 评分接入 | 已合 | |
| ✅ | 信创 4 源 (openEuler/Anolis/Kylin/UOS) | 已合 | sources/xc.go |
| ✅ | 弱口令探测占位 | 已合 | |
| ✅ | 漏洞 → 主机 → 包关联 | 已合 | |
| ❌ | NPatch eBPF 字节码 PoC 实现 | | |
| ❌ | NPatch 业务延迟 ≤5ms benchmark | | |
| ❌ | SBOM CycloneDX 生成 | | |
| ❌ | 50 条 PoC 自动验证 | | |
| ❌ | 灰度修复 1k 主机 P99≤30min + 100% 回滚 | | |
| ❌ | 漏洞-进程动态关联 | | |
| ❌ | 弱口令数据库 10w+ | | |
| ❌ | NPatch rule hot-reload | | |
| ❌ | NPatch UI 配置 + 模式切换 | | |

## 模块 6: 基线 / 合规 (14/25)

| 状态 | 项 | PR | 备注 |
|---|---|---|---|
| ✅ | Baseline 引擎 + 9 个 checker types | 已合 | plugins/baseline/engine/ |
| 🟢 | file_line_expr checker (Elkeid 兼容) | PR #80 | |
| 🟢 | Elkeid 50 CIS 基线导入 | PR #80 | plugins/baseline/config/cis/ |
| 🟢 | 等保 2.0 三级 40 条 (RHEL) | PR #93 | plugins/baseline/config/dengbao/ |
| 🟢 | CIS RHEL 8 L1 40 条 | PR #93 | plugins/baseline/config/cis-rhel/ |
| 🟢 | 中间件基线 50 条 (Nginx/Apache/Tomcat/MySQL) | PR #87 | plugins/baseline/config/middleware/ |
| ✅ | 主机基线 CEL Checker | 已合 | |
| ✅ | 修复 plan (pre/verify/rollback 字段) | 已合 | |
| ✅ | 等保 docx 导出 | 已合 | |
| ✅ | K8s 80 项 CIS (部分) | 已合 | |
| ✅ | 并发 worker 池 | 已合 | |
| ✅ | 基线规则 plugin 框架 | 已合 | |
| ✅ | 弱口令 detector 占位 | 已合 | |
| ✅ | 任务调度 | 已合 | |
| ❌ | Ubuntu 22.04 等保 2.0 规则 (DB_L3_UB_*) | | |
| ❌ | Windows Server 2019/2022 基线 (~100 条) | | |
| ❌ | 中间件扩到 160 (+ Redis/Postgres/RabbitMQ/Kafka 各 40) | | |
| ❌ | 数据库基线 (Oracle/MongoDB/Redis/DB2) | | |
| ❌ | 修复后验证 pre→snapshot→dryrun→apply→verify→rollback 完整链 | | |
| ❌ | 多格式导出 Word/Excel/CSV/PDF 趋势图 | | |
| ❌ | 差异扫描 last_status 字段 | | |
| ❌ | K8s CIS Benchmark v1.27 120 条 | | |
| ❌ | 信创 OS 基线 (Kylin/UOS/openEuler) | | |
| ❌ | 基线得分趋势分析 | | |
| ❌ | 5000 台主机 < 5min 性能验收 | | |

## 模块 7: 运行时 EDR (13/30)

| 状态 | 项 | PR | 备注 |
|---|---|---|---|
| ✅ | eBPF 8 事件类型 (process/file/network/dns) | 已合 | |
| ✅ | Storyline 故事线 (Server 聚合) | 已合 | |
| ✅ | Mode Resolver 4 级覆盖 | 已合 | common/mode/ |
| ✅ | 6 闸门 admission | 已合 | common/mode/gate/ |
| ✅ | IForest + MLStage + ONNX 推理 | 已合 | |
| ✅ | 入侵六件套 (见模块 3) | 已合 | |
| 🟢 | RASP Java/PHP/Python read-only | 已合 | |
| ✅ | DegradationLevel 0-3 框架 | 已合 | |
| 🟢 | privilege.c BPF 源 (6 hook) | PR #85 | bpf/privilege.c |
| 🟢 | DataType 3005/3006 常量 | PR #85/86 | event.go |
| 🟢 | Anti-Rootkit Agent scanner (kmod_hidden/known/syscall_drift/pid_hidden) | PR #86 | |
| 🟢 | ELFIntegrityMonitor | PR #90 | |
| 🟢 | SelfProtect (DUMPABLE/NNP/PTRACE_TRACEME) | PR #90 | |
| ❌ | privilege.c bpf2go 生成 .o + Go bindings | | 需在 Linux 跑 go generate |
| ❌ | PrivilegeCollector Start/Stop/event loop | | 待 bindings 后 |
| ❌ | privilege event → Pipeline → Alert 链路 | | |
| ❌ | Anti-Rootkit Indicator → Pipeline Stage | | |
| ❌ | Anti-Rootkit eBPF kallsyms 内核态校验 | | |
| ❌ | 三档订阅 (initial 13/standard 55/full 126 小类) | | |
| ❌ | Java RASP libmxsec_rasp.so 实现 (JVMTI + ASM) | | |
| ❌ | PHP Zend extension libmxsec_rasp_php.so | | |
| ❌ | Python audit hook 实际注册 | | |
| ❌ | Node RASP | | |
| ❌ | Playbook SOAR 编排 | | |
| ❌ | Agent 端自动响应 kill/iptables 真实下发 | | |
| ❌ | Watchdog 双进程互保完整实现 | | |
| ❌ | Anti-LD_PRELOAD 检测 | | |
| ❌ | madvise(MADV_DONTDUMP) 关键内存区 | | |
| ❌ | 反内存 dump (PR_SET_THP_DISABLE 等) | | |
| ❌ | EDR Performance benchmark (CPU<2%, MEM<200MB, 400EPS) | | |

## 模块 8: 病毒 / 反勒索 (8/15)

| 状态 | 项 | PR | 备注 |
|---|---|---|---|
| ✅ | scanner 插件 (CLI clamscan + YARA) | 已合 | plugins/scanner/ |
| 🟢 | clamd UNIX socket 客户端 | PR #82 | plugins/scanner/engine/clamd_socket.go |
| 🟢 | EICAR 自检 | PR #82 | |
| ✅ | YARA 规则框架 | 已合 | plugins/scanner/engine/yara.go |
| ✅ | quarantine 隔离箱 (插件级) | 已合 | plugins/scanner/engine/quarantine.go |
| 🟢 | Agent 主进程级隔离箱 (替代插件级) | PR #92 | internal/agent/edr/quarantine/ |
| ✅ | avscanner 诱饵投放 + inotify | 已合 | plugins/avscanner/ |
| 🟢 | Honeypot Policy + 12 备份白名单 | 已合 | |
| ❌ | Server 端 quarantine API ↔ Agent quarantine 集成 | | |
| ❌ | 三档扫描任务 (quick/full/custom) Agent 真实落地 | | |
| ❌ | EICAR 端到端闭环 (上传→扫→隔离→还原) | | |
| ❌ | UI 隔离箱管理 (restore/delete/analyze) | | |
| ❌ | freshclam 病毒库分发 SLA≤10min | | |
| ❌ | fanotify FanotifyInit/Mark 完整实现 (替代 inotify) | | |
| ❌ | YARA 完整规则库 (WebShell/勒索特征) | | |

## 模块 9: 多租户 / 配置 / 部署 / CI (5/15)

| 状态 | 项 | PR | 备注 |
|---|---|---|---|
| ✅ | 多租户骨架 | 已合 | |
| 🟢 | viper 配置 (engine 单点) | 已合 | |
| ✅ | mxctl 部署 (现有) | 已合 | |
| ✅ | AutoMigrate | 已合 | |
| 🟢 | scripts/build.sh ARCH=xc 信创全栈 | PR #91 | amd64+arm64+loong64 |
| ❌ | 100 租户 + 单租户 5w 主机压测 | | |
| ❌ | 配置中心 CRUD + 审批工作流 + 变更记录 (Manager API + UI) | | ConfigChangeRequest model 已建 (#89) |
| ❌ | mxctl region 扩展 + 多 Region 智能调度 | | |
| ❌ | OpenAPI 3.0 schema | | |
| ❌ | Go/Python/Java SDK | | |
| ❌ | 计费引擎 + Quota | | |
| ❌ | K8s Helm chart 端到端 install 验证 | | |
| ❌ | Docker Compose 升级 v2.0 6 微服务 | | |
| ❌ | systemd EnvironmentFile + KMS 集成 | 部分 | KMS 引擎已有 (#83), systemd 配置缺 |
| ❌ | 信创 OS 实测 4 内核版本 (Kylin/UOS/openEuler) | | |

---

## 下一阶段重点 (建议优先级)

### Phase 1 (短期, 真正可演示生产能力)
1. **配置中心 Manager API + Worker + UI** (M1-5 接续)
2. **隔离箱端到端集成** (M1-8 接续) — Agent → AC → Manager API → UI
3. **privilege.c Linux 跑 go generate + collector glue + Pipeline Stage** (M1-1 接续)
4. **Anti-Rootkit Pipeline Stage** (M1-2 接续)
5. **配置中心 + 隔离箱 + RASP 上报 → DataType 路由 → Pipeline** 全链路
6. **Server 端: ConfigChangeRequest CRUD API + RBAC + audit**
7. **viper 配置统一: manager/ac/consumer/vulnsync/llmproxy 接入**
8. **mxsec-server Helm 实际部署到 minikube 验证**

### Phase 2 (中期, 工程深度)
9. **Watchdog 双进程互保完整实现**
10. **fanotify 完整实现 + 替代 inotify**
11. **Agent main.go 集成 SelfProtect + ELFIntegrityMonitor**
12. **garble + UPX 实测体积 + CPU benchmark**
13. **NPatch eBPF PoC (单条规则: Log4j JNDI 阻断)**
14. **Engine 性能 benchmark (≥10k EPS)**
15. **5 种外发连接器 (Syslog 优先, Splunk HEC 次之)**
16. **OpenAPI 3.0 schema generator**

### Phase 3 (长期, 完整 v2.0)
17. **Java RASP libmxsec_rasp.so 工程立项 + 第一版**
18. **STIX/TAXII 客户端 + 自研补丁库**
19. **SOAR Playbook 编排引擎**
20. **MSSP 多 Region + 父子租户**
21. **100 租户 SaaS 压测**
22. **灾备演练 + RPO/RTO 实测**

---

## 进度推进规则

1. 每完成一项 → 本文档对应状态升级 + commit
2. PR 标题前缀对应模块编号: `feat(M1-1c)` / `feat(M5-3)` 等
3. 模块内进度统计在标题处更新
4. 每 5 个 PR 重算总进度 (X/185)
