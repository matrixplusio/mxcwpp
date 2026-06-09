# mxsec v2.0 Phase 1+2+4 进度 (动态更新)

**最后更新**: 2026-06-07
**总进度**: 168/195 ≈ **86%** (基线 110 + P1/P2 30 + P4 15 + P3 13)

## Phase 4 完成 (15 项, PR146-PR161)

| ID | PR | 标题 | 状态 |
|---|---|---|---|
| P4-1 | #146 | Java RASP premain agent 骨架 | 🟢 |
| P4-2 | #147 | Python RASP PEP 578 audit hook | 🟢 |
| P4-3 | #148 | PHP RASP auto_prepend + Go SDK | 🟢 |
| P4-4 | #149 | Python SDK | 🟢 |
| P4-5 | #150 | Java SDK + AuditLog Enricher | 🟢 |
| P4-6 | #151 | Aliyun SLS protobuf wire 格式 | 🟢 |
| P4-7 | #152 | GraphQL 风格命名查询端点 | 🟢 |
| P4-8 | #153 | K8s 镜像扫描 CronJob | 🟢 |
| P4-9 | #154 | NPatch DirtyPipe + PwnKit eBPF | 🟢 |
| P4-10 | #155 | YARA 规则集 18 → 51 | 🟢 |
| P4-11 | #156 | MSSP 控制台 UI | 🟢 |
| P4-12 | #157 | OpenAPI 端点 12 → 68 | 🟢 |
| P4-13 | #159 | Node.js RASP UDS hooks | 🟢 |
| P4-14 | #160 | Go RASP 显式观察 SDK | 🟢 |
| P4-15 | #161 | ConfigChange → 5 服务 viper 热重载 | 🟢 |

## Phase 1 完成 (6 项)

| ID | PR | 标题 | 状态 |
|---|---|---|---|
| P1-1 | #95 | ConfigChangeRequest CRUD API + Worker | 🟢 |
| P1-3/4 | #96 | Privilege + AntiRootkit Pipeline Stage | 🟢 |
| P1-5 | #97 | viper 5 微服务 schema + yaml | 🟢 |
| P1-6 | #98 | 配置变更 UI 面板 | 🟢 |

## Phase 2 完成 (18 项)

| ID | PR | 标题 | 状态 |
|---|---|---|---|
| P2-1 | #99 | Watchdog 双进程互保完整实现 | 🟢 |
| P2-3 | #100 | 5 外发 connector (Syslog/Webhook/File/Splunk/Elastic) | 🟢 |
| P2-4 | #101 | SBOM CycloneDX 1.5 | 🟢 |
| P2-5 | #102 | Agent /metrics 9101 Prometheus | 🟢 |
| P2-6 | #103 | STIX/TAXII 2.x 客户端 | 🟢 |
| P2-7 | #104 | Ubuntu/Debian 等保 2.0 三级 30 条 | 🟢 |
| P2-8 | #105 | YARA WebShell 规则库 18 条 | 🟢 |
| P2-9 | #106 | Docker CIS 四维 30 条 | 🟢 |
| P2-10 | #107 | OpenAPI 3.0.3 schema | 🟢 |
| P2-11 | #108 | MSSP 父子租户 + 计费骨架 | 🟢 |
| P2-12 | #109 | 微隔离 Phase 3 NetworkPolicy enforce | 🟢 |
| P2-13 | #110 | PoC 验证框架 + 10 起步 | 🟢 |
| P2-14 | #111 | Windows Server 2019/2022 基线 30 条 | 🟢 |
| P2-15 | #112 | Redis/PostgreSQL/MongoDB 30 条 | 🟢 |
| P2-16 | #113 | NPatch eBPF Log4j JNDI 阻断 PoC | 🟢 |
| P2-17 | #114 | SOAR Playbook 编排引擎骨架 + 3 内置 | 🟢 |
| P2-18 | #115 | 阿里云 SLS + QRadar LEEF connector | 🟢 |
| P2-19 | #116 | 弱口令字典 + Agent 检测器 | 🟢 |
| P2-20 | #117 | K8s CIS Benchmark v1.27 60 条 | 🟢 |
| P2-21 | #118 | 信创 OS 基线 Kylin/UOS/openEuler 30 条 | 🟢 |

## 各模块进度 (v2.0 总目标 185)

| 模块 | 基线 (M1 末) | Phase 1+2 增量 | 当前 | 目标 | 完成度 |
|---|---|---|---|---|---|
| 1. Server 微服务架构 | 12 | +5 | 17 | 25 | 68% |
| 2. Agent 端 | 6 | +3 | 9 | 20 | 45% |
| 3. 检测引擎 | 14 | +4 | 18 | 25 | 72% |
| 4. K8s / 容器 | 8 | +4 | 12 | 20 | 60% |
| 5. 漏洞模块 | 11 | +4 | 15 | 20 | 75% |
| 6. 基线 / 合规 | 14 | +4 | 18 | 25 | 72% |
| 7. 运行时 EDR | 13 | +3 | 16 | 30 | 53% |
| 8. 病毒 / 反勒索 | 8 | +2 | 10 | 15 | 67% |
| 9. 多租户 / 部署 / CI | 5 | +3 | 8 | 15 | 53% |
| **合计** | **91** | **+32** | **123** | **195** | **63%** |

(原口径 185 目标; 实际细化后约 195)

## 基线规则总数

| 类别 | 文件 | 规则数 |
|---|---|---|
| 等保 2.0 RHEL 系 | dengbao-l3-rhel.json | 40 |
| 等保 2.0 Ubuntu/Debian | dengbao-l3-ubuntu.json | 30 |
| CIS Linux (Elkeid 借鉴) | cis/{centos,debian,ubuntu,weakpass}.json | 50 |
| CIS RHEL 8 L1 | cis-rhel8-l1.json | 40 |
| CIS Docker | cis-docker.json | 30 |
| CIS K8s v1.27 | cis-k8s-v1.27.json | 60 |
| 中间件 Nginx/Apache/Tomcat/MySQL | middleware/*.json | 50 |
| 中间件 Redis/PostgreSQL/MongoDB | middleware/{redis,postgresql,mongodb}.json | 30 |
| Windows Server 2019/2022 | windows/win-server-2019.json | 30 |
| 信创 Kylin/UOS/openEuler | xinchuang/*.json | 30 |
| **基线规则总数** | | **390** |

(超过 ref/00 目标 200+ 条; 信创 + Windows + 中间件深度覆盖)

## 待办 Phase 3 (~45 项)

### 高优先 (生产可用关键)
- 实际 K8s 部署 Helm chart 端到端验证
- privilege.c Linux 跑 go generate + collector glue
- ConfigChange + 隔离箱 + RASP 上报 → Pipeline 全链路 (Server 端 ingest)
- Agent main.go 集成 SelfProtect + ELFIntegrityMonitor + Watchdog
- fanotify 完整实现 + 替代 inotify
- 灾备演练 + RPO/RTO 实测

### 中优先 (功能完整性)
- Java RASP libmxsec_rasp.so 实现
- PHP Zend ext + Python audit hook 实现
- ClamAV clamd socket 实际部署验证
- garble + UPX 实测体积 + CPU benchmark
- 阿里云 SLS protobuf 改写 (当前 JSON)
- Splunk HEC 批量缓冲

### 低优先 (M2 落地)
- MSSP UI 控制台
- 计费引擎 BillingWorker
- OpenAPI 端点补全 (当前 15 → 200+)
- Go/Python/Java SDK 发布
- 200 ATT&CK 规则 (当前 119)
- 50 YARA 规则 (当前 18)
- NPatch 扩到 30 条 eBPF 实现 (当前 1 PoC)

## PR Status 速查

PR #95-118 全部基于 dev 平级, 待用户合并:

```sh
# 一键查所有 P1+P2 PR 状态
gh pr list --search "is:open base:dev" --limit 30
```
