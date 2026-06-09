# MxSec Platform Community Edition

**[English](README.md) | 中文**

[![Go Version](https://img.shields.io/github/go-mod/go-version/imkerbos/mxsec-platform)](https://github.com/imkerbos/mxsec-platform)
[![License](https://img.shields.io/github/license/imkerbos/mxsec-platform)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/imkerbos/mxsec-platform?style=social)](https://github.com/imkerbos/mxsec-platform/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/imkerbos/mxsec-platform)](https://github.com/imkerbos/mxsec-platform/issues)
[![Last Commit](https://img.shields.io/github/last-commit/imkerbos/mxsec-platform)](https://github.com/imkerbos/mxsec-platform/commits/main)
[![Go Report Card](https://goreportcard.com/badge/github.com/imkerbos/mxsec-platform)](https://goreportcard.com/report/github.com/imkerbos/mxsec-platform)

开源的企业级主机与容器安全管理平台。覆盖安全基线、资产管理、漏洞扫描、病毒查杀、EDR 检测与合规审计，面向安全运营团队提供统一管控视图。

## 社区版说明

MxSec Platform **社区版** 包含完整的平台框架和全部核心安全能力，与内部版本架构一致。社区版完全免费，无需授权即可部署使用。当前已开源的能力主要包括：

- **全部端上能力**：Agent 数据采集、资产指纹、eBPF 运行时探针、基线检查插件等；
- **全部后端能力**：AgentCenter、Manager、Consumer、服务发现，均支持水平扩展；
- **完整管理控制台**：安全概览、资产中心、告警管理、基线检查、漏洞管理、容器安全等全功能 UI；
- **内置检测规则**：212 条 CIS 基线规则、80 条容器基线规则、CEL EDR 检测策略样例。

如需构建更完善的安全运营体系，建议基于平台提供的 CEL 规则引擎进行策略扩展，并结合威胁情报进行二次加工。

## 功能列表

| 功能 | 社区版 | 企业版 |
|------|--------|--------|
| Linux 数据采集（eBPF） | :white_check_mark: | :white_check_mark: |
| Agent 控制面（升级/配置/任务下发） | :white_check_mark: | :white_check_mark: |
| 主机状态与详情 | :white_check_mark: | :white_check_mark: |
| 资产采集（11 类） | :white_check_mark: | :white_check_mark: |
| 资产指纹（全局视图） | :white_check_mark: | :white_check_mark: |
| K8s 集群资产采集 | :white_check_mark: | :white_check_mark: |
| 主机/容器入侵检测 | `内置样例` | :white_check_mark: |
| EDR 检测（eBPF + CEL） | `内置样例` | :white_check_mark: |
| K8s Audit 入侵检测 | `内置样例` | :white_check_mark: |
| 行为序列检测 | :x: | :white_check_mark: |
| 告警白名单 | :white_check_mark: | :white_check_mark: |
| 告警聚合与溯源 | :white_check_mark: | :white_check_mark: |
| 威胁处置（kill/隔离/网络封禁） | :white_check_mark: | :white_check_mark: |
| 文件隔离箱 | :white_check_mark: | :white_check_mark: |
| 漏洞检测（OSV.dev + CVSS） | :white_check_mark: | :white_check_mark: |
| 漏洞情报热更新 | :x: | :white_check_mark: |
| 基线检查（CIS Benchmark） | :white_check_mark: | :white_check_mark: |
| 基线自动修复 | :white_check_mark: | :white_check_mark: |
| 病毒扫描（ClamAV + YARA-X） | :white_check_mark: | :white_check_mark: |
| 文件完整性监控（FIM） | :white_check_mark: | :white_check_mark: |
| 威胁情报（MISP IOC） | :white_check_mark: | :white_check_mark: |
| 容器 CIS 基线（80 规则） | :white_check_mark: | :white_check_mark: |
| 审计日志 | :white_check_mark: | :white_check_mark: |
| 组件管理与插件分发 | :white_check_mark: | :white_check_mark: |
| 系统监控（Prometheus） | :white_check_mark: | :white_check_mark: |
| 运维巡检与报告导出 | :white_check_mark: | :white_check_mark: |
| 内存威胁检测（memfd_exec / 进程镂空 / shellcode / LSASS dump） | :white_check_mark: | :white_check_mark: |
| AD / LDAP 域控审计（DCSync / Kerberoasting / 暴力破解等 7 规则） | :white_check_mark: | :white_check_mark: |
| DKOM Rootkit 检测（隐藏 PID / 内核模块 / 端口 / LD_PRELOAD） | :white_check_mark: | :white_check_mark: |
| 蜜罐传感器（SSH / HTTP 蜜罐 + 文件诱饵策略） | :white_check_mark: | :white_check_mark: |
| VEX 漏洞利用性声明导出（CycloneDX 1.5 / CSAF 2.0） | :white_check_mark: | :white_check_mark: |
| YARA-X 病毒规则库（73 条规则 / 50 家族） | :white_check_mark: | :white_check_mark: |
| 威胁狩猎（SPL 风格 DSL → SQL 转译） | :white_check_mark: | :white_check_mark: |
| 攻击故事线（ATT&CK 杀链时间线） | :white_check_mark: | :white_check_mark: |
| 行为基线检测（ML 异常评分） | :white_check_mark: | :white_check_mark: |
| Windows 支持 | :x: | :construction: |
| 主动防御（NPatch eBPF 热补丁） | `内置样例` | :white_check_mark: |
| 云查杀 | :x: | :construction: |

> :white_check_mark: 已支持 &nbsp; `内置样例` 含少量示例规则 &nbsp; :x: 未支持 &nbsp; :construction: 规划中

## 功能概览

| 模块 | 说明 |
|------|------|
| 安全基线 | 9 种检查器、212 条规则，覆盖 CIS Benchmark 核心项，支持单机/批量自动修复 |
| 资产中心 | 11 类资产采集（进程、端口、用户、软件包、容器等），关系计算与资产导出 |
| 漏洞管理 | 软件包 PURL 采集 + OSV.dev 匹配 + CVSS v3.1 评分 + SBOM 导出 |
| 病毒查杀 | ClamAV + YARA-X 双引擎扫描，任务管理 + 隔离箱处置 |
| 文件完整性 | 基于 AIDE 的 FIM 检查，策略、事件、任务全链路闭环 |
| EDR 检测 | Tetragon/eBPF 事件采集 + CEL 规则引擎 + MITRE ATT&CK 映射 |
| 容器安全 | K8s 集群管理、容器 CIS 基线（80 条规则）、Audit Webhook 接入 |
| 告警中心 | 告警聚合、白名单、自动响应（kill/隔离）、溯源时间线 |
| 威胁情报 | MISP IOC 导入 + Redis 缓存 + CEL 实时碰撞 |
| 内存取证 | memfd_exec / 进程镂空 / shellcode 注入 / LSASS dump 检测（EDR-3） |
| AD/LDAP 审计 | 7 条检测规则：DCSync、Kerberoasting、暴力破解、非工时 RDP、特权分配等（EDR-4） |
| 蜜罐传感器 | SSH/HTTP 蜜罐 + 文件诱饵 + 合法备份工具白名单（C1） |
| Rootkit 检测 | DKOM 隐藏 PID / 内核模块 / 端口 / LD_PRELOAD / /proc 不一致（C2） |
| 威胁狩猎 | SPL 风格 DSL → SQL 转译，跑在 ClickHouse 事件归档上 |
| VEX 导出 | CycloneDX VEX 1.5 + CSAF 2.0 给客户出具厂商漏洞声明（B7） |

## 产品截图

<table>
  <tr>
    <td><img src="docs/screenshots/dashboard.png" alt="安全概览" width="100%"><br><b>安全概览</b> — 实时安全态势评分、告警趋势、风险雷达</td>
    <td><img src="docs/screenshots/vulnerability-list.png" alt="漏洞列表" width="100%"><br><b>漏洞管理</b> — CVE 扫描、CVSS 评分、修复优先级</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/baseline-remediation.png" alt="基线修复" width="100%"><br><b>基线修复</b> — CIS Benchmark 自动修复，一键合规</td>
    <td><img src="docs/screenshots/vulnerability-bulletin.png" alt="漏洞通报" width="100%"><br><b>漏洞通报</b> — CVE 情报跟踪、SLA 管理</td>
  </tr>
  <tr>
    <td><img src="docs/screenshots/ml-anomaly-detection.png" alt="ML 异常检测" width="100%"><br><b>ML 异常检测</b> — Isolation Forest 行为异常评分</td>
    <td><img src="docs/screenshots/component-management.png" alt="组件管理" width="100%"><br><b>组件管理</b> — 插件分发、版本管理、远程推送</td>
  </tr>
</table>

## 架构概览

```
浏览器 ─→ Nginx ─→ Manager ×N ─→ MySQL / Redis / ClickHouse / Prometheus
Agent ─→ gRPC(mTLS) ─→ AgentCenter ×N ─→ Kafka ─┬→ Consumer ×N ─→ 存储层（持久化）
                                                 └→ Engine ×N    ─→ 告警/Storyline（检测分析）
Manager ──HTTP──→ LLMProxy ×N（多 LLM 适配）   VulnSync ×N ──Kafka──→ Engine/Manager
```

v2.0 后端拆分为 **六微服务**：Manager / AgentCenter / Consumer / Engine / LLMProxy / VulnSync，控制面全部无状态，支持水平扩展。Kafka 用两个 ConsumerGroup（持久化 / 检测）独立 offset 解耦，Redis 实现服务发现与分布式锁，ClickHouse 承载时序分析与事件归档。

详细架构参见 [架构设计文档](docs/architecture.md)。

## 技术栈

| 层面 | 技术 |
|------|------|
| 后端 | Go 1.25+（Gin / gRPC / Gorm / Zap） |
| 前端 | Vue 3 + TypeScript + Pinia + Ant Design Vue 4 |
| 存储 | MySQL 8.0+ / Redis 7 / ClickHouse 24 |
| 消息 | Kafka（KRaft 模式，7 Topic + DLQ） |
| 监控 | Prometheus（主机性能指标唯一数据源） |
| 通信 | gRPC 双向流 + mTLS + Protobuf |
| 部署 | Docker Compose / Systemd + Nginx |

## 支持平台

**主机 OS**: Rocky Linux 9/10, Oracle Linux 7/8/9, CentOS 7/8/9, Debian 10/11/12, Ubuntu 20.04/22.04

**运行时**: 物理机 / 虚拟机、Docker 容器宿主机、Kubernetes 节点与集群

## 快速开始

```bash
git clone https://github.com/imkerbos/mxsec-platform.git
cd mxsec-platform/deploy

cp .env.example .env
vim .env  # 修改 SERVER_IP / JWT_SECRET / 数据库密码

# 启动控制面（HA 模式）
docker compose --env-file .env up -d \
  --scale manager=2 --scale agentcenter=2 --scale consumer=2
```

访问 `http://<SERVER_IP>` 登录管理界面，默认账户 `admin / admin123`。

详细部署方案参见 [安装部署文档](docs/deployment.md)。

## 构建命令

```bash
make build-server                                        # 构建服务端
make build-consumer                                      # 构建 Consumer
make package-agent-all VERSION=1.0.0 SERVER_HOST=IP:6751 # 打包 Agent（RPM/DEB）
make package-plugins-all VERSION=1.0.0                   # 打包插件
make proto                                               # 生成 Protobuf 代码
make test                                                # 运行测试
make lint                                                # 代码检查
```

## 项目结构

```
mxsec-platform/
├── cmd/                    # 入口（agent + 6 个 server 服务 + mxctl + 工具）
│   ├── agent/              # Agent 入口
│   └── server/             # manager / agentcenter / consumer / engine / llmproxy / vulnsync
├── internal/
│   ├── server/             # 服务端（manager / agentcenter / consumer / engine / llmproxy / vulnsync / common）
│   └── agent/              # Agent（connection / transport / plugin / heartbeat / edr 25+ 子模块）
├── plugins/                # 11 个插件（baseline / collector / fim / scanner / avscanner / remediation / rasp-go / rasp-java / rasp-python / rasp-php / rasp-node）
├── api/proto/              # Protobuf 定义
├── ui/                     # 前端工程（Vue 3 + TypeScript）
├── configs/                # 配置文件（server.yaml / agent.yaml / 规则文件）
├── deploy/                 # 部署配置（Docker Compose dev/v2/pret + Nginx + systemd + 生产集群）
├── scripts/                # 构建与部署脚本
└── docs/                   # 文档
```

## 文档

- [架构设计](docs/architecture.md) - 系统拓扑、组件职责、数据链路、高可用设计
- [安装部署](docs/deployment.md) - 环境准备、单机/集群部署、Agent 安装、升级与备份
- [配置说明](docs/configuration.md) - 服务端配置、Agent 配置、环境变量
- [API 文档](docs/api-reference.md) - REST API 端点、请求/响应格式、认证
- [常见问题](docs/faq.md) - 部署与运行中的常见问题及排查方法
- [开源治理](docs/governance.md) - 项目治理模型、决策流程、安全策略
- [社区规范](docs/contributing.md) - 贡献指南、开发环境、代码规范、提交流程

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=imkerbos/mxsec-platform&type=Date)](https://star-history.com/#imkerbos/mxsec-platform&Date)

## Contributors

见 [CONTRIBUTORS.md](CONTRIBUTORS.md)。

## License

[Apache License 2.0](LICENSE)
