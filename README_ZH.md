# MxCwpp

**[English](README.md) | 中文**

[![Go Version](https://img.shields.io/github/go-mod/go-version/matrixplusio/mxcwpp)](https://github.com/matrixplusio/mxcwpp)
[![License](https://img.shields.io/github/license/matrixplusio/mxcwpp)](LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/matrixplusio/mxcwpp?style=social)](https://github.com/matrixplusio/mxcwpp/stargazers)
[![GitHub Issues](https://img.shields.io/github/issues/matrixplusio/mxcwpp)](https://github.com/matrixplusio/mxcwpp/issues)
[![Last Commit](https://img.shields.io/github/last-commit/matrixplusio/mxcwpp)](https://github.com/matrixplusio/mxcwpp/commits/main)
[![Go Report Card](https://goreportcard.com/badge/github.com/matrixplusio/mxcwpp)](https://goreportcard.com/report/github.com/matrixplusio/mxcwpp)

开源的主机与容器安全平台（CWPP），面向 Linux 与 Kubernetes。覆盖安全基线、资产清点、漏洞管理、病毒查杀、文件完整性监控、运行时检测与响应，为安全运营团队提供统一的管理控制台。

Agent、插件、后端服务与控制台全部在本仓库中，按 AGPL-3.0 免费部署使用。

## 功能

| 领域 | 能力 |
|------|------|
| 安全基线 | CIS Benchmark、等保 2.0 与中间件检查——30 个策略、614 条规则；支持单机与批量自动修复 |
| 资产清点 | 进程、端口、用户、软件包、容器等资产采集，关系计算、全局指纹与导出；Kubernetes 集群资产 |
| 漏洞管理 | 软件包 PURL 采集、OS 厂商公告与 OSV.dev 匹配、CVSS v3.1 评分，导出 SBOM 与 VEX（CycloneDX 1.5 / CSAF 2.0） |
| 病毒查杀 | ClamAV 与 YARA-X 双引擎，扫描任务与文件隔离 |
| 文件完整性监控 | 基于 AIDE 的 FIM，策略、事件、任务全流程 |
| 运行时检测 | eBPF 事件采集，CEL 规则引擎与 MITRE ATT&CK 映射，行为序列规则，ML 异常评分 |
| 内存与 Rootkit 检测 | memfd_exec、进程镂空、shellcode 注入、LSASS dump；DKOM 隐藏 PID / 内核模块 / 端口 / LD_PRELOAD |
| Kubernetes 安全 | 集群管理、容器 CIS 基线、通过审计 Webhook 做审计日志入侵检测 |
| AD / LDAP 审计 | DCSync、Kerberoasting、暴力破解、非工作时间 RDP、特权分配等 |
| 告警与响应 | 告警聚合、白名单、攻击故事线（ATT&CK 杀伤链时间线），进程查杀 / 文件隔离 / 网络封禁 |
| 威胁情报 | MISP IOC 导入，规则引擎内实时碰撞 |
| 威胁狩猎 | SPL 风格查询语言转译为 SQL，在 ClickHouse 事件归档上执行 |
| 运维 | 审计日志、组件与插件分发、Prometheus 监控、巡检报告 |

**开发中，尚未发布：**蜜罐传感器（SSH / HTTP 诱饵）、NPatch eBPF 虚拟补丁（目前只有 Log4j 原型）、Windows 支持。

## 架构

```
浏览器 ─→ Nginx ─→ Manager ×N ─→ MySQL / Redis / ClickHouse / Prometheus
Agent ─→ gRPC(mTLS) ─→ AgentCenter ×N ─→ Kafka ─┬→ Consumer ×N ─→ 存储层（持久化）
                                                 └→ Engine ×N    ─→ 告警（检测分析）
Manager ──HTTP──→ LLMProxy ×N（多 LLM 适配）   VulnSync ×N ──Kafka──→ Manager/Engine
```

后端由七个服务组成：Manager、AgentCenter、Consumer、Engine、LLMProxy、VulnSync、Scanner。控制面无状态，可水平扩展。Kafka 把持久化与检测解耦（两个消费组，offset 互相独立），Redis 负责服务发现与分布式锁，ClickHouse 承载时序分析与事件归档。VulnSync 拉取 OS 厂商公告并发布到 Kafka，用于与主机软件匹配。

详见 [架构设计](docs/architecture.md)。

## 技术栈

| 层面 | 技术 |
|------|------|
| 后端 | Go 1.26（Gin / gRPC / GORM / Zap） |
| 前端 | Next.js 15 + React 19 + TypeScript + TailwindCSS + Zustand + TanStack Query |
| 存储 | MySQL 8.0+ / Redis 7 / ClickHouse 24 |
| 消息 | Kafka（KRaft 模式） |
| 监控 | Prometheus |
| 通信 | gRPC 双向流 + mTLS + Protobuf |
| 部署 | Docker Compose / systemd + Nginx |

## 支持平台

**主机 OS**：Rocky Linux 9/10、Oracle Linux 7/8/9、CentOS 7/8/9、Debian 10/11/12、Ubuntu 20.04/22.04

**运行环境**：物理机与虚拟机、Docker 宿主机、Kubernetes 节点与集群

## 快速开始

```bash
git clone https://github.com/matrixplusio/mxcwpp.git
cd mxcwpp/deploy

cp .env.example .env
vim .env  # 修改 SERVER_IP / JWT_SECRET / 数据库密码

# 启动控制面（HA 模式）
docker compose --env-file .env up -d \
  --scale manager=2 --scale agentcenter=2 --scale consumer=2
```

访问 `http://<SERVER_IP>`，用 `admin / admin123` 登录，首次登录会强制修改密码。

前置条件、集群部署与 Agent 安装见 [安装部署](docs/deployment.md)。

## 构建

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
mxcwpp/
├── cmd/
│   ├── agent/              # Agent 入口
│   ├── server/             # agentcenter / consumer / engine / llmproxy / manager / scanner / vulnsync
│   └── tools/              # 运维工具（回放、ETL、迁移）
├── internal/
│   ├── agent/              # Agent（连接、传输、插件管理、EDR 模块）
│   ├── server/             # 后端服务与服务端共享包
│   ├── common/             # Agent 与服务端共用的包
│   └── deploy/             # 部署渲染与仓库检查
├── plugins/                # avscanner / baseline / collector / fim / logcollector / remediation / scanner
│                           # rasp-go / rasp-java / rasp-node / rasp-php / rasp-python；lib/ 为插件共享 SDK
├── api/proto/              # Protobuf 定义
├── web/                    # 控制台（Next.js 15 + React 19 + TypeScript）
├── configs/                # 配置样例与检测规则
├── deploy/                 # Docker Compose、Nginx、systemd 与集群部署
├── sdk/                    # 客户端 SDK（Go / Java / Python）
├── scripts/                # 构建与部署脚本
├── tests/                  # API、端到端、性能与规则测试
└── docs/                   # 文档
```

## 文档

- [架构设计](docs/architecture.md) - 系统拓扑、组件职责、数据链路、高可用设计
- [安装部署](docs/deployment.md) - 前置条件、单机与集群部署、Agent 安装、升级与备份
- [配置说明](docs/configuration.md) - 服务端与 Agent 配置、环境变量
- [API 文档](docs/api-reference.md) - REST 端点、请求/响应格式、认证
- [常见问题](docs/faq.md) - 常见问题与排查
- [开发指南](docs/development.md) - 本地环境、数据库迁移、插件开发
- [贡献指南](CONTRIBUTING.md) - 如何报告问题与提出需求
- [开源治理](docs/governance.md) - 项目角色、决策流程、安全策略

## Star History

[![Star History](docs/assets/star-history.svg)](https://github.com/matrixplusio/mxcwpp/stargazers)

## Contributors

见 [CONTRIBUTORS.md](CONTRIBUTORS.md)。

## License

[GNU Affero General Public License v3.0](LICENSE)

AGPL-3.0 要求衍生作品以相同许可开放，通过网络提供服务时同样适用。
