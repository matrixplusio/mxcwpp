# 文档

先读仓库根目录的 [README](../README_ZH.md)：功能、截图、快速开始都在那里。下面按读者分类。

## 运维与部署

| 文档 | 内容 |
|---|---|
| [安装部署](operations/deployment.md)（[English](operations/deployment.en.md)） | 前置条件、单机与集群部署、Agent 安装、升级与备份 |
| [配置说明](operations/configuration.md) | 服务端与 Agent 的配置项、环境变量 |
| [常见问题](operations/faq.md) | 部署与运行中的常见问题及排查 |

## 开发者

| 文档 | 内容 |
|---|---|
| [架构设计](development/architecture.md)（[English](development/architecture.en.md)） | 系统拓扑、组件职责、数据链路、高可用设计 |
| [开发指南](development/development.md) | 本地环境、数据库迁移、插件开发 |
| [代码风格与质量规范](development/code-style.md) | Go 与前端的编码约定 |
| [DataType 分配表](development/datatype-allocation.md) | Agent 上报数据类型编号的分配 |

贡献方式与提交约定见 [CONTRIBUTING.md](../CONTRIBUTING.md)。

## 参考

| 文档 | 内容 |
|---|---|
| [API 参考](reference/api-reference.md) | REST 端点、请求与响应格式、认证；每个路由都必须登记在这里（有门禁） |
| [OpenAPI](reference/openapi/) | OpenAPI 3.0 定义，目前只收录部分端点，完整列表以 API 参考为准 |
| [漏洞统计口径](reference/vuln-stats-glossary.md) | 漏洞相关数字的统计口径 |
| [ML 异常检测安全说明](reference/ml-anomaly-safety.md) | ML 异常检测的安全默认、模式与回滚 |

## 项目

| 文档 | 内容 |
|---|---|
| [开源治理](governance.md) | 治理模型、决策流程、版本管理 |
| [安全策略](../SECURITY.md) | 漏洞报告方式与处理目标 |
| [变更记录](../CHANGELOG.md) | 各版本的变化 |
