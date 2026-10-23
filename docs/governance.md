# 开源治理

## 治理模型

本项目由维护者主导（见 [CONTRIBUTORS.md](../CONTRIBUTORS.md)），维护者负责项目方向、架构决策、代码实现、审查与版本发布。

外部参与通过 Issue 进行：报告缺陷、提出需求、参与讨论。项目**不接受 Pull Request**，代码改动由维护者实现，详见 [CONTRIBUTING.md](../CONTRIBUTING.md)。

## 决策流程

- **日常变更**（缺陷修复、文档改进、小型功能）：维护者直接实施，按 [CONTRIBUTING.md](../CONTRIBUTING.md) 的本地验证与发布约束执行。
- **重大变更**（架构调整、新增或替换核心依赖、不向后兼容的 API 或协议变更、安全模型变更）：先在 Issue 中公开设计与取舍，讨论结论以评论形式记录在该 Issue 中，便于追溯。

## 版本管理

### 版本号

遵循 [Semantic Versioning 2.0.0](https://semver.org/)：`MAJOR.MINOR.PATCH`

- **MAJOR**：不兼容的 API 或协议变更
- **MINOR**：向后兼容的功能新增
- **PATCH**：向后兼容的缺陷修复

正式版本前可发布 RC 版本，Tag 格式为 `v1.0.0-rc.1`、`v1.0.0-rc.2`；RC 阶段只接受缺陷修复。

### 发布流程

1. 计划内的改动已合入，`make lint` 与 `make test` 通过
2. 更新版本号与 [CHANGELOG](../CHANGELOG.md)
3. 创建 Release Tag 并发布 GitHub Release
4. 构建并发布安装包与镜像
5. 同步更新文档

MAJOR 版本须同时提供迁移说明：不兼容变更清单、逐项迁移步骤、数据库 schema 迁移脚本（如有）、配置格式变更。

## 安全

漏洞报告与处理流程见 [SECURITY.md](../SECURITY.md)。

## 代码质量

合入主分支的代码须满足：

- `make lint` 与 `make test` 通过（含发布内容门禁与文档同步检查）
- 不引入已知漏洞依赖（`make vuln`）
- 新增功能带测试，缺陷修复带回归测试
- 数据库 schema 变更附迁移脚本，并验证向后兼容
- 涉及认证、授权、加密、输入处理的改动，对照安全审查清单逐项检查

## 行为准则

本项目遵循 [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/)，详见 [CODE_OF_CONDUCT.md](../CODE_OF_CONDUCT.md)。违反准则的行为可通过 contact@matrixplus.io 报告。

## 许可证

本项目使用 [GNU Affero General Public License v3.0](../LICENSE)。
