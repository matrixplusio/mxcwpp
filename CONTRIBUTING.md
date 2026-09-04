# 贡献指南

感谢参与。这份文档说明如何提交改动，以及哪些约束会在自动检查里拦下你 —— 提前知道能省一轮返工。

---

## 快速开始

```bash
git clone https://github.com/matrixplusio/mxcwpp.git
cd mxcwpp
make proto      # 生成 Protobuf 代码（生成物不入库，必须先跑）
make fmt lint test
```

`make proto` 是必需的第一步：`api/proto/` 下的生成代码不纳入版本控制，跳过它编译会失败。

---

## 分支与 PR

### 从 `dev` 切分支，不要从 `main`

```bash
git checkout dev
git pull upstream dev
git checkout -b <你的用户名>/<type>-<简短描述>
```

`type` 与提交类型一致（`feat` / `fix` / `docs` …）。

### 保持分支基线干净

**这是最常见的失败原因。** fork 之后如果直接在 `main` 上改，再把整个 `main` 提回来，PR 会包含上游的全部历史 —— GitHub 算不出有效差异，会显示 `0 changed files`，无法评审也无法合并。

提 PR 前自查：

```bash
git log --oneline upstream/dev..HEAD    # 应该只有你自己的提交
git diff --stat upstream/dev..HEAD      # 应该只有你改的文件
```

如果看到几十上百个不属于你的提交，说明基线错了。修法：

```bash
git fetch upstream
git rebase upstream/dev
```

### 一个 PR 一件事

改动跨越多个不相关的模块时拆成多个 PR。评审成本和 PR 大小不是线性关系。

---

## 提交信息

格式为 `<type>: <描述>`，类型限于：

```
feat  fix  docs  test  chore  refactor  perf  style  build  ci  revert
```

**标题控制在 60 字符以内**，细节写进正文。正文说明「为什么这么改」，代码本身已经说明了「改了什么」。

不要在提交信息中出现 AI 工具名称或 AI 生成署名。

---

## 本地验证

提交前跑完这三步，它们与自动检查执行的是同一套：

```bash
make fmt     # 格式化，之后 git diff 应为空
make lint    # golangci-lint，必须 0 issues
make test    # 全量测试，包含下面的门禁
```

安装 pre-commit 钩子可以把快速检查前移到提交时：

```bash
make hooks
```

钩子只做「快且必然失败」的检查（格式、冲突标记、明文令牌、发布约束），构建与测试留给 `make test`。

---

## 发布约束

本仓库公开发布，**不要写入任何具体运行环境的数据**。

判据是**来源**而不是长相：一个数字读起来再像技术依据，只要它取自某套真实运行的系统，写进仓库就等于把那套系统的规模、事故经过、误报率一并发布出去。注释、测试固件、提交信息一视同仁。

| 不要写 | 改成 |
|--------|------|
| `实测环境 111,111 条事件` | `数十万条事件` | <!-- leakscan:example -->
| `1234 台主机某计数器全为 0` | `全机群该计数器为 0` |
| 真实业务线编号 / 主机名 | `line-a` / `host-1` |
| 真实内网或公网地址 | 文档保留段（`203.0.113.x` / `10.0.0.x`，见 RFC 5737）|

需要记录真实环境细节时写到 `local-reports/`（已 gitignore）。

### 发布内容门禁

规则只有一份：`.githooks/leakscan.sh`（生产来源标记在 `.githooks/prod-claim-patterns`）。三个地方调用它：

| 时机 | 扫什么 | 能否绕过 |
|------|--------|----------|
| pre-commit | 本次暂存的新增行 | `--no-verify` 可跳过，只是尽早提醒 |
| pre-push（推往 GitHub）| 要推出去的**每一个** commit 的新增行、提交信息、新增文件路径 | 命中即拒绝，推送批准记录放不过它 |
| `make test` | 当前树的全部文本文件 | — |

拦截项：

- 文档保留段之外的 IP 地址
- 本地清单 `.production-identifiers`（仓库外、gitignore）登记的环境标识；**清单缺失时拒绝推送**
- 生产来源标记与具体数字同一行出现（`生产上`、`prod 实测`、`实测 prod`、带日期的 prod 或事故叙述等）
- 「实测」加具体数字、又没注明是实验室数据（基准、压测、本仓库、内核等）
- 业务线编号
- 形态明确的凭证：私钥、云与代码托管令牌、命令行 `--password`、带密码的 DSN
- 不该公开的文件：`local-reports/`、证书与私钥、kubeconfig、`.env`、数据库备份

pre-push 扫每个 commit 而不是最终 diff：中间 commit 一样会公开，后来删掉的内容照样留在历史里。

行尾写 `leakscan:example` 可跳过来源、业务线、凭证三项检查，只留给讲解规则本身的文档和门禁的反例固件；地址与本地清单不受它影响。

**改门禁时注意**：不要把要拦截的字符串写进门禁自己的正则或测试样本 —— 那等于把要防的东西写进了仓库。反例固件用合成值（编造的编号和数字），既能自检又不含真实数据。`TestLeakscanCatchesKnownShapes` 与 `TestPrePushBlocksLeaks` 钉住规则确实拦得住，正则失效时会失败而不是静默放行。

### 接线门禁

`TestNoUndeclaredUnwiredPackages` 另拦一类问题：`internal/` 或 `pkg/` 下新增的包若没有任何导入者，构建失败。

这不是风格要求。本项目代价最高的缺陷是静默失效 —— 能力写完、编译通过、日志干净，但没有调用方，于是它从来没有生效过；AC 的规则同步与 IOC 同步、celengine 的清理协程、蜜罐的监听器都是这样缺失的，编译器和测试都不会说。

包没有导入者本身不是错，不声明才是错。确实还不该接线的，登记到 `internal/deploy/testdata/unwired-packages.tsv` 并写明原因。清单双向校验：新出现的未接线包会被拦下，已经接线却仍留在清单里的也会被拦下。

`TestEveryClickHouseTableHasAWriter` 盯的是同一类问题的另一种形态：表建在 `deploy/init-clickhouse.sql` 里，部署时照常创建，查询它的代码也编译得过 —— 只是永远查到空。Go 包的导入者关系看不到它。每张建出来的表都必须在代码里有 `INSERT INTO`，否则登记到 `internal/deploy/testdata/clickhouse-tables-without-writer.tsv`。物化视图由源表驱动，不在检查范围。

---

## 文档同步

改了代码就要改对应的文档。有门禁的那些会直接构建失败，不用记；**没有门禁的四项需要主动做**。

| 改动 | 必须更新 | 有门禁 |
|------|----------|--------|
| 新增/修改 HTTP 路由 | `docs/api-reference.md` + `router/testdata/routes.golden` | ✅ |
| 新增 Prometheus 指标 | `deploy/config/prometheus-rules.yml` 加告警规则 | ✅ |
| 新增/删除检测 Stage | `internal/server/engine/capability.go` 清单 | ✅ |
| 新增 DataType | `docs/datatype-allocation.md` | ✅ |
| 新增基线策略文件 | `plugins/baseline/config/README.md` 的统计 | ✅ |
| 新增 `internal/`/`pkg/` 下的包 | 必须有导入者，否则登记 `internal/deploy/testdata/unwired-packages.tsv` | ✅ |
| 新增 ClickHouse 表 | 必须有写入方，否则登记 `internal/deploy/testdata/clickhouse-tables-without-writer.tsv` | ✅ |
| 新增服务/模块/包 | `docs/architecture.md` | ❌ |
| 配置项增删 | `docs/configuration.md` | ❌ |
| 部署步骤变化 | `docs/deployment.md` | ❌ |
| 任务完成/受阻 | `docs/roadmap.md` | ❌ |

---

## 改动尺度

**简单优先。** 不做超出需求的功能，不为不可能发生的场景写错误处理。200 行能用 50 行完成就用 50 行。

**精准改动。** 不顺手优化相邻代码，不重构没有坏的东西，匹配周围既有的风格。移除因自己改动而失效的代码，但不动改动前就存在的死代码。

检验标准：每一行改动都能追溯到这个 PR 要解决的问题。

---

## 测试

新增逻辑要带测试。测试要能真的抓住回归 —— 一个从不失败的测试比没有测试更糟，因为它让人以为这里有人管。

写完之后自问：把被测的那行代码改坏，这个测试会失败吗？如果不会，它测的不是你以为的东西。

---

## 编码规范

### Go

1. 日志用 `zap`，不用 `fmt.Println` / `log.Println`
2. HTTP 响应用 `response.go` 提供的 `Success` / `BadRequest` / `NotFound` / `InternalError`
3. 返回 `error` 而不是 `panic`，用 `fmt.Errorf` 包装并保留上下文
4. 配置从配置文件读取，不硬编码
5. 数据库查询用预加载避免 N+1，多步写入用事务

### React / TypeScript

1. API 调用封装在 `web/src/lib/api/`，组件内不直接调 axios
2. 定义接口类型，数据请求统一走 TanStack Query
3. 命名：组件 PascalCase，函数 camelCase，常量 UPPER_CASE

---

## 报告安全问题

不要用公开 issue 报告安全漏洞，流程见 [SECURITY.md](SECURITY.md)。

---

## 参考

[架构](docs/architecture.md) ·
[API](docs/api-reference.md) ·
[配置](docs/configuration.md) ·
[部署](docs/deployment.md) ·
[代码规范](docs/code-style.md) ·
[DataType 分配](docs/datatype-allocation.md) ·
[路线图](docs/roadmap.md)
