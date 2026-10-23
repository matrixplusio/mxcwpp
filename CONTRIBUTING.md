# 贡献指南

感谢关注本项目。

## 如何参与

本项目**通过 Issue 接受反馈，不接受 Pull Request**。代码改动由维护者实现。

- **报告缺陷**：用 [Bug 报告模板](https://github.com/matrixplusio/mxcwpp/issues/new?template=bug_report.md) 提交，写清版本、环境、复现步骤、期望与实际结果。
  日志与配置请先去掉主机名、地址、口令等环境信息。
- **提出需求**：用 [功能需求模板](https://github.com/matrixplusio/mxcwpp/issues/new?template=feature_request.md)，说明要解决的问题和使用场景，而不只是想要的做法。
- **安全漏洞**：不要提公开 Issue，流程见 [SECURITY.md](SECURITY.md)。

下面是维护者的开发约定，也供想在本地构建、二次开发的读者参考。

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

## 分支与提交

- 在本地功能分支上开发，完成后压成一个提交合入集成分支 `dev`；`main` 只接收验证过的发布单元，直接推送。
- **一个任务一个提交**。只有跨模块的大改动才拆成多条，且每条自身都要能编译、能测试。
- 推之前先看上一次 CI 是否为绿；红着就先修红，不在红的基础上继续叠推送。
- 不 amend、不强推已经推出去的提交。

## 提交信息

格式为 `<type>: <描述>`，类型限于：

```
feat  fix  docs  test  chore  refactor  perf  style  build  ci  revert
```

**标题一行，说清改了什么**，控制在 72 显示列以内（中文算 2 列）。正文可有可无，有就只写「为什么这么改」，代码本身已经说明了「改了什么」。不写 `wip`、`更新` 这类等于没说的标题。

---

## 本地验证

提交前跑完这三步，它们与自动检查执行的是同一套：

```bash
make fmt     # 格式化，之后 git diff 应为空
make lint    # golangci-lint，必须 0 issues
make test    # 全量测试，包含下面的门禁
```

钩子把快速检查前移到提交与推送时。`make test`、`make lint`、`make dev-docker-up` 会自动启用，也可以手动：

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

规则只有一份：`.githooks/leakscan.sh`（生产来源标记在 `.githooks/prod-claim-patterns`）。下面几处都调用它：

| 时机 | 扫什么 | 能否绕过 |
|------|--------|----------|
| pre-commit | 本次暂存的新增行 | 本地钩子，尽早提醒 |
| commit-msg | 提交信息 | 本地钩子，尽早提醒 |
| pre-push（推往 GitHub）| 要推出去的**每一个** commit 的新增行、作者、提交信息、新增文件路径；附注 tag 的说明 | 命中即拒绝，推送批准记录放不过它 |
| `make test` | 当前树的全部文本文件 | — |
| CI「泄露扫描」 | 本次推送的每一个 commit（只用公开规则，本地清单不上传）| — |

拦截项：

- 文档保留段之外的 IP 地址
- 本地清单 `.production-identifiers`（仓库外、gitignore）登记的环境标识；**清单缺失时拒绝推送**
- 生产来源标记与具体数字同一行出现（`生产上`、`prod 实测`、`实测 prod`、带日期的 prod 或事故叙述等）
- 「实测」加具体数字、又没注明是实验室数据（基准、压测、本仓库、内核等）
- 本地清单里 `re:` 开头的正则（业务线编号这类格式）与 `path:` 开头的路径规则
- 事故叙事与规模描述（不带数字也拦）
- 形态明确的凭证：私钥、云与代码托管令牌、命令行 `--password`、带密码的 DSN
- 不该公开的文件：`local-reports/`、证书与私钥、kubeconfig、`.env`、数据库备份

pre-push 扫每个 commit 而不是最终 diff：中间 commit 一样会公开，后来删掉的内容照样留在历史里。

行尾写 `leakscan:example` 可跳过来源、业务线、凭证三项检查，只留给讲解规则本身的文档和门禁的反例固件；地址与本地清单不受它影响。

配套工具：

- `scripts/refresh-denylist.sh`：从真实环境收集名字（本机 kubeconfig，加上本地 `scripts/denylist-sources.local.sh` 定义的只读查询），写进本地清单的自动生成段。默认只列候选词和它们在当前树的命中数，确认没有通用词后加 `--write`。
- `scripts/audit-remote.sh <URL>`：匿名克隆一个远端仓库的全部引用，按同一套规则逐提交检查。

**改门禁时注意**：不要把要拦截的字符串写进门禁自己的正则或测试样本 —— 那等于把要防的东西写进了仓库。反例固件用合成值（编造的编号和数字），既能自检又不含真实数据。`TestLeakscanCatchesKnownShapes` 与 `TestPrePushBlocksLeaks` 钉住规则确实拦得住，正则失效时会失败而不是静默放行。

### 接线门禁

`TestNoUndeclaredUnwiredPackages` 另拦一类问题：`internal/` 或 `pkg/` 下新增的包若没有任何导入者，构建失败。

这不是风格要求。代价最高的缺陷是静默失效 —— 能力写完、编译通过、日志干净，但没有调用方，于是它从来没有生效过，而编译器和测试都不会报错。

包没有导入者本身不是错，不声明才是错。确实还不该接线的，登记到 `internal/deploy/testdata/unwired-packages.tsv` 并写明原因。清单双向校验：新出现的未接线包会被拦下，已经接线却仍留在清单里的也会被拦下。

`TestEveryClickHouseTableHasAWriter` 盯的是同一类问题的另一种形态：表建在 `deploy/init-clickhouse.sql` 里，部署时照常创建，查询它的代码也编译得过 —— 只是永远查到空。Go 包的导入者关系看不到它。每张建出来的表都必须在代码里有 `INSERT INTO`，否则登记到 `internal/deploy/testdata/clickhouse-tables-without-writer.tsv`。物化视图由源表驱动，不在检查范围。

---

## 文档同步

改了代码就要改对应的文档。有门禁的那些会直接构建失败，不用记；**没有门禁的四项需要主动做**。

| 改动 | 必须更新 | 有门禁 |
|------|----------|--------|
| 新增/修改 HTTP 路由 | `docs/reference/api-reference.md` + `router/testdata/routes.golden` | ✅ |
| 新增 Prometheus 指标 | `deploy/config/prometheus-rules.yml` 加告警规则 | ✅ |
| 新增/删除检测 Stage | `internal/server/engine/capability.go` 清单 | ✅ |
| 新增 DataType | `docs/development/datatype-allocation.md` | ✅ |
| 新增基线策略文件 | `plugins/baseline/config/README.md` 的统计 | ✅ |
| 新增 `internal/`/`pkg/` 下的包 | 必须有导入者，否则登记 `internal/deploy/testdata/unwired-packages.tsv` | ✅ |
| 新增 ClickHouse 表 | 必须有写入方，否则登记 `internal/deploy/testdata/clickhouse-tables-without-writer.tsv` | ✅ |
| 新增服务/模块/包 | `docs/development/architecture.md` | ❌ |
| 配置项增删 | `docs/operations/configuration.md` | ❌ |
| 部署步骤变化 | `docs/operations/deployment.md` | ❌ |

---

## 改动尺度

**简单优先。** 不做超出需求的功能，不为不可能发生的场景写错误处理。200 行能用 50 行完成就用 50 行。

**精准改动。** 不顺手优化相邻代码，不重构没有坏的东西，匹配周围既有的风格。移除因自己改动而失效的代码，但不动改动前就存在的死代码。

检验标准：每一行改动都能追溯到这次要解决的问题。

---

## 测试

新增逻辑要带测试。测试要能真的抓住回归 —— 一个从不失败的测试比没有测试更糟，因为它让人以为这里有人管。

写完之后自问：把被测的那行代码改坏，这个测试会失败吗？如果不会，它测的不是你以为的东西。

---

## 验证与排查

- **声称「完成 / 修好了」之前，必须真的执行验证命令。** 没跑就说没跑，失败就贴失败输出。
- 用**退出码**判断成败，不要匹配错误文本——措辞一变就会误报成功。
- **验证成功要用只有成功才会出现的信号**：计数归零、目标端出现对应记录、状态字段翻转。「错误变了」不等于「修好了」。
- 部署之后验证两件事：**跑的确实是新代码**（比对二进制里的版本信息，构建缓存会让「构建成功」不等于新代码进去了）；**能力真的生效**（端到端有数据产出，不是容器 healthy、日志没报错）。
- **先问「是不是被什么挡住了」，再问「是不是坏了」**；判断「停了」之前先确认此刻本该在动；数字对不上时，先怀疑自己在量什么。
- 批量替换先 dry-run，逐处过目改前 / 改后再落盘，用带词界的正则，不用裸子串。

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
4. 最小支持分辨率 **1280×720**，浅色与暗色都要在此尺寸下正常显示：页面无横向滚动，
   按钮、表头、标签不折行，数值不被截断。具体做法：
   - 表格的短值列（IP、版本、时间、状态）设 `nowrap`；操作列（`key: "actions"`）自动不换行
   - 主机 ID、哈希、URL 这类长串用 `truncate` 时要给出 `max-w-*`，否则表格自动布局下截断不生效
   - 主机列、IP 列、时间列直接用 `HostCell`、`IpList`、`DateTimeCell`，不要各页手写——
     真实环境的主机名、多网卡 IP 和 64 位 host_id 远比测试数据长
   - 多段文本用 `line-clamp-*`，不要用单行 `truncate`——单行不能换行，会把整张表撑宽
   - 统计卡片一行超过 4 张时，`2xl` 以下改为每行 3 张

---

## 报告安全问题

不要用公开 issue 报告安全漏洞，流程见 [SECURITY.md](SECURITY.md)。

---

## 参考

[架构](docs/development/architecture.md) ·
[API](docs/reference/api-reference.md) ·
[配置](docs/operations/configuration.md) ·
[部署](docs/operations/deployment.md) ·
[代码规范](docs/development/code-style.md) ·
[DataType 分配](docs/development/datatype-allocation.md)
