# ML 异常检测安全说明（M0 + M1 部分）

本文档说明 ML 异常检测引擎（Isolation Forest + 多指标关联）在 M0 的安全默认、模式语义、
schema 闸、可观测性以及启用/回滚方式。M0 的目标是**线上止血**：让这套尚不成熟的 ML 信号
默认不产生任何业务影响，只在显式开启且前置条件就绪后才逐步落库。

## 五种安全模式

由 feature flag `anomaly.detector_mode` 控制（见 `internal/server/engine/anomaly/mode.go`）：

| 模式 | 行为 | 严重度上限 |
| --- | --- | --- |
| `off` | 完全关闭：不消费、不打分、不产任何信号 | — |
| `shadow`（默认） | 照常打分与关联检测，但**只写日志/指标，不落库** `anomaly_alerts` | high |
| `context` | 落库供 SOC 分析上下文；不进入任何自动响应 | high |
| `ranking` | 在 context 基础上，异常分参与**已有告警**的排序（不新建告警）| high |
| `alert` | 允许 critical 定罪（正式告警）| critical |

**安全默认**：缺配置 / 非法值 / DB 查询失败一律回落 `shadow`（绝不回落 `context` / `alert`），
保证"缺配置绝不默认写正式告警"。落库判定用正向白名单——只有**生效** `context` / `alert` 才 upsert，
`off` / `shadow` 及任何降级都不落库（结构性防止 `SetMode` 并发切 `off` 后快照仍落库）。

## Schema 闸（fail-closed）

落库依赖 `anomaly_alerts` 的 `hit_count` / `last_seen_at` 列与去重唯一索引
`ux_anomaly_alerts_dedup`（`tenant_id, host_id, alert_type, pattern_name, top_metric`）。
启动时 `VerifySchema()` 校验，缺任一项则判 schema 未就绪：

- 进程**保持存活**（不 fatal），其余消费功能不受影响；
- 一切会落库的模式（`context` / `alert`）**fail-closed 降级为 `shadow`**（只观测不落库）——
  因为无去重索引会让 upsert 退化成"每次触发新建一行"刷屏；
- `alert` 即便配置也需 schema 就绪才允许 critical。

## 严重度上限（不把 ML 信号当正式高危定罪）

- 仅**生效** `alert` 模式允许 critical，其余（含 `context`）一律封顶 high；
- `c2_beacon` 关联在 M0 仅有 proc/net/DNS **量级**联合升高，**无周期性（beaconing）特征**，
  pattern 声明上限即为 high，Description 明确为"待研判的 process/network/DNS-volume correlation、
  未验证 C2 周期性"。`pattern_name` 保留 `c2_beacon` 仅为兼容既有查询/UI/反馈数据，不代表已证实 C2。

## DNS M0 限制

agent 侧尚未采集真实 DNS 的 domain / rcode，因此：

- `dns_unique_domain`（idx 11）/ `dns_nx_ratio`（idx 12）两维不可信，不计入关联判定；
- `reconnaissance` 依赖 NXDOMAIN 枚举，M0 **整体禁用**；
- `dns_query` 事件的 `remote_addr` 是 resolver IP，不是被查询域名，**绝不**作为 `SuspiciousDomains` 富化
  （避免"把 resolver IP 称作 domain"）；
- `dns_query_count`（idx 10）只是计数、不依赖 domain/rcode，仍可信。

`dnsValid` 默认 `false`；M1 接通真实 domain/rcode 后再放开（同时置位 `dns_field_ready` 指标）。

## 可观测性：/readyz 与 Prometheus

- **/readyz**（Consumer 独立 HTTP 端口，默认 `:9100`）聚合各组件就绪检查，`anomaly_schema` 未就绪返回 503。
  与 `/healthz`（进程存活）区分：schema 未就绪时进程仍存活（只观测不落库），但 `/readyz` 报未就绪。
- **Prometheus 指标**（低基数，无 `host_id` label，注册在 Consumer 独立 registry，启动初始化并每 30s 刷新）：
  - `mxcwpp_anomaly_detector_mode{mode}` / `mxcwpp_anomaly_detector_effective_mode{mode}`：配置/生效模式 one-hot；
  - `mxcwpp_anomaly_schema_ready` / `mxcwpp_anomaly_dns_field_ready` / `mxcwpp_anomaly_iforest_trained`：0/1；
  - `mxcwpp_anomaly_sample_count` / `mxcwpp_anomaly_host_count`：训练样本数 / 已跟踪主机数。

## 如何显式启用

1. 先确认 schema 就绪：`/readyz` 中 `anomaly_schema=ready`（或指标 `mxcwpp_anomaly_schema_ready=1`）。
   若未就绪，检查迁移 `migrateAnomalyAlertDedup` 是否成功建索引。
2. 灰度落库上下文：把 flag `anomaly.detector_mode` 设为 `context`（经 manager admin API）。
   观察 `mxcwpp_anomaly_detector_effective_mode{mode="context"}=1`，严重度仍封顶 high。
3. 如需正式告警（谨慎）：设为 `alert`。仅在 schema 就绪时才生效为 `alert` 并允许 critical。

## 如何回滚

- 立即止血：把 flag 设回 `shadow`（继续观测但不落库）或 `off`（完全停）。Consumer 每 30 秒重载一次，最迟一个刷新周期生效；重启也会立即加载。
- 无需回滚代码：模式是运行时开关，安全默认恒为 `shadow`。

## M1 进展（2026-07-31 更新）

M0 只是安全止血，**不代表 ML 达到行业先进水平**。M1 清单及当前状态：

| 项 | 状态 | 说明 |
| --- | --- | --- |
| **漂移 / 投毒防护** | ✅ 已做 | 长期参照基线（不随滑窗移动）+ 3σ 拒绝重训。见下节 |
| **质量度量（precision）** | ✅ 已做 | 仅由人工研判计算（confirmed / false_positive），open 不计入；样本不足返回 `null` 而非 0 |
| **升档门槛** | ✅ 已做 | 升 context 需已研判 ≥30 且总体 ≥70%，且无任何单模式 <50%；降档无条件允许 |
| **参照基线持久化** | ✅ 已做 | 存 `anomaly_model_states`，跨重启恢复 |
| **模型本身持久化 / 版本化** | ❌ **未做** | 只持久化了参照基线，**森林没有落盘**。重启后仍需重新积累样本 + 等一个重训周期（30 分钟）才恢复评分能力 |
| **feature store** | ❌ 未做 | 仍是进程内内存缓冲 |
| **时间切分验证** | ❌ 未做 | 无训练/验证集划分，无泛化评估 |
| **recall 测量** | ❌ **未做** | 需要标注的主机指标时序语料。检测规则那套回放语料（进程/文件事件）不覆盖这里。**这是真空白，不要当成已覆盖** |
| **真实 DNS domain/rcode 采集** | ❌ 未做 | DNS 相关维与 `reconnaissance` 仍关闭 |

### 漂移与训练投毒

IForest 每 30 分钟用滑动窗口重训，"什么算正常"由最近看到的数据决定。这有个固有弱点：
**攻击者只要把动作放慢到跨越多个训练窗口，每窗只比上窗高一点，逐窗比较永远正常，
最后攻击行为成为基线。**

对策是保留一份**不随滑窗移动**的长期参照基线；训练窗口偏离超过 3σ 时**拒绝本轮重训**，
继续使用旧模型——宁可模型变旧，也不要学一个被污染的新模型。

| 指标 | 含义 |
| --- | --- |
| `mxcwpp_anomaly_reference_baseline_ready` | 参照基线是否就绪（**0 = 投毒防护未生效**）|
| `mxcwpp_anomaly_feature_drift` | 各维度相对参照的偏移（σ）|
| `mxcwpp_anomaly_retrain_rejected_total` | 被拒绝的重训次数 |
| `mxcwpp_anomaly_model_age_seconds` | 距上次成功训练的时长 |

**能力边界**：建立参照基线的那一刻若环境中已有攻击，参照本身就是脏的。
剔除极端值只能挡住少数离群点，挡不住"从一开始就被入侵"。

### ranking 档：排序，不定罪

异常分只影响 `risk_score`，从而改变告警在列表里的先后，**不产生任何告警、不提升严重度**。

加权封顶 1.15，而相邻严重度档的基础分差是 20（high 60 / critical 80）——
`60 × 1.15 = 69`，够不到 80。**再异常的主机也无法把一条 high 顶进 critical 的分数区间。**
这是结构性保证，不是调参：跨档就是定罪，而无监督检测给出的是「少见」不是「恶意」。

跨进程通路：检测器在 consumer 进程评分并周期写 `host_anomaly_scores`，
engine 进程经原子快照读取（与资产权重、关联加权同一条路，热路径零 DB 查）。
分数超过 2 小时不再参与排序——一台主机昨天异常不代表现在异常。

升 ranking 门槛严于 context：已研判 ≥50 条且精确率 ≥80%。
排错顺序的代价不是多看一条，而是把真实威胁推到没人看得完的列表后面。

### alert 档在 1.0 不开放

无监督异常检测给出的是"少见"，不是"恶意"。季度结算、批量导数、临时扩容都少见。
让它独立定罪的结果是值班被无害事件淹没，从此不再看告警。
`EvaluateModeChange` 对 `alert` 档硬拒（`blocking=true`），不受数据好坏影响。
**ML 在 1.0 的位置是排序与佐证，不是定罪。**
