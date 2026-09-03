# 漏洞统计口径术语表

**目的**：漏洞数据落在两张表(`vulnerabilities` = 全局 CVE 目录 / `host_vulnerabilities` = 主机漏洞实例)，
历史上不同端点随手挑表挑字段，导致同名指标(如"漏洞总数""已修复")在不同页面数值对不上。
本表锁定每个指标的**唯一权威口径**，新增任何漏洞统计**必须**遵循，禁止再从 `vulnerabilities`
的 CVE 级字段派生实例级展示。

## 两张表的分工

| 表 | 含义 | 粒度 |
|---|---|---|
| `vulnerabilities` | 通告拉进来的 CVE 全集(含大量从不命中任何主机的库存条目) | CVE 级(一行 = 一个 CVE) |
| `host_vulnerabilities` | 某主机实际命中某漏洞的关联记录 | 实例级(一行 = 主机 × 漏洞) |

## 指标定义

| 指标 | 权威口径 | 展示位置 | 禁止用 |
|---|---|---|---|
| **漏洞种类** | `COUNT(DISTINCT vulnerabilities.id)` WHERE `EXISTS host_vulnerabilities`(命中主机的 CVE 去重数) | 漏洞列表页顶部卡片 | ❌ `vulnerabilities` 全表 COUNT(含 orphan 库存) |
| **主机漏洞实例** | `COUNT(*) FROM host_vulnerabilities WHERE status != 'ignored'` | 修复页顶部卡片 | ❌ `vulnerabilities.affected_hosts` 求和(stale) |
| **已修复实例** | `COUNT(*) FROM host_vulnerabilities WHERE status = 'patched'` | 修复页卡片 + 趋势图 + 修复页"已修复明细"表 | ❌ `vulnerabilities.status='patched'` |
| **列表页状态筛选** | `EXISTS host_vulnerabilities WHERE vuln_id=… AND status=?`(该 CVE 有此状态的实例即命中) | 漏洞列表页"已修复/未修复"筛选 | ❌ `vulnerabilities.status=?`(CVE 级,漏掉部分修复) |
| **修复率** | 已修复实例 / (主机漏洞实例)  | 修复页 | ❌ CVE 级派生 |
| **MTTR** | `AVG(TIMESTAMPDIFF(HOUR, created_at, patched_at))` on `host_vulnerabilities` WHERE `patched` | 修复页 | — |
| **每日检出趋势** | `host_vulnerabilities` 按 `DATE(created_at)` 分组(主机首次检出) | 修复页趋势图 | ❌ `vulnerabilities.discovered_at`(= advisory 发布日，与主机无关) |
| **每日修复趋势** | `host_vulnerabilities` 按 `DATE(patched_at)` WHERE `patched` | 修复页趋势图 | ❌ `vulnerabilities.patched_at` |

## 为什么禁用 `vulnerabilities` 的 per-host 字段

`vulnerabilities` 表带 `status` / `patched_at` / `discovered_at` / `affected_hosts` / `patched_hosts`
5 个 CVE 级聚合字段(见 `internal/server/model/vulnerability.go` 注释):

- `status` / `patched_at` 是 **CVE 级 rollup** —— 仅当该 CVE **全部**命中主机都修好才置 `patched`。
  故绝大多数恒为 `unpatched` / `NULL`。拿它算修复率恒 0、算趋势与实例级卡片打架。
- `discovered_at` = advisory 首次入库/发布日，与"主机何时检出"无关。
- `affected_hosts` / `patched_hosts` 是维护中的计数，有 stale 风险(用 `EXISTS`/`COUNT` 实查)。

**真实修复成果与时间线只在 `host_vulnerabilities`。** CVE 级 rollup 仅供内部生命周期判断，不上界面。

## CVE 级 vs 实例级举例(prod 2026-07-02)

- 漏洞种类 = 1005(命中主机的 CVE 去重)
- 主机漏洞实例 = 28874(一个 CVE 命中 N 台主机 → N 行)

两者相差数十倍是**正常**的量纲差异，不是数据错误。列表页与修复页因此展示不同数字，各自 label 已标明口径。
