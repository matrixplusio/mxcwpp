# 漏洞管理模块升级设计方案

**版本**: v1.1-draft  
**日期**: 2026-05-15  
**状态**: 待评审  
**范围**: 漏洞情报 / 漏洞扫描 / 漏洞修复 三大模块全面升级

---

## 一、现状分析

### 1.1 已实现能力

| 模块 | 能力 | 核心文件 |
|------|------|---------|
| 情报 | OSV.dev + NVD + Red Hat 三源同步 | `vuln_scanner.go`, `nvd_sync.go`, `redhat_sync.go` |
| 情报 | CVSS v3.1 完整向量解析与评分 | `vuln_scanner.go` |
| 扫描 | PURL 批量查询 OSV.dev（1000/批，50 并发） | `vuln_scanner.go` |
| 扫描 | 增量优化，已知漏洞缓存减少 ~70% API 调用 | `vuln_scanner.go` |
| 扫描 | NVD CPE 匹配 + 描述关键词回退匹配 | `nvd_sync.go` |
| 扫描 | Red Hat 受影响包 RPM 名称提取匹配 | `redhat_sync.go` |
| 修复 | RPM/DEB 自动生成修复命令 | `remediation.go` |
| 修复 | 任务全生命周期（pending→confirmed→running→success/failed） | `remediation_executor.go` |
| 修复 | 三级超时（pending 24h / confirmed 1h / running 30min） | `remediation_executor.go` |
| 修复 | 执行后版本对比自动验证 | `remediation_verify.go` |
| 修复 | Dry-Run 预览 + gRPC 下发 Agent 执行 | `remediation_executor.go` |
| 修复 | MTTR / 修复率 / 按严重级别分布 / 30 天趋势 | `remediation.go` |

### 1.2 当前数据模型

```go
// vulnerability.go — 当前字段
type Vulnerability struct {
    ID, CveID, OsvID, PURL, Severity, CvssScore, Component,
    Description, AffectedHosts, PatchedHosts, Status,
    DiscoveredAt, PatchedAt, CurrentVersion, FixedVersion, ReferenceUrl
}

type HostVulnerability struct {
    ID, VulnID, HostID, Hostname, IP, CurrentVersion, Status, PatchedAt
}

type RemediationTask struct {
    ID, VulnID, CveID, HostID, Hostname, IP, Component, FixedVersion,
    Command, Status, ExecOutput, ExitCode, CreatedBy, ConfirmedBy,
    ConfirmedAt, StartedAt, FinishedAt
}
```

### 1.3 竞品对标

| 能力 | MxCwpp 当前 | 青藤万相 | CrowdStrike | Qualys/Tenable |
|------|-----------|---------|-------------|----------------|
| 数据源覆盖 | 3 源 | 10+ 源（含 CNVD/CNNVD） | 自研情报 + NVD + KEV | 20+ 源 |
| 漏洞优先级 | 仅 CVSS | 多维评分 | Threat Graph 关联 | EPSS + 资产权重 |
| 定时扫描 | 手动触发 | 自动周期 | 实时 Sensor | 自动周期 |
| 语言依赖 | 无 | 支持 | 支持 | 核心能力 |
| 容器扫描 | 无 | 支持 | 支持 | 支持 |
| 离线模式 | 无 | 支持 | 无（SaaS） | 混合 |
| 修复编排 | OS 包更新 | OS + 中间件 | OS + 自动隔离 | OS + 虚拟补丁 |
| 国内编号 | 无 | CNVD/CNNVD | 无 | 无 |

### 1.4 差距总结

- **情报**: 缺少 CNVD/CNNVD（国内合规刚需）、无在野利用标记、无智能优先级
- **扫描**: 仅覆盖 OS 包管理器，缺少语言依赖/容器镜像/定时调度
- **修复**: 最完善的模块，需补齐批量策略和语言级修复能力

---

## 二、漏洞情报升级

### 2.1 CNVD / CNNVD 数据源接入

#### 背景

国内等保（GB/T 22239）和关基保护要求漏洞报告覆盖 CNVD/CNNVD 编号，当前平台仅有国际数据源，无法满足国内合规场景。

#### 数据获取方案

**CNVD（国家信息安全漏洞共享平台）**

| 方案 | 方式 | 优点 | 缺点 | 推荐 |
|------|------|------|------|------|
| A | 第三方聚合 API（漏洞盒子/奇安信 CERT） | 数据结构化、更新快 | 需评估授权和费用 | ★★★ |
| B | 爬取公开页面 `cnvd.org.cn/flaw/list` | 无需授权 | 被封 IP 风险、HTML 结构变化 | ★★ |
| C | CNVD 技术组成员申请批量数据包 | 最全面 | 审批周期长、需资质 | ★ |

- 推荐：先用方案 A 快速接入，中期申请方案 C
- 关键字段：CNVD 编号、标题、危害等级、影响产品、CVE 映射、公开时间
- 匹配策略：优先通过 CVE ID 关联 `vulnerabilities` 表；无 CVE 映射的 CNVD 漏洞**单独入库**
- 同步频率：每日增量（最近 14 天）

**CNNVD（国家信息安全漏洞库）**

| 方案 | 方式 | 优点 | 缺点 | 推荐 |
|------|------|------|------|------|
| A | 下载官方 XML/JSON 数据包 `cnnvd.org.cn` | 官方数据、最全 | 需申请、审批 | ★★★ |
| B | 爬取公开查询页面 | 无需审批 | 同 CNVD 方案 B | ★★ |
| C | CVE→CNNVD 映射表（开源 cnnvd2cve 项目） | 快速补齐编号 | 仅编号映射，无详情 | ★ |

- 推荐：先用方案 C 快速补齐编号，中期用方案 A 获取完整数据
- 严重级别映射：超危→critical / 高危→high / 中危→medium / 低危→low
- 编号格式：CNVD-YYYY-NNNNN、CNNVD-YYYYMM-NNN

#### 数据模型变更

`vulnerabilities` 表新增字段：

```go
// vulnerability.go — 新增字段
CnvdID     string `gorm:"column:cnvd_id;type:varchar(50);index" json:"cnvdId"`
CnnvdID    string `gorm:"column:cnnvd_id;type:varchar(50);index" json:"cnnvdId"`
```

对应 SQL：

```sql
ALTER TABLE vulnerabilities
  ADD COLUMN cnvd_id  VARCHAR(50) DEFAULT '' COMMENT 'CNVD 编号',
  ADD COLUMN cnnvd_id VARCHAR(50) DEFAULT '' COMMENT 'CNNVD 编号',
  ADD INDEX idx_cnvd_id (cnvd_id),
  ADD INDEX idx_cnnvd_id (cnnvd_id);
```

#### 后端实现

新增文件，遵循 `nvd_sync.go` / `redhat_sync.go` 的模式：

```
internal/server/manager/biz/
├── cnvd_sync.go       # CNVD 同步逻辑
├── cnnvd_sync.go      # CNNVD 同步逻辑
```

核心方法：

```go
// VulnScanner 新增方法
func (v *VulnScanner) SyncCNVD() error   // CNVD 增量同步
func (v *VulnScanner) SyncCNNVD() error  // CNNVD 编号补齐

// SyncOnly() 调用链扩展
func (v *VulnScanner) SyncOnly() error {
    v.SyncNVD()
    v.SyncRedHat()
    v.SyncCNVD()    // 新增
    v.SyncCNNVD()   // 新增
    v.SyncExploit() // 新增（见 2.2）
}
```

**CNVD 同步核心逻辑**：

1. 调用数据源 API，获取最近 14 天 CNVD 记录
2. 提取 CVE 映射字段（CNVD 多数漏洞有对应 CVE ID）
3. 有 CVE 映射 → `UPDATE vulnerabilities SET cnvd_id = ? WHERE cve_id = ?`
4. 无 CVE 映射 → 作为新漏洞 INSERT，`cve_id` 留空或填 CNVD 编号
5. 对新入库漏洞执行主机匹配（通过 affected_products 与 software 表匹配）

**CNNVD 同步核心逻辑**：

1. 解析 CVE→CNNVD 映射表（CSV/JSON）
2. 批量 UPDATE：`UPDATE vulnerabilities SET cnnvd_id = ? WHERE cve_id = ?`
3. 若用完整数据源（方案 A），同 CNVD 流程处理无 CVE 映射的记录

#### 前端变更

- 漏洞列表新增 CNVD/CNNVD 编号列，支持点击跳转官方详情页
- 漏洞详情页展示国内编号区块
- 搜索框支持 CNVD/CNNVD 编号检索
- 漏洞报告 PDF 导出包含 CNVD/CNNVD 编号

#### API 变更

```
GET /vulnerabilities — 响应新增 cnvdId, cnnvdId 字段
GET /vulnerabilities — 搜索支持 CNVD/CNNVD 编号模糊匹配
POST /vulnerabilities/sync — 同步范围扩展，包含 CNVD/CNNVD
```

`buildVulnerabilityQuery` 的 Search 条件追加：

```go
clauses = append(clauses,
    "vulnerabilities.cnvd_id LIKE ?",
    "vulnerabilities.cnnvd_id LIKE ?",
)
args = append(args, pattern, pattern)
```

---

### 2.2 ExploitDB / CISA KEV 利用标记

#### 背景

区分"有公开 Exploit"和"已被在野利用"的漏洞，对优先级排序至关重要。CISA KEV（已知被利用漏洞目录）是美国政府维护的权威在野利用清单。

#### 定位

**不作为独立漏洞源**，仅为已有漏洞记录打标签。不创建新的 `vulnerabilities` 记录。

#### 数据模型变更

```go
// vulnerability.go — 新增字段
HasExploit bool   `gorm:"column:has_exploit;default:false" json:"hasExploit"`
InKEV      bool   `gorm:"column:in_kev;default:false" json:"inKev"`
ExploitRef string `gorm:"column:exploit_ref;type:varchar(500)" json:"exploitRef"`
```

```sql
ALTER TABLE vulnerabilities
  ADD COLUMN has_exploit TINYINT(1) DEFAULT 0 COMMENT '是否有公开 Exploit',
  ADD COLUMN in_kev      TINYINT(1) DEFAULT 0 COMMENT '是否在 CISA KEV 目录中',
  ADD COLUMN exploit_ref VARCHAR(500) DEFAULT '' COMMENT 'Exploit 参考链接';
```

#### 后端实现

新增文件：

```
internal/server/manager/biz/exploit_sync.go
```

```go
func (v *VulnScanner) SyncExploit() error  // ExploitDB + KEV 标签同步
```

**CISA KEV 同步逻辑**（优先实现，数据量小、公开 JSON）：

1. 下载 `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
2. 解析 JSON，提取 CVE ID 列表（~1200 条，全量同步）
3. 批量 UPDATE：`UPDATE vulnerabilities SET in_kev = 1 WHERE cve_id IN (?)`
4. 同步频率：每日全量（数据量小，无需增量）

**ExploitDB 同步逻辑**：

1. 下载 ExploitDB CSV（`https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv`）
2. 提取有 CVE 映射的 Exploit 条目
3. 批量 UPDATE：
   ```sql
   UPDATE vulnerabilities
   SET has_exploit = 1, exploit_ref = ?
   WHERE cve_id = ? AND has_exploit = 0
   ```
4. 同步频率：每日增量（比对已处理的最大 Exploit ID）

#### 前端变更

- 漏洞列表新增标签列：
  - 红色标签 `在野利用` — `in_kev = true`
  - 橙色标签 `有 Exploit` — `has_exploit = true && !in_kev`
- 筛选器新增：按利用状态筛选（全部 / 有 Exploit / 在野利用 / 无 Exploit）
- 漏洞详情展示 Exploit 参考链接（可点击跳转）

#### API 变更

```
GET /vulnerabilities — 新增 exploit_status 筛选参数
    exploit_status=has_exploit | in_kev | none
GET /vulnerabilities — 响应新增 hasExploit, inKev, exploitRef 字段
```

---

### 2.3 漏洞优先级排序

#### 背景

当前仅按 CVSS 分数排序，CVSS 9.8 的漏洞可能影响的是内网不对外暴露的服务，实际风险低于 CVSS 7.5 但已被在野利用的公网服务漏洞。需要多维度加权评分，帮助用户聚焦真正有威胁的漏洞。

#### 评分模型

**漏洞优先级分 = CVSS 基础分 × 权重 + 利用状态分 + 暴露面分 + 补丁可用性分**

```
Priority Score = W1 × CVSS_normalized
              + W2 × exploit_score
              + W3 × exposure_score
              + W4 × patch_score
```

| 维度 | 权重 | 评分规则 | 分值范围 |
|------|------|---------|---------|
| CVSS 基础分 | W1=0.35 | `cvss_score / 10.0` 归一化 | 0~1 |
| 利用状态 | W2=0.30 | in_kev=1.0 / has_exploit=0.7 / 无=0.0 | 0~1 |
| 暴露面 | W3=0.20 | 受影响主机数占比 + 对外服务标记 | 0~1 |
| 补丁可用性 | W4=0.15 | 有修复版本=0.8 / 无修复版本=0.2 | 0~1 |

暴露面评分细则：

```
exposure_score = host_ratio × 0.5 + internet_facing × 0.5
其中:
  host_ratio = affected_hosts / total_hosts（上限 1.0）
  internet_facing = 1.0 if 任一受影响主机有公网 IP 或对外端口; else 0.0
```

补丁可用性评分：有补丁意味着可以立即行动，优先级应更高（不是更低）。

#### 数据模型变更

```go
// vulnerability.go — 新增字段
PriorityScore  float64 `gorm:"column:priority_score;type:decimal(5,3);default:0;index" json:"priorityScore"`
ExposureScore  float64 `gorm:"column:exposure_score;type:decimal(3,2);default:0" json:"exposureScore"`
```

```sql
ALTER TABLE vulnerabilities
  ADD COLUMN priority_score DECIMAL(5,3) DEFAULT 0 COMMENT '综合优先级评分',
  ADD COLUMN exposure_score DECIMAL(3,2) DEFAULT 0 COMMENT '暴露面评分',
  ADD INDEX idx_priority_score (priority_score);
```

#### 后端实现

新增文件：

```
internal/server/manager/biz/vuln_priority.go
```

```go
// PriorityCalculator 漏洞优先级计算器
type PriorityCalculator struct {
    db     *gorm.DB
    logger *zap.Logger
}

// RecalculateAll 重新计算所有 unpatched 漏洞的优先级评分
func (p *PriorityCalculator) RecalculateAll() error

// RecalculateOne 计算单个漏洞的优先级评分
func (p *PriorityCalculator) RecalculateOne(vulnID uint) (float64, error)

// CalculateExposure 计算暴露面评分
func (p *PriorityCalculator) CalculateExposure(vulnID uint, totalHosts int64) float64
```

计算时机：
- `ScanAll()` 完成后批量重算
- `SyncExploit()` 完成后重算受影响漏洞
- 漏洞状态变更（ignore/patch）后更新关联漏洞
- 新主机上线/下线后重算受影响漏洞

#### 前端变更

- 漏洞列表默认按 `priority_score DESC` 排序（替代 CVSS 排序）
- 新增优先级列，显示为颜色条（红/橙/黄/蓝对应 高/中高/中/低）
- 优先级阈值：>= 0.75 高 / >= 0.50 中高 / >= 0.25 中 / < 0.25 低
- 列表筛选器新增：按优先级范围筛选
- Dashboard 概览卡片显示：高优先级未修复漏洞数

#### API 变更

```
GET /vulnerabilities — 新增排序 sort=priority_score|cvss_score
GET /vulnerabilities — 新增筛选 priority=high|medium-high|medium|low
GET /vulnerabilities/:id — 响应新增 priorityScore, exposureScore
GET /vulnerabilities/stats/priority — 新增优先级分布统计接口
```

---

### 2.4 离线漏洞库缓存

#### 背景

私有化部署场景（军工、政务、金融）内网环境无法访问外部 API（OSV.dev / NVD / Red Hat），需要本地漏洞库支持扫描功能。

#### 架构设计

```
┌──────────────────────────────────────────┐
│               VulnScanner                │
│                                          │
│  ① 查本地缓存 ──→ 命中 ──→ 直接使用     │
│        │                                 │
│        ↓ 未命中                           │
│  ② 调 OSV API ──→ 成功 ──→ 写入缓存      │
│        │                                 │
│        ↓ 失败（网络不通）                  │
│  ③ 降级为仅本地缓存扫描                   │
└──────────────────────────────────────────┘
```

#### 数据模型

新增本地漏洞缓存表：

```go
// vuln_cache.go
type VulnCache struct {
    ID         uint      `gorm:"primaryKey"`
    OsvID      string    `gorm:"uniqueIndex;type:varchar(100)"`
    RawJSON    string    `gorm:"type:mediumtext"` // OSV.dev 原始响应
    CachedAt   time.Time
    ExpiredAt  time.Time // 缓存过期时间（默认 7 天）
}
```

新增离线数据包导入记录表：

```go
type VulnDBImport struct {
    ID         uint      `gorm:"primaryKey"`
    FileName   string    `gorm:"type:varchar(200)"`
    FileSize   int64
    SHA256     string    `gorm:"type:varchar(64)"`
    VulnCount  int       // 导入漏洞条数
    Status     string    // importing / success / failed
    ImportedAt time.Time
}
```

#### 后端实现

```
internal/server/manager/biz/vuln_cache.go
```

核心逻辑：

1. **在线模式**：OSV 查询结果自动写入 `vuln_cache`，后续相同 OSV ID 优先读缓存
2. **离线模式**：管理员通过 UI 上传 OSV 数据包（Google 提供的 GCS 导出），批量导入 `vuln_cache`
3. **混合模式**：先查缓存，miss 时尝试在线查询，失败则降级
4. VulnScanner 构造函数新增 `offlineMode bool` 参数

OSV.dev 提供的离线数据包：

```
gs://osv-vulnerabilities/  （按 ecosystem 分目录）
├── Alpine/
├── Debian/
├── PyPI/
├── npm/
└── ...
```

每个 ecosystem 目录下有 `all.zip`，包含所有漏洞的 JSON 文件。

#### 前端变更

- 系统管理新增"漏洞库管理"页面
- 显示当前缓存状态（在线/离线/混合模式）
- 离线数据包上传入口 + 导入进度条
- 缓存统计：总条数、最后更新时间、过期条数

#### API 变更

```
GET  /vulnerabilities/cache/stats    — 缓存统计
POST /vulnerabilities/cache/import   — 上传离线数据包
GET  /vulnerabilities/cache/imports  — 导入历史
POST /vulnerabilities/cache/purge    — 清理过期缓存
```

---

## 三、漏洞扫描升级

### 3.1 定时自动扫描

#### 背景

当前扫描必须手动触发（UI 点击或 API 调用），生产环境需要无人值守的周期性扫描。

#### 实现方案

利用 Go 内置 `time.Ticker` 或 `robfig/cron` 实现 Server 端定时任务（不依赖系统 crontab）。

#### 数据模型

新增扫描调度配置表：

```go
// scan_schedule.go
type ScanSchedule struct {
    ID         uint   `gorm:"primaryKey"`
    Name       string `gorm:"type:varchar(100);not null"`         // 任务名称
    ScanType   string `gorm:"type:varchar(20);not null"`          // full_scan / sync_only
    CronExpr   string `gorm:"type:varchar(50);not null"`          // Cron 表达式
    Enabled    bool   `gorm:"default:true"`
    LastRunAt  *time.Time
    NextRunAt  *time.Time
    CreatedBy  string `gorm:"type:varchar(64)"`
    CreatedAt  time.Time
    UpdatedAt  time.Time
}
```

#### 后端实现

```
internal/server/manager/biz/scan_scheduler.go
```

```go
type ScanScheduler struct {
    db       *gorm.DB
    logger   *zap.Logger
    scanner  *VulnScanner
    cron     *cron.Cron     // robfig/cron v3
}

func (s *ScanScheduler) Start()                    // 启动调度器，加载所有 Enabled 的 schedule
func (s *ScanScheduler) Stop()                     // 优雅停止
func (s *ScanScheduler) AddSchedule(sch *ScanSchedule) error
func (s *ScanScheduler) RemoveSchedule(id uint) error
func (s *ScanScheduler) UpdateSchedule(id uint, updates map[string]any) error
```

默认初始化数据：

```go
// 默认扫描计划（init_data.go）
{Name: "每日漏洞库同步", ScanType: "sync_only", CronExpr: "0 2 * * *", Enabled: true}   // 每天凌晨 2 点
{Name: "每周全量扫描",   ScanType: "full_scan", CronExpr: "0 3 * * 0", Enabled: true}   // 每周日凌晨 3 点
```

扫描完成后自动触发优先级重算（调用 `PriorityCalculator.RecalculateAll()`）。

#### 前端变更

- 漏洞列表页顶部扫描状态栏新增"扫描计划"入口
- 扫描计划管理页面：CRUD 操作 + 启用/禁用开关
- Cron 表达式可视化编辑器（或预设模板：每日/每周/每月）
- 下次执行时间预览

#### API 变更

```
GET    /vulnerabilities/schedules           — 扫描计划列表
POST   /vulnerabilities/schedules           — 创建扫描计划
PUT    /vulnerabilities/schedules/:id       — 更新扫描计划
DELETE /vulnerabilities/schedules/:id       — 删除扫描计划
POST   /vulnerabilities/schedules/:id/toggle — 启用/禁用
```

---

### 3.2 语言依赖扫描

#### 背景

当前 VulnScanner 仅通过 PURL 扫描 OS 级软件包（RPM/DEB），无法发现应用层语言依赖中的漏洞。现代应用大量使用第三方开源库，语言依赖漏洞占比逐年上升。

#### 支持范围

| 语言 | 依赖文件 | PURL Scheme | 优先级 |
|------|---------|------------|--------|
| Go | go.sum | `pkg:golang/` | P0（本项目是 Go） |
| Node.js | package-lock.json, yarn.lock | `pkg:npm/` | P1 |
| Python | requirements.txt, Pipfile.lock, poetry.lock | `pkg:pypi/` | P1 |
| Java | pom.xml, build.gradle(.kts) | `pkg:maven/` | P2 |
| Rust | Cargo.lock | `pkg:cargo/` | P2 |

#### 架构设计

```
Agent 端 (Collector 插件扩展)
│
├─ 扫描 /opt, /home, /var/www 等目录
├─ 识别 go.sum, package-lock.json 等文件
├─ 解析依赖列表 → 生成 PURL
├─ 上报 Server
│
Server 端
│
├─ 写入 software 表（type="language_dep", ecosystem="Go/npm/PyPI/..."）
├─ VulnScanner 批量查询 OSV.dev（OSV.dev 原生支持语言依赖 PURL）
└─ 结果写入 vulnerabilities + host_vulnerabilities
```

#### 数据模型变更

`software` 表已有 `purl` 字段，新增：

```go
// 扩展 software 表
Ecosystem   string `gorm:"column:ecosystem;type:varchar(30);index"` // 操作系统 / Go / npm / PyPI / Maven
SourceFile  string `gorm:"column:source_file;type:varchar(500)"`    // 依赖文件路径
```

```sql
ALTER TABLE software
  ADD COLUMN ecosystem   VARCHAR(30) DEFAULT '' COMMENT '生态系统',
  ADD COLUMN source_file VARCHAR(500) DEFAULT '' COMMENT '依赖文件来源路径';
```

#### 后端实现 — Agent 端

Collector 插件扩展依赖文件扫描器：

```
plugins/collector/
├── dep_scanner.go           # 依赖文件发现 + 解析入口
├── parsers/
│   ├── gosum.go             # go.sum 解析器
│   ├── npm_lockfile.go      # package-lock.json 解析器
│   ├── pip_requirements.go  # requirements.txt 解析器
│   ├── maven_pom.go         # pom.xml 解析器
│   └── cargo_lock.go        # Cargo.lock 解析器
```

扫描策略：
- 默认扫描目录：`/opt`, `/home`, `/var/www`, `/srv`, `/usr/local`
- 可通过配置文件自定义扫描路径和排除路径
- 扫描深度：最大 5 层目录
- 文件大小限制：单个依赖文件 < 10MB
- 增量策略：记录文件 mtime，仅重新解析变化的文件

依赖 PURL 生成示例：

```
go.sum: golang.org/x/crypto v0.17.0 → pkg:golang/golang.org/x/crypto@0.17.0
package-lock.json: express@4.18.2 → pkg:npm/express@4.18.2
requirements.txt: Django==4.2.7 → pkg:pypi/django@4.2.7
```

#### 后端实现 — Server 端

VulnScanner 无需大改——OSV.dev 原生支持语言 PURL 查询。改动点：

1. `ScanAll()` 从 `software` 表查询时，不再限定 ecosystem，同时查出语言依赖
2. 语言依赖的 PURL 直接进入 OSV 批量查询流程
3. 漏洞记录的 `component` 字段格式统一为 `ecosystem/package_name`（如 `Go/golang.org/x/crypto`）

```go
// 调整 ScanAll 的查询条件
// 原：WHERE purl != '' AND purl LIKE 'pkg:rpm/%' OR purl LIKE 'pkg:deb/%'
// 新：WHERE purl != ''  （不限定 scheme，覆盖所有 ecosystem）
```

#### 前端变更

- 漏洞列表的 Component 列增加生态系统图标（Go Gopher / npm / PyPI / Maven）
- 筛选器新增 Ecosystem 筛选（全部 / OS / Go / npm / PyPI / Maven）
- 主机详情的资产指纹 Tab 新增"语言依赖"子类

#### API 变更

```
GET /vulnerabilities — 新增 ecosystem 筛选参数
GET /asset-fingerprint/dependencies/:host_id — 主机语言依赖列表
```

---

### 3.3 容器镜像扫描

#### 背景

v3 阶段将深化 K8s 容器安全。容器镜像漏洞是容器安全的第一道防线——在镜像构建/部署前发现漏洞，比运行时再修复成本低 10 倍以上。

#### 架构设计

不自研扫描引擎，集成成熟的开源工具 **Trivy**（CNCF 项目，Aqua Security 维护）：

```
方式一：Server 端调用（推荐）
┌──────────────┐     ┌───────────┐     ┌──────────┐
│ Manager API  │────→│ Trivy CLI │────→│ Registry │
│              │←────│ (Server端) │     │ (镜像仓库)│
└──────────────┘     └───────────┘     └──────────┘
       │
       ↓ 结果解析
  vulnerabilities 表

方式二：Agent 端扫描（可选，用于无 Registry 场景）
┌──────────┐     ┌───────────┐
│ Agent    │────→│ Trivy CLI │────→ 扫描本地 Docker images
│          │←────│ (Agent端)  │
└──────────┘     └───────────┘
```

推荐方式一：Server 端直接连 Registry 扫描，避免每台 Agent 安装 Trivy。

#### 数据模型

新增镜像扫描相关表：

```go
// image_scan.go
type ImageScan struct {
    ID          uint      `gorm:"primaryKey"`
    Image       string    `gorm:"type:varchar(500);not null;index"` // 镜像全名 registry/repo:tag
    Digest      string    `gorm:"type:varchar(100)"`                // sha256 摘要
    OS          string    `gorm:"type:varchar(50)"`                 // 镜像 OS
    TotalVulns  int
    CriticalCnt int
    HighCnt     int
    Status      string    `gorm:"type:varchar(20)"` // pending / scanning / done / failed
    ScannedAt   *time.Time
    CreatedAt   time.Time
}

type ImageVulnerability struct {
    ID          uint   `gorm:"primaryKey"`
    ImageScanID uint   `gorm:"index"`
    VulnID      *uint  `gorm:"index"` // 关联 vulnerabilities 表（可能为空）
    CveID       string `gorm:"type:varchar(50);index"`
    Package     string `gorm:"type:varchar(200)"`
    Version     string `gorm:"type:varchar(100)"`
    FixedVersion string `gorm:"type:varchar(100)"`
    Severity    string `gorm:"type:varchar(20)"`
    Title       string `gorm:"type:text"`
}
```

#### 后端实现

```
internal/server/manager/biz/image_scanner.go
```

```go
type ImageScanner struct {
    db         *gorm.DB
    logger     *zap.Logger
    trivyPath  string // trivy 二进制路径
}

// ScanImage 扫描单个镜像
func (s *ImageScanner) ScanImage(image string) (*ImageScan, error)

// ScanRegistry 扫描整个 Registry 中的镜像列表
func (s *ImageScanner) ScanRegistry(registryURL string, auth *RegistryAuth) error

// ParseTrivyOutput 解析 Trivy JSON 输出
func (s *ImageScanner) ParseTrivyOutput(output []byte) ([]ImageVulnerability, error)
```

Trivy 调用方式：

```bash
trivy image --format json --severity CRITICAL,HIGH,MEDIUM,LOW \
  --quiet registry.example.com/app:latest
```

扫描结果与 `vulnerabilities` 表通过 CVE ID 关联，补充镜像维度的影响范围。

#### 前端变更

- 容器集群菜单下新增"镜像扫描"页面
- 镜像列表 + 扫描状态 + 漏洞统计
- 支持手动输入镜像名触发扫描
- 支持配置 Registry 地址 + 认证信息
- 镜像漏洞详情列表（关联跳转到漏洞管理）

#### API 变更

```
POST /images/scan              — 触发镜像扫描
GET  /images/scans             — 扫描记录列表
GET  /images/scans/:id         — 扫描详情 + 漏洞列表
GET  /images/scans/:id/vulns   — 镜像漏洞列表
POST /images/registries        — 配置 Registry
GET  /images/registries        — Registry 列表
```

---

### 3.4 SBOM 导入扫描

#### 背景

SBOM（Software Bill of Materials）是软件供应链安全的基础。当前平台仅支持 CycloneDX 格式导出，缺少导入能力。用户可能从 CI/CD 流程中生成 SBOM，需要平台接收并扫描。

#### 支持格式

| 格式 | 版本 | 说明 |
|------|------|------|
| CycloneDX | 1.4+ | JSON/XML，当前已支持导出 |
| SPDX | 2.3 | JSON，Linux Foundation 标准 |

#### 后端实现

```
internal/server/manager/biz/sbom_import.go
```

```go
type SBOMImporter struct {
    db      *gorm.DB
    logger  *zap.Logger
    scanner *VulnScanner
}

// Import 解析 SBOM 文件并触发漏洞扫描
func (s *SBOMImporter) Import(file io.Reader, format string, projectName string) (*SBOMImportResult, error)

type SBOMImportResult struct {
    ProjectName    string
    ComponentCount int
    VulnCount      int
    CriticalCount  int
    HighCount      int
}
```

流程：

1. 解析 SBOM 文件，提取组件列表（name + version + PURL）
2. 组件写入 `software` 表（`host_id` 使用特殊前缀 `sbom:<project_name>`）
3. 调用 VulnScanner 对新组件执行漏洞匹配
4. 返回扫描结果摘要

#### API 变更

```
POST /sbom/import         — 上传 SBOM 文件
GET  /sbom/projects       — SBOM 项目列表
GET  /sbom/projects/:name — 项目组件 + 漏洞详情
```

---

## 四、漏洞修复升级

### 4.1 修复策略模板

#### 背景

当前修复任务按"漏洞 × 主机"维度创建，大规模环境（数百台主机、数千漏洞）下操作繁琐。需要按业务线/标签/主机组批量创建修复策略。

#### 数据模型

```go
// remediation_policy.go
type RemediationPolicy struct {
    ID           uint      `gorm:"primaryKey"`
    Name         string    `gorm:"type:varchar(100);not null"`
    Description  string    `gorm:"type:text"`
    // 目标筛选条件
    TargetType   string    `gorm:"type:varchar(20)"` // all / business_line / tag / host_ids
    TargetValue  string    `gorm:"type:text"`         // JSON: business_line_id / tag_names / host_ids
    // 漏洞筛选条件
    SeverityMin  string    `gorm:"type:varchar(20)"`  // 最低严重级别（critical/high/medium/low）
    PriorityMin  float64   `gorm:"type:decimal(5,3)"` // 最低优先级分
    AutoConfirm  bool      `gorm:"default:false"`     // 是否自动审批
    // 执行控制
    MaxParallel  int       `gorm:"default:10"`         // 最大并行执行主机数
    RolloutType  string    `gorm:"type:varchar(20)"`   // immediate / canary / rolling
    CanaryRatio  int       `gorm:"default:10"`         // 金丝雀比例（%）
    // 状态
    Enabled      bool      `gorm:"default:true"`
    LastRunAt    *time.Time
    CreatedBy    string    `gorm:"type:varchar(64)"`
    CreatedAt    time.Time
    UpdatedAt    time.Time
}
```

#### 执行策略

**立即执行（immediate）**：同时对所有匹配主机创建修复任务

**金丝雀（canary）**：
1. 先选 N% 主机创建任务
2. 金丝雀主机修复成功后，管理员确认
3. 确认后对剩余主机批量创建任务

**滚动（rolling）**：
1. 按 `MaxParallel` 分批执行
2. 每批完成（成功率 > 80%）后自动开始下一批
3. 任一批次成功率 < 80% 时暂停，等待人工介入

#### 后端实现

```
internal/server/manager/biz/remediation_policy.go
```

```go
type PolicyExecutor struct {
    db       *gorm.DB
    logger   *zap.Logger
    executor *RemediationExecutor
}

// Execute 执行修复策略
func (p *PolicyExecutor) Execute(policyID uint) error

// matchHosts 根据策略条件匹配目标主机
func (p *PolicyExecutor) matchHosts(policy *RemediationPolicy) ([]string, error)

// matchVulns 根据条件筛选漏洞
func (p *PolicyExecutor) matchVulns(policy *RemediationPolicy, hostIDs []string) ([]model.Vulnerability, error)

// executeBatch 分批执行
func (p *PolicyExecutor) executeBatch(tasks []model.RemediationTask, maxParallel int) error
```

#### 前端变更

- 修复任务页面新增"修复策略"Tab
- 策略创建向导：选择目标范围 → 选择漏洞条件 → 配置执行方式 → 预览影响范围 → 确认创建
- 策略执行状态看板：进度条 + 分批状态 + 失败明细

#### API 变更

```
POST   /remediation-policies           — 创建修复策略
GET    /remediation-policies           — 策略列表
GET    /remediation-policies/:id       — 策略详情
PUT    /remediation-policies/:id       — 更新策略
DELETE /remediation-policies/:id       — 删除策略
POST   /remediation-policies/:id/execute — 执行策略
POST   /remediation-policies/:id/preview — 预览影响范围（不实际执行）
```

---

### 4.2 语言依赖修复支持

#### 背景

语言依赖扫描（3.2 节）发现漏洞后，需要对应的修复方案。OS 包通过 yum/apt 升级，语言依赖需要不同的处理方式。

#### 修复命令生成扩展

`remediation.go` 的 `generateCommands` 新增语言依赖分支：

```go
func (s *RemediationService) generateCommands(vuln *model.Vulnerability) []RemediationCommand {
    pkgType := s.detectPackageType(vuln.PURL)

    switch pkgType {
    case "rpm":  // 现有逻辑
    case "deb":  // 现有逻辑
    case "golang":
        return s.generateGoCommands(vuln)
    case "npm":
        return s.generateNpmCommands(vuln)
    case "pypi":
        return s.generatePyPICommands(vuln)
    case "maven":
        return s.generateMavenCommands(vuln)
    }
}
```

各语言修复命令示例：

| 语言 | 修复命令 | 说明 |
|------|---------|------|
| Go | `go get golang.org/x/crypto@v0.18.0` | 升级到修复版本 |
| npm | `npm install express@4.19.0` | 升级到修复版本 |
| PyPI | `pip install Django==4.2.8 --upgrade` | 升级到修复版本 |
| Maven | 提供 pom.xml 修改建议 | 非命令行方式 |

**注意**：语言依赖修复通常不通过 Agent 远程执行（涉及开发环境、CI/CD 流程），而是提供修复建议。`RemediationAdvice` 返回命令和参考链接，由开发者自行处理。

#### `detectPackageType` 扩展

```go
func (s *RemediationService) detectPackageType(purl string) string {
    switch {
    case strings.HasPrefix(purl, "pkg:rpm/"):    return "rpm"
    case strings.HasPrefix(purl, "pkg:deb/"):    return "deb"
    case strings.HasPrefix(purl, "pkg:golang/"): return "golang"
    case strings.HasPrefix(purl, "pkg:npm/"):    return "npm"
    case strings.HasPrefix(purl, "pkg:pypi/"):   return "pypi"
    case strings.HasPrefix(purl, "pkg:maven/"):  return "maven"
    case strings.HasPrefix(purl, "pkg:cargo/"):  return "cargo"
    default: return ""
    }
}
```

---

## 五、实施路线

### Phase 1 — 情报增强（预计 2 周）

| 步骤 | 内容 | 验证方式 |
|------|------|---------|
| 1.1 | 数据模型迁移：新增 cnvd_id, cnnvd_id, has_exploit, in_kev, exploit_ref, priority_score, exposure_score | 数据库表结构正确，AutoMigrate 无报错 |
| 1.2 | CISA KEV 同步（最简单，公开 JSON，~1200 条） | `in_kev` 字段正确标记已知被利用漏洞 |
| 1.3 | ExploitDB 同步 | `has_exploit` 字段正确标记有 Exploit 的漏洞 |
| 1.4 | 优先级计算器 | `priority_score` 字段计算正确，排序结果合理 |
| 1.5 | CNVD 数据源接入（先确定获取方式） | `cnvd_id` 正确关联 |
| 1.6 | CNNVD 编号补齐 | `cnnvd_id` 正确关联 |
| 1.7 | SyncOnly() 串联 + 同步历史记录 | 全链路同步正常 |
| 1.8 | 前端：标签展示 + 筛选 + 优先级排序 | UI 交互正常 |

### Phase 2 — 扫描增强（预计 3 周）

| 步骤 | 内容 | 验证方式 |
|------|------|---------|
| 2.1 | 定时扫描调度器 | cron 表达式解析正确，定时触发扫描 |
| 2.2 | Go 依赖解析器（go.sum） | 正确提取 Go module PURL |
| 2.3 | npm 依赖解析器（package-lock.json） | 正确提取 npm PURL |
| 2.4 | Python 依赖解析器（requirements.txt） | 正确提取 PyPI PURL |
| 2.5 | Agent Collector 插件扩展 | 依赖文件发现 + 解析 + 上报 |
| 2.6 | VulnScanner 语言依赖覆盖 | OSV 查询覆盖语言 PURL |
| 2.7 | 离线漏洞库缓存 | 在线缓存 + 离线导入 + 混合模式 |
| 2.8 | 容器镜像扫描（Trivy 集成） | 镜像漏洞正确识别 |
| 2.9 | 前端：定时扫描管理 + 生态系统筛选 | UI 交互正常 |

### Phase 3 — 修复增强（预计 2 周）

| 步骤 | 内容 | 验证方式 |
|------|------|---------|
| 3.1 | 修复策略模板 CRUD | 策略创建/编辑/删除正常 |
| 3.2 | 策略执行器（immediate / canary / rolling） | 分批执行逻辑正确 |
| 3.3 | 语言依赖修复命令生成 | Go/npm/PyPI/Maven 命令正确 |
| 3.4 | 前端：策略管理 + 执行看板 | UI 交互正常 |
| 3.5 | SBOM 导入扫描 | CycloneDX/SPDX 解析正确 |

---

## 六、数据模型变更汇总

### 新增字段（vulnerabilities 表）

| 字段 | 类型 | 索引 | 来源 |
|------|------|------|------|
| cnvd_id | VARCHAR(50) | idx_cnvd_id | §2.1 |
| cnnvd_id | VARCHAR(50) | idx_cnnvd_id | §2.1 |
| has_exploit | TINYINT(1) | — | §2.2 |
| in_kev | TINYINT(1) | — | §2.2 |
| exploit_ref | VARCHAR(500) | — | §2.2 |
| priority_score | DECIMAL(5,3) | idx_priority_score | §2.3 |
| exposure_score | DECIMAL(3,2) | — | §2.3 |

### 新增字段（software 表）

| 字段 | 类型 | 索引 | 来源 |
|------|------|------|------|
| ecosystem | VARCHAR(30) | idx_ecosystem | §3.2 |
| source_file | VARCHAR(500) | — | §3.2 |

### 新增表

| 表名 | 说明 | 来源 |
|------|------|------|
| scan_schedules | 扫描调度配置 | §3.1 |
| vuln_cache | 离线漏洞缓存 | §2.4 |
| vuln_db_imports | 离线数据包导入记录 | §2.4 |
| image_scans | 镜像扫描记录 | §3.3 |
| image_vulnerabilities | 镜像漏洞关联 | §3.3 |
| remediation_policies | 修复策略模板 | §4.1 |

---

## 七、新增文件清单

### 后端（Go）

```
internal/server/manager/biz/
├── cnvd_sync.go              # CNVD 同步
├── cnnvd_sync.go             # CNNVD 同步
├── exploit_sync.go           # ExploitDB + CISA KEV 同步
├── vuln_priority.go          # 优先级计算
├── vuln_cache.go             # 离线缓存
├── scan_scheduler.go         # 定时扫描调度
├── image_scanner.go          # 容器镜像扫描
├── sbom_import.go            # SBOM 导入
├── remediation_policy.go     # 修复策略模板

internal/server/manager/api/
├── image_scans.go            # 镜像扫描 API
├── scan_schedules.go         # 扫描计划 API
├── remediation_policies.go   # 修复策略 API
├── sbom.go                   # SBOM 导入 API（扩展已有）

internal/server/model/
├── scan_schedule.go          # 扫描计划模型
├── vuln_cache.go             # 缓存模型
├── image_scan.go             # 镜像扫描模型
├── remediation_policy.go     # 修复策略模型

plugins/collector/
├── dep_scanner.go            # 依赖文件发现
├── parsers/
│   ├── gosum.go
│   ├── npm_lockfile.go
│   ├── pip_requirements.go
│   ├── maven_pom.go
│   └── cargo_lock.go
```

### 前端（Vue）

```
ui/src/views/
├── VulnList/index.vue              # 扩展：标签、优先级、生态系统筛选
├── VulnRemediation/
│   ├── Policies.vue                # 新增：修复策略管理
│   └── PolicyExecute.vue           # 新增：策略执行看板
├── ImageScan/
│   ├── index.vue                   # 新增：镜像扫描列表
│   └── Detail.vue                  # 新增：镜像漏洞详情
├── System/
│   └── VulnDBManage.vue            # 新增：漏洞库管理（离线缓存）

ui/src/api/
├── vulnerabilities.ts              # 扩展：新增字段和接口
├── image-scans.ts                  # 新增
├── scan-schedules.ts               # 新增
├── remediation-policies.ts         # 新增
```

---

## 八、API 变更汇总

### 扩展已有接口

| 接口 | 变更 |
|------|------|
| `GET /vulnerabilities` | 新增筛选：exploit_status, ecosystem, priority; 新增排序：priority_score; 响应新增 7 个字段 |
| `GET /vulnerabilities/:id` | 响应新增优先级和情报字段 |
| `POST /vulnerabilities/sync` | 同步范围扩展至 6 个数据源 |

### 新增接口

| 接口 | 说明 | 章节 |
|------|------|------|
| `GET /vulnerabilities/stats/priority` | 优先级分布统计 | §2.3 |
| `GET /vulnerabilities/cache/stats` | 缓存统计 | §2.4 |
| `POST /vulnerabilities/cache/import` | 上传离线数据包 | §2.4 |
| `GET /vulnerabilities/cache/imports` | 导入历史 | §2.4 |
| `POST /vulnerabilities/cache/purge` | 清理过期缓存 | §2.4 |
| `CRUD /vulnerabilities/schedules` | 扫描计划管理 | §3.1 |
| `POST /images/scan` | 触发镜像扫描 | §3.3 |
| `GET /images/scans` | 扫描记录列表 | §3.3 |
| `GET /images/scans/:id` | 扫描详情 | §3.3 |
| `GET /images/scans/:id/vulns` | 镜像漏洞列表 | §3.3 |
| `CRUD /images/registries` | Registry 配置 | §3.3 |
| `POST /sbom/import` | SBOM 导入 | §3.4 |
| `GET /sbom/projects` | SBOM 项目列表 | §3.4 |
| `GET /sbom/projects/:name` | 项目详情 | §3.4 |
| `CRUD /remediation-policies` | 修复策略管理 | §4.1 |
| `POST /remediation-policies/:id/execute` | 执行策略 | §4.1 |
| `POST /remediation-policies/:id/preview` | 预览影响范围 | §4.1 |

---

## 九、菜单结构变更

```
漏洞管理 (BugOutlined)                    # 现有
├── 漏洞列表 → /vuln-list                 # 扩展
├── 扫描计划 → /vuln-scan-schedules       # 新增
├── 修复报告 → /vuln-remediation          # 现有
├── 修复任务 → /vuln-remediation/tasks    # 现有
├── 修复策略 → /vuln-remediation/policies # 新增
└── 漏洞库管理 → /vuln-db-manage          # 新增

容器集群 (CloudServerOutlined)             # 现有
├── ...                                    # 现有子菜单
└── 镜像扫描 → /kube/image-scan           # 新增
```

---

## 十、风险评估

| 风险 | 等级 | 影响 | 缓解措施 |
|------|------|------|---------|
| CNVD/CNNVD 数据获取方式不确定 | 高 | 无法按期交付国内数据源 | 先用 CVE→CNVD/CNNVD 映射表快速补齐编号，再逐步接入完整数据 |
| Trivy 版本兼容性 | 中 | 不同版本 JSON 输出格式可能不同 | 锁定 Trivy 版本（如 v0.52+），JSON Schema 解析做兼容处理 |
| 离线数据包体积大 | 中 | OSV 全量数据 > 1GB，上传耗时 | 支持分 ecosystem 上传，增量导入 |
| 优先级评分准确性 | 中 | 权重配比不合理导致排序不符直觉 | 初始权重可调，提供管理员配置界面，根据实际使用反馈调优 |
| 语言依赖扫描性能 | 低 | 大仓库依赖文件多，解析耗时 | 增量策略 + 文件大小限制 + 并发控制 |
| Agent Collector 兼容性 | 低 | 不同发行版依赖文件路径不同 | 默认扫描路径可配置，覆盖主流路径 |

---

## 十一、开放问题

以下问题需要在实施前确认：

1. **CNVD 数据源选型**：确认第三方聚合 API 的可用性和费用，或决定是否先走映射表方案
2. **Trivy 部署形态**：Server 端部署 Trivy CLI 还是 Trivy Server 模式（HTTP API）
3. **优先级权重**：当前 W1=0.35/W2=0.30/W3=0.20/W4=0.15 是否合理，是否需要管理员可配置
4. **语言依赖扫描目录**：默认扫描 `/opt, /home, /var/www, /srv` 是否覆盖主要场景
5. **修复策略的金丝雀/滚动模式**：v1.1 是否实现，还是先做 immediate 模式
6. **SBOM 导入优先级**：是否可以延后到 Phase 3 之后作为独立迭代
