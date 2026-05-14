# 发展路线

## 当前状态

**版本**: v1.0.0（开发中）  
**MVP 完成度**: 100%  
**阶段**: 质量加固 + 能力补齐

## 已交付能力

| 模块 | 关键实现 |
|------|---------|
| 安全基线 | 策略/规则/任务/修复，212 条规则，9 种检查器 |
| 告警体系 | 告警聚合/处置/白名单/自动响应/溯源分析 |
| 审计日志 | 操作审计全链路，模型/中间件/API/前端 |
| FIM | 策略/事件/任务闭环，ClickHouse 归档 |
| 容器安全 | 集群/告警/事件/CIS 基线（80 条规则）/白名单/K8s Audit Webhook |
| 病毒查杀 | ClamAV + YARA-X 双引擎，任务/结果/隔离箱 |
| 漏洞管理 | PURL 采集 + OSV.dev/NVD/Red Hat 三源匹配 + CVSS v3.1 评分 |
| CEL 规则引擎 | 38 条内置规则 + MITRE 映射 + 热加载 |
| eBPF 检测 | Tetragon 事件采集 → ClickHouse 归档 |
| 行为序列检测 | 滑动窗口 + 状态机 + Redis |
| 威胁情报 | MISP IOC → Redis → CEL 碰撞 |
| 自动响应 | 规则命中 → AC 下发 kill/隔离 |
| HA 架构 | Manager/AC/Consumer 多实例 + Kafka + Redis SD + ClickHouse |
| 系统管理 | 用户/通知/组件/安装/巡检/授权 |
| 资产中心 | 11 类采集器、关系计算、资产导出 |

## 近期规划

> 验证已有功能真正可靠 > 新增功能

### 漏洞离线缓存

- 定期下载 OSV.dev 数据到本地缓存
- VulnScanner 优先查本地，缓存 miss 再调 OSV API
- 支持手动触发全量同步
- 解决内网客户无法访问外部 API 的问题

### 病毒扫描白名单完善

- 扫描结果白名单（按文件路径/hash/威胁名称忽略）
- 隔离箱补齐（quarantine_files 关联、恢复审计、批量处置）
- 误报处理流程（标记误报 → 加入白名单 → 后续扫描自动跳过）

### K8s 基线历史快照

- 新增 `kube_baseline_snapshots` 表，保留每次检查完整结果
- 支持按时间查看历史结果和趋势对比
- 周期报告引用历史数据

### 漏洞数据源扩展 — CNVD + CNNVD + ExploitDB/KEV

> 状态：待开发 | 优先级：P0（CNVD/CNNVD）、P2（ExploitDB/KEV）

#### 背景与目标

当前漏洞库仅有 OSV.dev / NVD / Red Hat 三个数据源，国内合规场景（等保、关基）要求覆盖 CNVD/CNNVD 编号；ExploitDB/KEV 可标记"已在野利用"漏洞，提升漏洞优先级排序能力。

#### 一、数据源接入方案

**1. CNVD（国家信息安全漏洞共享平台）**

- 数据获取方式：CNVD 无稳定公开 REST API
  - 方案 A（推荐）：对接第三方聚合 API（漏洞盒子、奇安信 CERT 等），需评估授权
  - 方案 B：定期爬取 CNVD 公开页面（`https://www.cnvd.org.cn/flaw/list`），解析列表+详情页
  - 方案 C：通过 CNVD 技术组成员身份申请数据共享，获取批量数据包
- 关键字段：CNVD 编号、标题、危害等级、影响产品、CVE 映射、公开时间
- 匹配策略：优先通过 CVE ID 关联现有 `vulnerabilities` 表，无 CVE 映射的 CNVD 漏洞单独入库
- 同步频率：每日增量同步最近 14 天

**2. CNNVD（国家信息安全漏洞库）**

- 数据获取方式：CNNVD 无公开 API
  - 方案 A（推荐）：下载官方 XML/JSON 数据包（需申请，`https://www.cnnvd.org.cn`）
  - 方案 B：爬取 CNNVD 公开查询页面
  - 方案 C：通过 CNNVD 编号与 CVE 编号的映射关系，利用第三方映射表（如 cnnvd2cve 开源项目）做编号关联
- 关键字段：CNNVD 编号、漏洞名称、威胁等级（超危/高危/中危/低危）、CVE 映射、影响产品、发布时间
- 匹配策略：通过 CVE ID 与 `vulnerabilities` 表关联
- 严重级别映射：超危→critical、高危→high、中危→medium、低危→low
- 同步频率：每日增量

**3. ExploitDB / CISA KEV**

- ExploitDB：公开 CSV/JSON（`https://gitlab.com/exploit-database/exploitdb`），包含 CVE 映射
- CISA KEV：公开 JSON（`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`），数据量小（~1200 条），全量同步
- 用途：**不作为独立漏洞源**，而是为现有漏洞记录打标签（`has_exploit`、`in_kev`）
- 同步频率：每日全量（KEV 数据量小），ExploitDB 增量

#### 二、数据模型变更

`vulnerabilities` 表新增字段：

```sql
ALTER TABLE vulnerabilities
  ADD COLUMN cnvd_id      VARCHAR(50)  DEFAULT '' COMMENT 'CNVD 编号',
  ADD COLUMN cnnvd_id     VARCHAR(50)  DEFAULT '' COMMENT 'CNNVD 编号',
  ADD COLUMN has_exploit   TINYINT(1)   DEFAULT 0  COMMENT '是否有公开 Exploit',
  ADD COLUMN in_kev        TINYINT(1)   DEFAULT 0  COMMENT '是否在 CISA KEV 目录中',
  ADD COLUMN exploit_ref   VARCHAR(500) DEFAULT '' COMMENT 'Exploit 参考链接',
  ADD INDEX idx_cnvd_id (cnvd_id),
  ADD INDEX idx_cnnvd_id (cnnvd_id);
```

对应 model 变更（`internal/server/model/vulnerability.go`）：

```go
CnvdID     string `gorm:"column:cnvd_id;type:varchar(50);index" json:"cnvdId"`
CnnvdID    string `gorm:"column:cnnvd_id;type:varchar(50);index" json:"cnnvdId"`
HasExploit bool   `gorm:"column:has_exploit;default:false" json:"hasExploit"`
InKEV      bool   `gorm:"column:in_kev;default:false" json:"inKev"`
ExploitRef string `gorm:"column:exploit_ref;type:varchar(500)" json:"exploitRef"`
```

#### 三、代码结构

新增文件，遵循现有 `nvd_sync.go` / `redhat_sync.go` 的模式：

```
internal/server/manager/biz/
├── cnvd_sync.go       # CNVD 同步逻辑
├── cnnvd_sync.go      # CNNVD 同步逻辑
├── exploit_sync.go    # ExploitDB + CISA KEV 同步逻辑
```

VulnScanner 新增方法：

```go
func (v *VulnScanner) SyncCNVD() error    // CNVD 同步
func (v *VulnScanner) SyncCNNVD() error   // CNNVD 同步
func (v *VulnScanner) SyncExploit() error // ExploitDB + KEV 标签同步
```

`SyncOnly()` 调用链扩展：

```go
func (v *VulnScanner) SyncOnly() error {
    // ... 现有逻辑 ...
    v.SyncNVD()
    v.SyncRedHat()
    v.SyncCNVD()      // 新增
    v.SyncCNNVD()     // 新增
    v.SyncExploit()   // 新增
}
```

#### 四、前端变更

- 漏洞列表增加 CNVD/CNNVD 编号列，支持点击跳转
- 漏洞详情展示 Exploit 状态标签（红色"已在野利用"、橙色"有 Exploit"）
- 筛选器增加：按数据源筛选、按 Exploit 状态筛选
- 漏洞报告 PDF 导出包含 CNVD/CNNVD 编号

#### 五、实施步骤

```
1. 数据模型迁移（model + migration）     → 验证：数据库表结构正确
2. CISA KEV 同步（最简单，公开 JSON）     → 验证：in_kev 字段正确标记
3. ExploitDB 同步                        → 验证：has_exploit 字段正确标记
4. CNVD 数据源接入（先确定获取方式）      → 验证：cnvd_id 正确关联
5. CNNVD 数据源接入                      → 验证：cnnvd_id 正确关联
6. 前端展示适配                          → 验证：列表/详情/筛选/导出正常
7. SyncOnly() 串联 + 同步历史记录完善     → 验证：全链路同步正常
```

#### 六、风险与注意事项

- CNVD/CNNVD 数据获取方式需要先确认授权和合法性，爬虫方案有被封 IP 的风险
- CNVD/CNNVD 部分漏洞没有 CVE 映射，需要支持仅有国内编号的漏洞记录
- 需要处理编号格式校验：CNVD-YYYY-NNNNN、CNNVD-YYYYMM-NNN
- ExploitDB/KEV 是标签维度而非漏洞源，不应产生新的 `vulnerabilities` 记录

---

## 中期方向

### 漏洞优先级排序

CVSS 基础分 + 运行状态 + 对外暴露 + 补丁可用性加权评分，前端按优先级排序。

### 攻击样本回放测试

建立关键场景测试样本（反弹 Shell、提权、挖矿、容器逃逸），CEL 规则回放验证。

### 等保/审计报表

按客户需求输出等保合规证据链报表。

## 远期方向

| 方向 | 说明 | 备注 |
|------|------|------|
| K8s 准入控制 | Webhook 拦截特权容器/hostPath/hostNetwork | 做 PoC 验证后推进 |
| 漏洞覆盖扩展 | 容器镜像、SBOM 导入、语言依赖 | 按需扩展 |
| FIM 实时化 | 评估 eBPF file_open 事件替代 AIDE | 现有方案够用 |
| 多租户 | 业务线级别数据隔离 | 需明确需求后推进 |
| 规则工程化 | 版本管理、灰度发布、命中率统计 | 需生产数据积累 |

## 技术决策记录

| 决策 | 选型 | 理由 |
|------|------|------|
| 运行时检测 | Tetragon（非自研 eBPF） | CNCF 生产就绪，避免内核兼容性问题 |
| 规则引擎 | CEL-Go（非 Falco/Sigma） | 嵌入式，无独立进程开销 |
| 漏洞库 | OSV.dev + NVD + Red Hat（已接入）；CNVD + CNNVD + ExploitDB/KEV（待接入） | 多源分层：OSV 主扫描，NVD/Red Hat 补充，CNVD/CNNVD 满足国内合规，KEV 标记在野利用 |
| 病毒引擎 | YARA-X（非经典 YARA） | Rust 重写，经典 YARA 已 EOL |
| 服务发现 | Redis（非 etcd） | AC 实例 <= 500 内无需引入额外组件 |
| RASP | 放弃 | OpenRASP 已停维护，Tetragon 可部分替代 |
