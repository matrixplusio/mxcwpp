# 漏洞扫描误报问题 — 深度评估

> User 反馈：prod 入库 CVE 与实际不符（CVE-2026-32253 / -39831 / -39832 / -44930 错关联到 openssl / ssh / httpd）。Gemini/ChatGPT 诊断为「description keyword 匹配」误报，建议改 CPE / OSV PURL 结构化匹配。

## 一、代码现状（事实先于结论）

**现有扫描器并未使用 description keyword 匹配。**

### 1.1 NVD 同步路径（`internal/server/manager/biz/nvd_sync.go`）

```go
// 行 159-167
// CPE 严格匹配已安装软件 — 唯一精确手段
// 历史 fallback：matchByDescription 用 substring keyword 匹配...
// 该 fallback 已废弃，永远不再使用。
// 无 CPE 配置（Awaiting Analysis）的 CVE 直接跳过，保证 99.99% 数据真实性。
matches := v.matchCPEToSoftware(item.CVE.Configurations, softwareByName)
if len(matches) == 0 {
    continue
}
```

匹配核心 `matchCPENode`（行 386-433）：
- 严格过滤 `cpe:2.3:a:*` (application only)
- `target_sw` 仅接受 Linux-compatible（拒绝 Windows/macOS-only CVE）
- 版本约束必须存在（`versionStart*` / `versionEnd*` 至少一个），否则拒绝
- 严格 range 比对已装版本

```go
// 行 624-628
// 注：matchByDescription + descKeywordMap 已永久删除。
// 该机制用 substring keyword 关联 CVE 与已装软件，准确性极差：
// 商业级 CWPP 仅用 CPE 严格匹配 + OSV PURL match + OS Advisory，禁止任何 substring fallback。
```

### 1.2 OSV 主扫描路径（`vuln_scanner.go`）

```go
// 行 547
req.Queries[i] = osvQuery{Package: osvPackage{PURL: purl}}
```

走 OSV.dev `/v1/querybatch` API，**PURL 精确匹配**（行业标准最强匹配）。

写入 `Component = pkgInfo.Name`（PURL 解析的真实包名），不用 description。

### 1.3 Red Hat 同步（`redhat_sync.go`）

```go
// 行 96
matches := v.matchRedHatPackages(item.AffectedPackages, softwareByName)
```

用 Red Hat API 返回的 `AffectedPackages`（结构化 RPM 包名），不用 description。

### 1.4 CNNVD 同步（`cnnvd_sync.go`）

**只补 CNNVD 编号映射**到已存在 CVE，不创建新漏洞。

### 1.5 Advisory Coordinator（`advisory/coordinator.go`）

用 `adv.AffectedPkgs[0].Name`（结构化），不用 description。

## 二、AI 诊断 vs 代码事实

| AI 论点 | 代码事实 | 准确性 |
|---|---|---|
| 用 description 关键字匹配 | matchByDescription 已永久删除（行 624-628 注释明示） | ❌ 错 |
| 应该用 CPE 配置节点 | 已用 `matchCPEToSoftware(item.CVE.Configurations, ...)` | ✅ 已实现 |
| 应该用 OSV PURL | 已用 `osvQuery.Package.PURL` 精确匹配 | ✅ 已实现 |
| 应该解析 cpe:2.3:a:vendor:product:version | `parseCPE23` 已完整解析 part/vendor/product/version/target_sw/target_hw | ✅ 已实现 |
| 应过滤 Windows-only CVE | `cpeTargetSWLinuxCompatible(parsed.targetSW)` 已严格过滤 | ✅ 已实现 |

**结论 1**：AI 的诊断不符合代码现状。它描述的是一个粗糙原型系统的问题，而我们的扫描器**早已**采用商业级 CWPP 标准的 CPE + PURL 严格匹配。

## 三、真实可能的误报根因（5 个候选）

代码层面无 description fallback，但 user 看到的误报数据真实存在。根因候选：

### 3.1 历史脏数据残留（最大可能）

`matchByDescription` 注释说"已永久删除"。但**MySQL `vulnerabilities` 表里的旧数据**仍是上次开启 description 时写入的，从未清理。

**验证方法**：
```sql
-- 查可疑 CVE 是否数据库里存在 + Component 字段是什么
SELECT cve_id, component, source, confidence, created_at FROM vulnerabilities
WHERE cve_id IN ('CVE-2026-32253', 'CVE-2026-39831', 'CVE-2026-39832', 'CVE-2026-44930');

-- 看 confidence='fake' 的脏数据（matchByDescription 写入时 confidence 设置为 'fake'）
SELECT COUNT(*) FROM vulnerabilities WHERE confidence='fake';
```

**修复**：批量删除 `confidence='fake'` 或源为 history-keyword 的旧数据。

### 3.2 cpeProductMatch 模糊匹配过宽

`nvd_sync.go:592-621`：
```go
// 软件名去掉常见前缀后匹配（python3-urllib3 → urllib3, lib64curl → curl）
prefixes := []string{"python3-", "python-", "perl-", "ruby-", "golang-", "lib", "lib64", "lib32"}
```

⚠️ `lib` 前缀剥离可能产生误关联：`libname` 主机包剥成 `name`，恰好 NVD 有 `cpe:2.3:a:vendor:name:*` 的不相关 CVE 时就误中。

**严格度评估**：中风险。`lib` 前缀剥离逻辑过于宽松，应限定到具体已知映射（如 `libssl` → `openssl`、`libcurl` → `curl`），不应通用剥离 `lib*`。

**修复**：把 `lib`/`lib64`/`lib32` 前缀剥离替换成显式映射表。

### 3.3 NVD CPE 数据本身错误（vendor confusion）

NVD 早期对小众软件（如 Sunshine 游戏流媒体）有时打错 CPE。比如把 Sunshine 漏洞的 CPE 误标为 `cpe:2.3:a:openssl:openssl:*`，因为 description 提到 OpenSSL verification。

**验证**：直接查 NVD JSON：
```bash
curl -s 'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-32253' | jq '.vulnerabilities[0].cve.configurations[].nodes[].cpeMatch[].criteria'
```

如果 CPE 真是 `openssl`，那是 NVD 数据错，不是扫描器错。

**修复**：上 OSV.dev 作主源（OSV 经 GHSA 团队人工校对，比 NVD CPE 准），NVD 作 fallback。

### 3.4 CPE versionRange 边界 bug

`cpeVersionInRange` 实现细节可能在某些 corner case 下错判：
- 比对 SemVer 与非 SemVer 版本（如 RHEL 风格 `1.0-1.el8.x86_64`）
- `versionEndExcluding` 字段含 epoch（`1:1.1.1f-21`）解析失败

**修复**：用 `github.com/Masterminds/semver/v3` + RPM-style 比较库（`github.com/sassoftware/go-rpmutils`）替代手写。

### 3.5 OSV 数据问题

OSV.dev 偶尔有错关 PURL 案例。极少见（< 0.1%），但确实存在。

**修复**：消费侧加 confidence label 区分（已实现：`Confidence` 字段）。

## 四、推荐方案（按优先级）

### P0 — 立即清理脏数据（30 分钟）

```sql
-- 1. 备份现有 vulnerabilities
CREATE TABLE vulnerabilities_backup_$(date +%Y%m%d) AS SELECT * FROM vulnerabilities;

-- 2. 删除 confidence=fake 的脏数据
DELETE FROM host_vulnerabilities WHERE vuln_id IN (SELECT id FROM vulnerabilities WHERE confidence='fake');
DELETE FROM vulnerabilities WHERE confidence='fake';

-- 3. 删除 user 报告的具体误报 CVE（如不是当前系统真实漏洞）
DELETE FROM host_vulnerabilities WHERE vuln_id IN (
    SELECT id FROM vulnerabilities WHERE cve_id IN ('CVE-2026-32253','CVE-2026-39831','CVE-2026-39832','CVE-2026-44930')
    AND component IN ('openssl','openssh','httpd')
);
DELETE FROM vulnerabilities WHERE cve_id IN ('CVE-2026-32253','CVE-2026-39831','CVE-2026-39832','CVE-2026-44930')
    AND component IN ('openssl','openssh','httpd');

-- 4. 触发全量重扫（OSV PURL + NVD CPE 重新匹配）
```

### P1 — 修 cpeProductMatch 前缀剥离过宽（2 小时）

替换通用 `lib` 剥离为显式映射表：

```go
var libToProduct = map[string]string{
    "libssl":    "openssl",
    "libcrypto": "openssl",
    "libcurl":   "curl",
    "libxml2":   "libxml2",
    "libxslt":   "libxslt",
    // ... 显式列出已知映射
}
```

不在表里的 `lib*` 包不做剥离 → 拒绝匹配。

### P2 — 提升 OSV 作主源 + NVD 降级（4 小时）

当前架构 OSV 主、NVD 补缺。但 OSV 优先级在某些路径不够明显。改造：

1. `VulnScanner.ScanIncremental` 先 OSV PURL match
2. NVD 仅对 OSV 未覆盖的 CVE 触发 CPE match（已存在的 OSV 记录跳过 NVD）
3. Red Hat advisory 对 RHEL/Rocky/CentOS 优先（OS-specific 最准）

### P3 — 加入 GHSA 数据源（1 周）

GitHub Advisory Database 是 OSV 数据的主要来源之一，但 GHSA 自己有更细 PURL 映射 + 维护团队人工校对。

补 `internal/server/manager/biz/ghsa_sync.go`：
- 拉 `https://api.github.com/advisories`（CVE + ghsa-id + 精确 affected packages）
- 写入 source='ghsa', confidence='high'

### P4 — version range 重构（1 周）

替换手写 `cpeVersionInRange`：
- `pkg:rpm/*` → 用 `go-rpmutils` 做 RPM 版本比较
- `pkg:deb/*` → 用 `go-debian/version`
- `pkg:*` → SemVer

### P5 — 加自检 + 误报反馈闭环（持续）

UI 上加「误报反馈」按钮 → 写 `vuln_false_positives` 表 → 扫描时跳过。
持续收敛长尾误报。

## 五、不推荐的方案

### ❌ 重写整套扫描器

AI 暗示要"改用 CPE/PURL"——已经实现。重写没意义且高风险。

### ❌ 上 LLM 二次校验 CVE↔包

成本高 + 延迟高 + 不可靠。CWPP 行业内没人用 LLM 做 P0 匹配。

### ❌ 切换 Trivy / Grype

这些工具有自己的特长但也有相同 CPE/PURL 误报问题。引入第三方等于双倍维护成本。

## 六、行动建议

按 P0 → P1 顺序立即做：

1. **今晚（user 醒后）**：执行 P0 SQL，清脏数据 + 重扫
2. **明天**：P1 改 cpeProductMatch
3. **本周**：P2 OSV 优先 + NVD 降级
4. **下周**：P3 GHSA 数据源
5. **下月**：P4 版本比较库重构 + P5 误报反馈

## 七、对 AI 诊断的总体评估

**Gemini/ChatGPT 的诊断只对了 50%**：
- ✅ 正确：CPE / OSV PURL 是商业级方案的正确方向
- ❌ 错误：诊断我们扫描器在用 description 匹配，这与代码事实不符
- ⚠️ 警示：跨 AI 信息可能基于通用粗糙系统假设。我方扫描器实际是商业级实现，**误报根因更可能是历史脏数据 + 边缘 cpeProductMatch 漏洞**，而非架构层错误。

User 决策建议：**别相信 AI 直接给的方案。先 P0 清脏数据 + 验证具体 CVE 在 NVD 的真实 CPE 是什么，再决定是否做 P2-P5**。
