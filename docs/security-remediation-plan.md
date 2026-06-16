# 安全加固落地方案（Agent↔AC 信任链 + 越权 + 注入 + 微服务）

**生成日期**: 2026-06-15 | **状态**: 实施中 | **审计基线分支**: kerbos/feat-prod-v2-services

本文是一次系统性安全审计后的修复落地方案。审计覆盖传输层、鉴权授权、注入/输入校验、密钥与微服务四个域，对照 OWASP Top 10 与工业级 CWPP 标准。

## 已确认的决策

1. **存量 agent 迁移**：双轨灰度自动签发（AC 临时同时认旧共享证书 + 新一机一证，老 agent 上线自动换新证，全网换完再关旧证认可，零掉线）。
2. **AC gRPC 端口（6751）暴露面**：仅内网/VPC。→ CRITICAL 紧迫度为"内网横向移动后可利用"，仍按 CRITICAL 修复（失陷主机横向是 CWPP 常态威胁模型）。
3. **LLM 数据出境**：默认本地模型（自托管 ollama）+ 外发前脱敏主机名/IP + 数据出境开关默认关（国内合规）。

## 威胁模型

- **TM-1 中间人/伪造 AC**：内网攻击者冒充 AC，劫持 agent（换证、下发危险指令）。
- **TM-2 恶意/伪造 agent**：攻击者伪造 AgentID 顶替他人主机，或灌流量打垮 AC。
- **TM-3 越权租户/用户**：合法登录态横向/纵向越权访问他人数据与管理接口。
- **TM-4 注入/RCE**：通过 server 下发链路或 API 输入触发命令执行/路径逃逸/SSRF。
- **TM-5 供应链/数据出境**：漏洞库投毒、敏感数据外发第三方 LLM。

---

## 批 1：Agent↔AC 信任链（对应 TM-1 / TM-2）

修的根因三连环：① mTLS 名存实亡（服务端 `VerifyClientCertIfGiven` + 客户端首连 `InsecureSkipVerify` 无 pinning）；② AgentID 取自消息体零 TLS 绑定；③ 全网共享一张证书且无吊销。

**安全实施顺序（每步可独立上线、不停机）**：

- **步骤 1（纯增量）**：CA 支持按 AgentID 签发单机证书 `SignAgentCert(caBundle, agentID)`，CN=AgentID，ExtKeyUsage=ClientAuth。不影响任何现网行为。`internal/deploy/cluster/certs.go`
- **步骤 2（纯增量）**：AC 新增签发接口（enroll）。agent 带 bootstrap token 申请单机证书，AC 校验 token 后用 CA 在线签发返回。proto 加 `bootstrap_token` / enroll RPC。agent 内置 AC CA 指纹（pin）。
- **步骤 3（纯增量）**：agent 引导逻辑——本地无单机证书时走 enroll（CA pinning 校验 AC 身份），换到单机证书；有则正常 mTLS。废除 `InsecureSkipVerify` 兜底路径（改为 pin 校验）。`internal/agent/connection/connection.go`
- **步骤 4（观察期，不拒绝）**：AC 用 `peer.FromContext` 取客户端证书 CN，与消息体 AgentID 比对，**不一致只告警不拒绝**，观察存量迁移进度。`internal/server/agentcenter/transfer/service.go:224`
- **步骤 5（吊销）**：AC 维护吊销序列号黑名单，`VerifyPeerCertificate` 回调拒绝。
- **步骤 6（翻开关，全网迁移完成后）**：服务端 `ClientAuth=RequireAndVerifyClientCert`；CN≠AgentID 直接拒；关闭旧共享证书认可与无条件证书下发。`internal/server/agentcenter/server/server.go:51`
- **步骤 7（下行信任）**：见下方"步骤 7 范围说明"。

### 批 1 实施记录（分支 kerbos/sec-agent-ac-trust-chain）

**设计原则**：零 proto 改动（bootstrap 令牌走 gRPC metadata，单机证书复用现有 `CertificateBundle` 消息）；全部新行为由 server 配置 `mtls.*` 开关控制，默认全关，现网零影响。

已落地：
- `internal/common/certissue`：按 AgentID 在线签发单机证书 `SignAgentCert` + CA 指纹 `CAFingerprint` + 链 pin 校验 `VerifyChainPinnedCA`（含单测）。
- `internal/deploy/cluster/certs.go`：`SignAgentCert` 委托 certissue。
- AC `mtls` 配置新增：`ca_key` / `enroll_token` / `per_agent_cert` / `enforce_agent_id` / `revoked_serials`。
- AC `server.go`：握手期 `VerifyPeerCertificate` 吊销序列号（覆盖 Transfer + FileExt）；保留 `VerifyClientCertIfGiven`（单监听端口需放行 enroll 无证书连接），强制鉴权移到应用层。
- AC `transfer`：`peerLeafCert` 取已验证 peer 证书 CN，与上报 AgentID 绑定；`enforce_agent_id=false` 观察模式（只告警），`=true` 强制（CN 不符/无证书且令牌无效则拒）；`per_agent_cert` 开启时 enroll 校验令牌后在线签发单机证书下发。
- agent `connection.go`：首连 `firstConnectTLSConfig`，配置 `ca_fingerprint` 时 `VerifyConnection` pin 住 AC CA，否则回退兼容模式。
- agent `transport.go`：enroll 令牌经 metadata 上报。
- agent `sync.go`：下发 CA 与 pin 不符则拒绝落盘（防中间人换 CA 永久劫持）。
- agent `main.go`：首次签发完成后主动重连，切到单机证书 mTLS。

### 步骤 7 范围说明（重要）

原计划"所有高危下行指令 ed25519 签名"，经安全分析后修正为以下组合，理由在此说明，避免做无效防护：

- **换证（CertificateBundle）**：已由 agent 端 CA 指纹 pin 防护——下发的 CA 与 pin 不符即拒绝（`sync.go`）。这直接堵死"中间人换 CA 永久劫持"。✅
- **自更新包（AgentUpdate）**：已有 ed25519 离线签名校验（`updater/signature.go`，私钥离线）。✅
- **重启/config**：步骤 1-6 完成后，agent 经 pin 的 CA 校验 AC 身份，中间人无法冒充 AC 注入这些指令，由 mTLS 通道保证真实性。
- **依赖安装（DependencyInstall）**：残余 RCE 面（从 AC 指定 URL 下载执行）。用 AC 在线 CA 签名无意义——能签名者即已控制 AC。正确控制是**下载源白名单 + 包签名**，归入批 3（H 级"DownloadUrl 白名单 + 包签名"）。

结论：用 AC 在线密钥给动态指令签名，对"AC 被攻陷"无防护价值（攻陷 AC 即握有 CA）；真正的真实性保障是步骤 1-6 的双向 mTLS + 离线签名的自更新 + 批 3 的依赖源白名单。

---

## 批 2：多租户越权（对应 TM-3，OWASP A01）

根因：业务路径 `/api/v1/*` 从未挂 tenant 中间件；91 个 handler 仅 8 个做租户过滤 → ~240 处跨租户 IDOR；写操作挂"任意登录用户"；权限表存在但无中间件强制。

- **步骤 1（一处兜底挡大面）**：注册 GORM 全局 Query/Update/Delete callback，从 gin context 取 tenant 自动加 `WHERE tenant_id=?`。一处修复覆盖绝大多数 IDOR。
- **步骤 2**：`apiV1Auth` 强制挂 `tenant.Middleware()`，写入 tenant identity 供 callback 读取。
- **步骤 3**：写操作（扫描/修复/网络阻断/删隔离/集群管理）收敛到 admin 组或加 `RoleMiddleware`。
- **步骤 4**：落地基于 permission 表的 `RequirePermission(code)` 中间件，让 RBAC 真正生效。
- **步骤 5**：超管 token 禁止误走业务路径（强制 Middleware 兜底）。

---

## 批 3：注入 / RCE / SSRF（对应 TM-4，OWASP A03）

SQL 注入已确认安全（全面参数化），本批针对命令注入、路径遍历、SSRF、DoS。

- **命令注入**：baseline `checkers.go:227`（`sh -c` 拼 `rule.Param[0]`）、`fixer.go:52`（`bash -c` 拼 `rule.Fix.Command`）改命令白名单/数组参数化；remediation `main.go:353` fix 路径补 `validPkgName` 校验（与 precheck 对齐）。
- **路径遍历→RCE**：`internal/agent/plugin/plugin.go` `validatePluginConfig` 加 `filepath.Base(cfg.Name)==cfg.Name` 校验，防 `../` 目录外写可执行文件。
- **SSRF**：提取公共 `pkg/ssrf`（强制 http/https + 解析 IP 拒内网/loopback/link-local/元数据 169.254.169.254 + 逐跳 CheckRedirect），接入通知 webhook（`notifications.go`）、漏洞数据源（`vuln_data_sources.go`）落库与发送两端。
- **DoS**：CEL 引擎加 `cel.CostLimit` + `InterruptCheckFrequency` + 求值 context 超时（`celengine/engine.go`、`kube/rule_engine.go`）；分页 page_size 统一走 `ParsePagination` 收敛上限。

---

## 批 4：AC 加固 + 微服务 + 合规（对应 TM-2 / TM-5）

- **AC 抗 DoS**：加 panic recovery interceptor、`grpc.MaxConcurrentStreams`、全局连接数上限、按 AgentID/IP 令牌桶限流。`internal/server/agentcenter/server/server.go`
- **llmproxy**：`/complete` `/embed` 加内部认证（复用 v1 `X-Internal-Secret`）；prompt 注入隔离（结构化输入分离 system/data + 固定输出 schema 校验）；默认本地模型 + 外发脱敏 + 出境开关默认关。
- **vulnsync**：漏洞数据源完整性校验（已解析的 checksum 字段实际校验；支持 GPG 的源验签），防供应链投毒。
- **其他**：JWT jti 黑名单（Redis）支持注销/吊销；登录接口接线 IP 限流（限流中间件已写好未接线）+ 修 KeyByTenant 读错 key 的 bug；安全响应头中间件（HSTS/X-Frame-Options/X-Content-Type-Options/CSP）；v2 三镜像加非 root user；OTel 生产关 insecure。

### 批 4 实施记录（分支 kerbos/sec-hardening-batch4，2026-06-16，已合 dev 未 push）

新增开关默认全关（生产灰度开），panic recovery 与「数据出境默认关」为安全默认。

- **AC 抗 DoS**：`grpc.anti_dos.*` 配置（`max_concurrent_streams`/`max_conns`/`per_ip_rps`/`per_ip_burst`）。panic recovery 拦截器始终启用；`agentcenter/server/antidos.go`（recovery + 单 IP 令牌桶 `golang.org/x/time/rate`）；全局连接上限用 `netutil.LimitListener`（`agentcenter/setup/init.go`）。
- **llmproxy**：`security.go` 内部认证（常量时间比较）挂 `/complete` `/embed`；`llm_assist.go` 改 system/data 分离 + 输出 schema 校验（不再回显原始模型文本、riskLevel 枚举强校验）；新 `llmproxy/redact` 包做 IP/主机名脱敏 + 本地端点判定；出境默认关（`LLM.AllowDataEgress=false`，仅本地模型），router 与 llm_assist 两条路径均接入。
- **vulnsync**：新 `vulnsync/integrity` 包（checksum 格式校验 + 摘要比对 + detached GPG 验签）；Rocky advisory 校验已解析 checksum 格式并带入 `PkgFix.Checksum` 供下游验包。
- **JWT 黑名单**：`auth.go` Logout 写 jti 到 Redis（TTL=剩余有效期），`AuthMiddleware` 校验，Redis 异常 fail-open。`server.security.jwt_blacklist.enabled`。
- **安全响应头**：`middleware/security_headers.go`，`server.security.headers.{enabled,hsts,csp}`。
- **登录 IP 限流**：`server.security.login_rate_limit.*` 挂 `/auth/login` + `/auth/login-precheck`（按 IP）；修 `KeyByTenant` 读错 context key（改用 `tenant.GetIdentity`）。
- **v2 镜像 non-root**：engine/llmproxy/vulnsync Dockerfile 加 uid 10001 用户，chown 日志/工作目录。

注：OTel 生产关 insecure 本批未做。新单测：`redact`、`integrity`、router egress 路径。

---

## 已确认达工业级（保持，不动）

- SQL 注入：全面参数化，order by 白名单，无 LIKE 注入。
- JWT 算法硬校验（防 alg=none / RS→HS 混淆）、bcrypt 密码、secret 长度校验、登录验证码 + 账户锁。
- CORS 白名单（非 `*`）、错误不泄露堆栈。
- 无硬编码真实密钥、无私钥误入库、依赖锁版本无高危老版本。
- agent 自更新 ed25519 签名校验（作为下行签名推广模板）。
- v2 config-change / MSSP 层正确按 tenant 过滤（正确范式，v1 历史 handler 待回填）。

---

## 纵向越权 + RBAC（分支 kerbos/feat-rbac-vertical-authz，单租户）

多租户取消（一企业一租户），但纵向越权与 RBAC 仍落地。

**问题**：`permissions`/`role_permissions` 表已建已 seed 但无任何中间件强制执行（仅供 UI 渲染）；~30 个危险写操作挂在普通登录组，任何 user 登录即可调用（漏扫/修复下发/网络阻断/隔离删除/主机删除/K8s 增删改/规则增删）。实际只有 admin/user 两档。

**实现**（`internal/server/manager/api/permission_enforce.go`）：
- `PermissionResolver`：缓存 `role→{permCode}`，`Has(role,code)` 判定，admin 恒通过；内存缓存，`UpdateRolePermissions` 后 `ReloadGlobalResolver()` 失效刷新。
- `EnforceWritePermissions` 中间件挂在 apiV1Auth 组：按 `c.FullPath()` 做**最长前缀匹配**映射到 14 个模块级 code（vuln/kube/detection/fim/virus/baseline/operations/assets/alerts），仅校验写操作（GET/HEAD/OPTIONS 放行），缺权限 → 403。
- 读不卡、写按模块卡；user 默认无写权；危险操作需管理员在 RBAC 面板显式授权。让 `role_permissions` 表真正参与放行。

**实测**（dev 活体）：user 写 scan/host-del/kube-create 全 403、读 200、admin 全通过；admin 授予 user `vuln` 后 user scan 即 200（缓存热刷新）、kube 仍 403（粒度生效）、撤销后复 403。
