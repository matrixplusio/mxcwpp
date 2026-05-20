# TODOLIST-FIX

架构评估发现的改进项，按维度和优先级分类。

---

## 模块实现完成度（2026-05-20 评估）

| 模块 | 完成度 | 说明 |
|------|--------|------|
| Agent 核心 | 85% | 插件管理、心跳、gRPC 通信、依赖管理均已实现 |
| 基线合规 | 85% | 212 条规则、9 种检查器、修复器，最完整的模块 |
| 通知系统 | 85% | 多渠道通知（邮件/钉钉/企微/飞书），完整实现 |
| 组件管理 | 90% | Agent/插件/依赖分发、推送记录、版本管理 |
| 资产采集 | 80% | 11 类采集器（进程/端口/用户/软件/容器等） |
| 报告系统 | 80% | 代码量最大的单个 API 模块，多类型报告生成 |
| FIM | 75% | 策略/事件/基线/分类器，有单元测试 |
| 漏洞管理 | 75% | OSV/NVD/RedHat 三源 + CVSS v3.1 + CNVD/CNNVD 标记 |
| 漏洞修复 | 70% | 一键修复 + 预检 + 诊断 + 自动验证 |
| 病毒查杀 | 70% | ClamAV + YARA-X 双引擎，隔离箱 |
| 告警体系 | 70% | 聚合/处置/白名单/溯源，缺告警去重 |
| K8s 容器安全 | 65% | CIS 基线 80 条、审计、告警，缺历史快照 |
| CEL 检测引擎 | 50% | 38 条规则 + 热加载，覆盖 MITRE ~15 个技术点 |
| 威胁情报 | 40% | abuse.ch IOC → Redis，未深度接入检测流水线 |
| EDR 自研引擎 | 10% | 仅 Tetragon 事件转发，设计文档规划的 13 个子系统均未实现 |

> EDR 设计文档 (`docs/edr-engine-design.md`) 规划了：自研 eBPF 采集层（cilium/ebpf）、YAML 规则库、
> 双层检测（Agent 端实时阻断 + Server 端深度分析）、进程因果追踪、行为基线、WAL 缓冲、网络隔离、
> 用户态降级（CentOS 7 兼容）等。当前仅实现了 Tetragon JSON 事件流客户端。

---

## 一、架构层

### Agent

- [ ] **[P1] Agent 全局资源降级机制**
  - 当前只有插件级 prlimit 和 Dormant 模式（依赖不可用时休眠）
  - 缺少基于宿主机系统负载的主动降级：CPU > 80% 降频、> 95% 暂停非关键采集
  - 参考青藤：系统负载过高时 Agent 自动降级运行，极端情况自杀保护业务

- [ ] **[P2] Agent 自杀机制**
  - 极端情况（Agent 本身异常占满 CPU）无法自我终止
  - 持续 5 分钟 CPU > 98% 时 Agent 应自动退出，由 systemd 重启恢复

- [ ] **[P2] RingBuffer 溢出监控**
  - 当前溢出时静默丢弃旧数据，无 metric 或日志告知丢弃数量
  - 建议增加丢弃计数 metric，纳入 Heartbeat 上报

### 数据管线

- [ ] **[P1] MySQL 数据自动清理**
  - ClickHouse 有 30 天 TTL、Kafka Topic 有保留策略、Redis 有 TTL
  - MySQL 的 scan_results / fim_events / command_ack_records 无自动清理
  - 建议 Manager 增加定时任务：scan_results 保留 90 天、command_ack 保留 90 天

- [ ] **[P2] ClickHouse 故障降级告警**
  - Consumer 中 ClickHouse 初始化失败时仅 Warn + 跳过
  - eBPF 事件存储和告警上下文取证依赖 ClickHouse
  - 建议增加健康检查和降级通知（日志 + 可选告警）

---

## 二、资产采集层

### 采集调度

- [ ] **[P0] 首次采集随机延迟**
  - 当前所有 Handler 启动后立即全量采集上报
  - 大量 Agent 同时启动（K8s 滚动更新）会瞬间压爆 AC/Kafka
  - 参考 Elkeid：首次执行加入 0~interval 随机延迟错峰上报

- [ ] **[P1] 重型采集错峰执行**
  - software(rpm -qa)、app(版本命令) 有 IO 开销，固定 12h/6h 间隔可能在业务高峰期执行
  - 参考 Elkeid BeforeDawn：凌晨 2-4 点随机执行重型采集

- [ ] **[P1] 容器采集间隔缩短为 5 分钟**
  - 容器生命周期经常只有几分钟，1 小时间隔会错过短命容器
  - Elkeid 容器采集间隔为 5 分钟

- [ ] **[P1] 增加 batch_seq 批次标识**
  - 每次全量采集生成唯一批次 ID，随数据上报
  - Server 端可做前后批次 diff 对比、完整性校验
  - 参考 Elkeid package_seq（FNV-32 hash of timestamp）

### 容器关联

- [ ] **[P0] 容器关联改用 PID namespace**
  - 当前用 cgroup 字符串匹配（/docker/、/containerd/），cgroup v2 下路径格式不同会失效
  - 改为读取 /proc/{pid}/ns/pid inode 与容器列表 pns 对比
  - 同时增加 container_name 字段（从 Docker/CRI API 获取）

- [ ] **[P1] 跨 Handler 缓存共享**
  - 容器采集的 container_id → container_name 映射应共享给进程/端口采集器
  - 避免每个 Handler 独立解析 cgroup 的重复工作

### 字段补充

- [ ] **[P1] 进程采集增加 start_time + container_name**
  - start_time：从 /proc/{pid}/stat 第 22 个字段解析，基础资产信息
  - container_name：通过跨 Handler 缓存从容器采集获取

- [ ] **[P1] 增加 pypi/jar 软件包采集**
  - Python 依赖：pip list --format=json 或解析 site-packages
  - Java 依赖：扫描运行中进程加载的 jar 文件
  - 补齐 Python/Java 应用的依赖资产发现

- [ ] **[P2] 端口采集增加绑定 IP**
  - 当前只采集端口号，不采集绑定的 IP 地址
  - /proc/net/tcp 的 local_address 字段已包含 IP，解析即可

- [ ] **[P2] 应用检测增加 PHP-FPM/Etcd/Kubelet/Tomcat**
  - PHP-FPM：Web 场景常见
  - Etcd/Kubelet：K8s 环境组件
  - Tomcat：Java Web 常用

### 架构优化

- [ ] **[P2] 应用检测改为规则表驱动**
  - 当前每个应用一个 detect 函数（硬编码），扩展需写代码
  - 参考 Elkeid ruleMap：进程名→版本命令→正则→配置路径，加应用只需加规则
  - 支持层级子规则（Nginx → Tengine → OpenResty）

### 资产变更检测

- [ ] **[P2] Server 端资产变更对比**
  - 当前全量采集直接覆盖，无变更记录
  - 对比两次全量快照，生成新增/删除/修改事件
  - 敏感变更（新账号、新端口、新进程）触发通知
  - 参考青藤：持续监控敏感资产变更，支持实时/定时通知

---

## 三、EDR 检测层

### 当前能力概览

| 能力 | MxSec | 青藤万相 | 长亭牧云 | Elkeid |
|------|-------|---------|---------|--------|
| 内核事件采集 | Tetragon eBPF（进程/文件/网络） | 用户态 Agent（无内核模块） | 无 eBPF（Safe Bash 方案） | 自研 eBPF Driver（进程/文件/网络/DNS） |
| 规则引擎 | CEL-Go（嵌入式） | 私有引擎 | 私有引擎 | Sigma/自研 HUB |
| 进程事件 | exec/exit + PID/PPID/cmdline/UID | 完整进程树 + 行为链 | 进程审计 | exec/exit + 完整进程树 |
| 文件事件 | open/read/write（仅路径+flags） | 文件篡改 + 蜜罐文件 | 文件变更审计 | open/read/write + rename/unlink |
| 网络事件 | tcp/udp/icmp（IP:Port 级） | 外联检测 + DNS 审计 | 端口扫描检测 | tcp/udp/dns + SSL SNI |
| 端口扫描检测 | Redis 滑动窗口（60s/10 端口） | 内置引擎 | 内置 | 无内置 |
| 自动响应 | kill/隔离/封堵（仅 critical） | kill/隔离/封堵 + 工单联动 | 阻断 + 修复 | kill/隔离 |
| 多步攻击检测 | 序列检测器（内存态，未持久化） | 攻击链可视化 + ATT&CK 图谱 | 行为序列 | 无内置 |
| 威胁情报 | abuse.ch 3 源（未接入检测流） | 商业情报 + 0day 推送 | 商业情报 | 社区情报 |
| MITRE ATT&CK | 规则级标注 mitre_id | 完整 ATT&CK 矩阵映射 | ATT&CK 视图 | 规则级标注 |

### 事件采集

- [ ] **[P0] 增加 DNS 查询事件采集**
  - 当前只采集 IP:Port 级网络事件，无法检测 DGA 域名、DNS 隧道、恶意域名解析
  - Tetragon 支持 kprobe hook udp_sendmsg（dst_port=53）解析 DNS payload
  - 或 hook dns_resolve/getaddrinfo 在应用层采集
  - 竞品对比：Elkeid 有完整 DNS 审计；青藤有外联域名检测

- [ ] **[P1] 增加文件 rename/unlink/chmod 事件**
  - 当前文件事件只有 open/read/write，无法检测文件删除、重命名、权限篡改
  - 日志清除（rm /var/log/*）、后门权限提升（chmod u+s）等攻击无法检测
  - Tetragon kprobe 挂载 security_inode_rename / security_inode_unlink / security_inode_setattr

- [ ] **[P1] 进程事件增加 env / cwd / tty 字段**
  - env：检测 LD_PRELOAD 注入、代理劫持（HTTP_PROXY）
  - cwd：辅助判断进程上下文（从 /tmp 启动 vs /usr/bin）
  - tty：区分交互式 shell 和后台进程，辅助 T1059 检测
  - 竞品对比：青藤采集完整进程上下文

- [ ] **[P2] 网络事件增加 bytes/direction 字段**
  - 当前只知道连接了谁，不知道传输了多少数据
  - 大流量外传（数据窃取 T1041）无法仅靠连接事件检测
  - Tetragon kprobe 可获取 send/recv 字节数

### 检测能力

- [ ] **[P0] 威胁情报接入检测流水线**
  - abuse.ch IOC 已同步到 Redis，但 CEL 规则无法直接查询 Redis
  - 方案：Consumer 在评估 CEL 前先做 IOC 预匹配，匹配到的事件注入 `ioc_hit=true` 字段
  - 网络事件：remote_addr 匹配恶意 IP；进程事件：exe MD5 匹配恶意哈希
  - 竞品对比：青藤有实时 0day 情报推送 + 自动检测联动

- [ ] **[P0] 进程树构建与关联分析**
  - 当前每个事件孤立评估，无法检测跨事件攻击模式
  - 例：Apache → bash → curl → /tmp/payload → chmod +x → 执行，需关联 5 个事件
  - 方案：Consumer 维护内存进程树（host_id → pid → ProcessNode），事件评估时注入父链信息
  - 竞品对比：青藤/Elkeid 均有完整进程树 + 攻击链可视化

- [ ] **[P1] 序列检测规则持久化**
  - SequenceDetector 逻辑完整，但规则只在内存中
  - 需要：数据库存储 + API CRUD + 热加载
  - 参考现有 detection_rules 表结构扩展

- [ ] **[P1] 告警聚合去重**
  - 当前每次规则命中都生成独立告警（无去重）
  - 同一主机同一规则持续触发会产生大量重复告警（告警风暴）
  - 方案：相同 (host_id, rule_id) 在窗口期内只更新 last_seen_at + 计数，不新建告警
  - 竞品对比：青藤有告警合并 + 攻击事件聚合

- [ ] **[P2] CEL 引擎增加聚合函数支持**
  - 当前 CEL 只能做单事件布尔判断
  - 无法表达 "10 秒内同一主机 5 次 exec" 等频率类规则
  - 方案：在 CEL 环境中注入自定义函数 count_recent(field, window, threshold)
  - 底层用 Redis 滑动窗口实现（类似 ScanDetector）

- [ ] **[P2] 增加蜜罐文件检测**
  - 在关键路径放置诱饵文件（/root/.ssh/config.bak、/tmp/.mysql_backup）
  - 文件被读取/写入时立即触发高危告警（攻击者横向移动/信息收集）
  - 竞品对比：青藤有蜜罐文件 + 蜜罐服务（高交互诱捕）

### 自动响应

- [ ] **[P1] 响应动作执行确认**
  - 当前 kill/隔离/封堵 发送命令后无验证
  - Agent 执行结果应通过 command_ack 回传，AutoResponder 检查执行状态
  - 失败时重试（最多 3 次）+ 记录最终状态

- [ ] **[P2] IP 封堵白名单**
  - 当前所有 critical 规则的 remote_ip 都会触发封堵
  - 误封内网网关/DNS/监控 IP 会导致业务故障
  - 需要配置封堵白名单 + 封堵时长（非永久）

### 报告与可视化

- [ ] **[P2] ATT&CK 矩阵视图**
  - 当前只有规则级 mitre_id 标注，无全局 ATT&CK 覆盖度视图
  - 需要前端实现 ATT&CK 矩阵热力图：哪些技术已覆盖、哪些告警命中
  - 竞品对比：青藤有完整 ATT&CK Navigator 视图
