# P2-5 Plugin IPC os.Pipe → UDS 评估

## 现状

`internal/agent/plugin/plugin.go:319-329` 每 plugin 创 2 个 `os.Pipe()`:
- `rx_r, rx_w`: Agent ← Plugin (上行)
- `tx_r, tx_w`: Agent → Plugin (下行)
- 子进程 ExtraFiles 拿到 fd 3 (tx_r) + fd 4 (rx_w)
- Agent 进程持 rx_r + tx_w 共 4 fd / plugin

10 plugin × 4 fd = 40 fd. RLIMIT_NOFILE 1024 默认充足, 但极端场景 (插件 50+) 接近上限.

## P2-5 改 socketpair 方案

`syscall.Socketpair(AF_UNIX, SOCK_STREAM, 0)` 返 2 个 fd, 双工通信, 父子各持 1 fd:
- 4 fd / plugin → 2 fd / plugin (-50%)
- 单 socket 双工省 syscall (read+write 共享 buffer)

## 阻塞因素

1. **Protocol break**: plugin SDK 假设 fd 3 = 读, fd 4 = 写. 改 socketpair → fd 3 双工, 需所有 plugin 二进制配套升级
2. **跨语言 SDK**: 当前 Go SDK 走 io.Reader/io.Writer, 改双工 socket 需重写
3. **Backward compat 难**: 旧 plugin (v1.x) 二进制无法跟新 Agent 通信
4. **Wire format**: 当前 length-prefixed message 协议依赖单向 pipe 简化逻辑, 双工 socket 需加序列号防 race

## 收益

- 单 host 节省 ~20 fd (10 plugin × 2)
- syscall 数 read+write 合并 (10-15% IPC 吞吐)
- 整体 IPC 性能 < 5% (非热点)

## 决策

**Skip P2-5 实做**:
- 收益 (5% IPC + 50% fd) 远低于 protocol break 风险
- fd 限制非瓶颈 (sysctl fs.file-max 默认 8M)
- 跨插件二进制兼容性破坏面大

**保留方案**: v3.0 plugin SDK 重构时同步切换 (建议改成 gRPC over UDS, 走 protobuf 协议而非裸 length-prefixed bytes).

**短期收益**: 已通过其他 P0/P1 项达成 (Async Kafka / pipeline 解码 / worker pool 已支撑 100k EPS, IPC 非瓶颈).

## 当前 mitigation

- 加 RLIMIT_NOFILE 检查 + 启动告警 (插件数 × 4 > soft limit 时 warn)
- plugin 异常退出走 dormant 模式避免 fd 泄漏

留 v3.0 SDK 重构时整体改造.
