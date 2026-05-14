# MxSec Tetragon 部署

Tetragon eBPF 事件采集策略，供 MxSec Sensor 插件消费。

## 文件说明

| 文件 | 用途 | DataType |
|------|------|---------|
| `process-monitor.yaml` | 进程执行 / setuid / ptrace | 3000 |
| `file-monitor.yaml` | 敏感文件访问 / 内核模块加载 | 3001 |
| `network-monitor.yaml` | TCP 外连 / DNS / C2 端口 | 3002 |
| `install.sh` | 一键安装部署脚本 |

## 前置条件

- Linux kernel >= 4.19（eBPF CO-RE 支持）
- systemd
- root 权限

## 安装

```bash
sudo ./install.sh
```

## 手动部署（已安装 Tetragon）

```bash
sudo cp *.yaml /etc/tetragon/tetragon.tp.d/
sudo systemctl restart tetragon
tetra tracingpolicy list   # 验证
```

## 查看事件

```bash
# 实时事件流
sudo tetra getevents -o compact

# JSON 详细事件
sudo tetra getevents
```

## 与 MxSec Sensor 插件集成

Sensor 插件通过 Unix socket 连接 Tetragon：

```
/var/run/tetragon/tetragon.sock
```

事件流被 Sensor 解析后，按 DataType 3000-3002 上报到 AgentCenter → Kafka → Consumer → ClickHouse `ebpf_events` 表。

## 卸载

```bash
sudo rm /etc/tetragon/tetragon.tp.d/mxsec-*.yaml
sudo systemctl restart tetragon
```
