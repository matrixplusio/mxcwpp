# Privilege escalation eBPF hooks (M1-1)

`privilege.c` 实现 6 个 kprobe 抓提权/容器逃逸/Rootkit 加载关键路径:

| Hook | 事件类型 | ATT&CK | 触发场景 |
|---|---|---|---|
| `kprobe/commit_creds` | 30 EVENT_PRIV_COMMIT_CREDS | T1548 提权 | UID/GID/cap 切换唯一入口, 抓所有提权 |
| `kprobe/__x64_sys_setreuid` | 31 EVENT_PRIV_SETUID | T1548.003 | 显式 setreuid/setresuid 系统调用 |
| `kprobe/__x64_sys_setregid` | 32 EVENT_PRIV_SETGID | T1548.003 | 显式 setregid/setresgid |
| `kprobe/__x64_sys_ptrace` | 33 EVENT_PRIV_PTRACE | T1055.008 | ptrace 注入/调试器附加 |
| `kprobe/__x64_sys_mount` | 34 EVENT_PRIV_MOUNT | T1611 | mount 调用 (容器逃逸经典) |
| `kprobe/security_kernel_module_request` | 35 EVENT_PRIV_KMOD_LOAD | T1547.006 | LKM rootkit 加载 (modprobe/autoload) |

## 生成 Go bindings

在 Linux 构建机 (须 clang >= 11 + libbpf-dev):

```sh
cd internal/agent/edr/collector
go generate ./...
```

产出 (与 process/file/network 同模式):

```
privilege_bpfel.go  / privilege_bpfel.o   (amd64, arm64)
privilege_bpfeb.go  / privilege_bpfeb.o   (s390x, mips — 罕用)
```

bpf2go 自动生成的 `loadPrivilegeObjects` 和 `privilegeObjects` 提供加载入口。

## Collector glue (后续 PR)

本 PR 仅落地 BPF 源 + event 常量 + Go event struct (待 `privilege_collector.go` 接入)。

待生成 bindings 后, 写 `privilege_collector.go`:

```go
type PrivilegeCollector struct {
    objs   privilegeObjects
    links  []link.Link
    reader *perf.Reader
}

func (c *PrivilegeCollector) Start() error {
    loadPrivilegeObjects(&c.objs, nil)
    link.Kprobe("commit_creds", c.objs.KprobeCommitCreds, nil)
    // ... 5 个其他 kprobe
    perf.NewReader(c.objs.PrivEvents, 4*4096)
}
```

## 关键设计选择

- **commit_creds 优于 setuid 系列**:
  setuid 只覆盖显式系统调用; commit_creds 是内核唯一入口,
  抓 capability 变更 / SUID 提权 / NS 切换 等所有路径

- **security_kernel_module_request 优于 init_module**:
  modprobe/autoload/udev 触发的加载也都走此 LSM hook, 覆盖更全

- **过滤 UID/GID 不变的 commit_creds**:
  commit_creds 高频 (每次 task_struct 创建都调), 仅 UID/GID 真切换才上报,
  否则 perf buffer 噪声爆炸

- **per-CPU scratch 替代栈**:
  privilege_event ~328 字节超 BPF 512 栈预算, 用 PERCPU_ARRAY 安全分配

- **kprobe 而非 fentry**:
  fentry 性能更好但需 BTF + 内核 >= 5.5; kprobe 兼容 5.4 (我们 minimum)

## 信创内核兼容

- Kylin V10 (5.4): commit_creds + 5 系统调用 OK; LKM hook 名可能不同, fallback `kernel_load_data`
- UOS (5.10): 全部 OK
- openEuler (5.10/4.19): 5.10 全 OK; 4.19 commit_creds + setuid OK, ptrace/mount/kmod 需 fallback
- Anolis (4.19/5.10): 同 openEuler

后续 PR 加 `kernel_version_probe.go` 在 Start() 期间按内核版本动态启用/跳过。
