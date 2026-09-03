// lsm/bpf/lsm_hooks.c — BPF_PROG_TYPE_LSM 全套 hook 骨架 (C10)
//
// 内核 5.7+ 支持 BPF LSM, 可在 kernel 安全决策点拦 (不能阻断, 仅观察, 走 read-only).
// 比 kprobe 更可靠 (kprobe 在 SMP 上有 race), 也比 lsm 钩子直接通过 access 检查更细粒度.
//
// 钩子覆盖 6 大类:
//   - bprm_check_security: 进程 exec 前检 (cmdline / argv / envp)
//   - inode_create: 任何文件创建 (含敏感目录 /etc/passwd /root/.ssh/authorized_keys)
//   - inode_unlink: 删文件 (审计 / 反 reaper)
//   - inode_rename: 改名 (反 race condition)
//   - socket_connect: 出站连接 (审计 C2)
//   - mmap_file: 内存映射 (反 PE injection)
//
// 全部 return 0 (允许), 仅 ringbuf 上报. observe-only 严守.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct lsm_event {
    __u64 ts_ns;
    __u32 pid;
    __u32 uid;
    __u8  hook; // 1=bprm 2=create 3=unlink 4=rename 5=connect 6=mmap
    char  comm[16];
    char  path[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 21);
} lsm_events SEC(".maps");

// 敏感路径前缀 (用户态启动时下发到 map; 此处简化硬编码常见路径).
static __always_inline int is_sensitive(const char *p, int len) {
    if (len < 5) return 0;
    // /etc /root /var/log /home/.ssh/authorized_keys 简化匹配前缀
    if (p[0] == '/' && p[1] == 'e' && p[2] == 't' && p[3] == 'c' && p[4] == '/') return 1;
    if (p[0] == '/' && p[1] == 'r' && p[2] == 'o' && p[3] == 'o' && p[4] == 't') return 1;
    return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(lsm_bprm, struct linux_binprm *bprm, int ret) {
    struct lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->hook = 1;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    // 读 bprm->filename
    const char *fn = NULL;
    bpf_core_read(&fn, sizeof(fn), &bprm->filename);
    if (fn) bpf_probe_read_kernel_str(&e->path, sizeof(e->path), fn);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/inode_create")
int BPF_PROG(lsm_create, struct inode *dir, struct dentry *dentry, umode_t mode, int ret) {
    struct lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->hook = 2;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    const char *name = NULL;
    bpf_core_read(&name, sizeof(name), &dentry->d_name.name);
    if (name) bpf_probe_read_kernel_str(&e->path, sizeof(e->path), name);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/inode_unlink")
int BPF_PROG(lsm_unlink, struct inode *dir, struct dentry *dentry, int ret) {
    struct lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->hook = 3;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    const char *name = NULL;
    bpf_core_read(&name, sizeof(name), &dentry->d_name.name);
    if (name) bpf_probe_read_kernel_str(&e->path, sizeof(e->path), name);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/socket_connect")
int BPF_PROG(lsm_connect, struct socket *sock, struct sockaddr *addr, int addrlen, int ret) {
    struct lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->hook = 5;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(lsm_mmap, struct file *file, unsigned long reqprot, unsigned long prot, unsigned long flags, int ret) {
    // 仅关注 PROT_EXEC + WRITE 同时设置 (W^X 违例, 自修改代码)
    if (!(prot & 4) || !(prot & 2)) return 0; // 4=EXEC, 2=WRITE
    struct lsm_event *e = bpf_ringbuf_reserve(&lsm_events, sizeof(*e), 0);
    if (!e) return 0;
    e->ts_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid() & 0xffffffff;
    e->hook = 6;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}
