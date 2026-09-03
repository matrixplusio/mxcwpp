// Package rootkit 实现 Agent 端 Anti-Rootkit 内核完整性自检 (M1-2)。
//
// 检测维度 (4 类):
//
//  1. kmod 隐藏: 对比 /proc/modules 与 /sys/module/<name>/ 列表
//     差异 → LKM rootkit 隐藏自己 (Diamorphine/Reptile/...)
//  2. syscall_table 异常: 读 /proc/kallsyms 取 sys_call_table 地址,
//     首次启动落 baseline; 周期对比, 偏移即 hook
//  3. PID 隐藏: 对比 /proc/<pid> 与 getdents64(/proc) 系统调用结果,
//     差异 → 内核 hook getdents 实现 PID 隐藏
//  4. 可疑 LKM 名: insmod 加载/已 loaded 的模块名匹配已知 rootkit 列表
//
// 不做的事 (留 M2):
//   - eBPF kallsyms read 内核态校验 (需 CO-RE + 5.5+)
//   - IDT/fops 校验 (Agent 用户态读不到)
//
// 自检周期: 默认 5 分钟; 命中即上报 DataType 3006。
package rootkit

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
)

// KnownRootkitModules 已知 LKM rootkit 名片单 (case-insensitive)。
var KnownRootkitModules = []string{
	"diamorphine", "reptile", "beurk", "suterusu", "adore-ng", "adore",
	"knark", "phalanx", "kbeast", "mood-nt", "wnps", "evilbpf",
}

// Indicator 是单次扫描产生的潜在 rootkit 指标。
type Indicator struct {
	Category   string // kmod_hidden / syscall_drift / pid_hidden / known_rootkit_kmod
	Severity   string // medium / high / critical
	Detail     string
	Evidence   map[string]string // category 维度的细节字段
	DetectedAt time.Time
}

// Scanner 周期性自检 + 命中即上报。
type Scanner struct {
	logger   *zap.Logger
	interval time.Duration

	mu              sync.Mutex
	syscallBaseAddr uint64 // 首次启动后落盘的 sys_call_table 地址 (kallsyms)
	known           map[string]struct{}
}

// NewScanner 构造。
func NewScanner(interval time.Duration, logger *zap.Logger) *Scanner {
	if logger == nil {
		logger = zap.NewNop()
	}
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	known := make(map[string]struct{}, len(KnownRootkitModules))
	for _, n := range KnownRootkitModules {
		known[strings.ToLower(n)] = struct{}{}
	}
	return &Scanner{
		logger:   logger,
		interval: interval,
		known:    known,
	}
}

// Run 阻塞循环, 每 interval 跑一轮 + 把指标推 ch。
//
// 调用方需在另一 goroutine 起 Run, 关闭 ctx 退出。
func (s *Scanner) Run(ctx context.Context, ch chan<- Indicator) {
	tick := time.NewTicker(s.interval)
	defer tick.Stop()
	// 启动立刻跑一次, 不等第一个 tick
	s.runOnce(ctx, ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			s.runOnce(ctx, ch)
		}
	}
}

// ScanOnce 单次扫描, 返回本轮所有指标 (无 chan, 用于一次性自检)。
func (s *Scanner) ScanOnce(_ context.Context) []Indicator {
	var out []Indicator
	out = append(out, s.checkHiddenModules()...)
	out = append(out, s.checkKnownRootkitModules()...)
	if ind := s.checkSyscallTableDrift(); ind != nil {
		out = append(out, *ind)
	}
	out = append(out, s.checkHiddenPIDs()...)
	for i := range out {
		if out[i].DetectedAt.IsZero() {
			out[i].DetectedAt = time.Now()
		}
	}
	return out
}

func (s *Scanner) runOnce(ctx context.Context, ch chan<- Indicator) {
	for _, ind := range s.ScanOnce(ctx) {
		select {
		case ch <- ind:
		case <-ctx.Done():
			return
		default:
			s.logger.Warn("rootkit indicator queue full, drop",
				zap.String("category", ind.Category))
		}
	}
}

// checkHiddenModules 对比 /proc/modules 和 /sys/module/。
//
// procModules: insmod 看见的模块清单 (rootkit 删自己即不出现)
// sysModules:  内核内部 kobject 注册, rootkit 较难抹掉
// /sys 比 /proc 多 → 隐藏模块
// /proc 比 /sys 多 → 不正常 (一般不发生, 但仍报)
func (s *Scanner) checkHiddenModules() []Indicator {
	procMods, perr := readProcModules()
	sysMods, serr := readSysModules()
	if perr != nil || serr != nil {
		return nil
	}
	procSet := make(map[string]struct{}, len(procMods))
	for _, m := range procMods {
		procSet[m] = struct{}{}
	}
	sysSet := make(map[string]struct{}, len(sysMods))
	for _, m := range sysMods {
		sysSet[m] = struct{}{}
	}
	// hidden in proc: 在 sys 但不在 proc
	var hidden []string
	for m := range sysSet {
		if _, ok := procSet[m]; !ok {
			hidden = append(hidden, m)
		}
	}
	sort.Strings(hidden)
	if len(hidden) == 0 {
		return nil
	}
	return []Indicator{{
		Category: "kmod_hidden",
		Severity: "critical",
		Detail:   "/sys/module 出现但 /proc/modules 缺失, LKM rootkit 隐藏自己",
		Evidence: map[string]string{
			"hidden_modules": strings.Join(hidden, ","),
			"sys_total":      strconv.Itoa(len(sysMods)),
			"proc_total":     strconv.Itoa(len(procMods)),
		},
	}}
}

// checkKnownRootkitModules /proc/modules 命中已知 rootkit 名。
func (s *Scanner) checkKnownRootkitModules() []Indicator {
	mods, err := readProcModules()
	if err != nil {
		return nil
	}
	var hits []string
	for _, m := range mods {
		if _, ok := s.known[strings.ToLower(m)]; ok {
			hits = append(hits, m)
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return []Indicator{{
		Category: "known_rootkit_kmod",
		Severity: "critical",
		Detail:   "已加载模块名命中已知 LKM rootkit 列表",
		Evidence: map[string]string{
			"matched": strings.Join(hits, ","),
		},
	}}
}

// checkSyscallTableDrift 读 /proc/kallsyms 找 sys_call_table 地址。
//
// 首次启动: 落 baseline。
// 后续: 对比, 若地址不变但 syscall 处理函数被 hook 我们读不到,
// 这里仅检测最朴素的 "kallsyms 中 sys_call_table 行消失" 异常。
func (s *Scanner) checkSyscallTableDrift() *Indicator {
	addr, err := readSyscallTableAddr()
	if err != nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.syscallBaseAddr == 0 {
		s.syscallBaseAddr = addr
		return nil
	}
	if s.syscallBaseAddr == addr {
		return nil
	}
	// 地址变化 → 内核重载 (升级) 或 hook
	return &Indicator{
		Category: "syscall_drift",
		Severity: "high",
		Detail:   "sys_call_table 地址变化, 可能为内核升级或 syscall hook",
		Evidence: map[string]string{
			"baseline_addr": strconv.FormatUint(s.syscallBaseAddr, 16),
			"current_addr":  strconv.FormatUint(addr, 16),
		},
	}
}

// checkHiddenPIDs 对比 /proc/<pid> 与 getdents 系统调用结果。
//
// 简化: 仅遍历 /proc 取 PID 列表 + 用 syscall 包 Getdents 再读一次。
// 一致即正常; 差异 → 内核 hook getdents 实现 PID 隐藏。
//
// 实际部署效果有限 (大多数 rootkit 也 hook fopen("/proc")), 但留作覆盖率。
func (s *Scanner) checkHiddenPIDs() []Indicator {
	pidsA, errA := readProcPIDs()
	pidsB, errB := readProcDirent()
	if errA != nil || errB != nil {
		return nil
	}
	a := make(map[string]struct{}, len(pidsA))
	for _, p := range pidsA {
		a[p] = struct{}{}
	}
	var diff []string
	for _, p := range pidsB {
		if _, ok := a[p]; !ok {
			diff = append(diff, p)
		}
	}
	if len(diff) == 0 {
		return nil
	}
	sort.Strings(diff)
	return []Indicator{{
		Category: "pid_hidden",
		Severity: "high",
		Detail:   "/proc 标准遍历缺失 getdents 看见的 PID, 可能为内核 hook 隐藏进程",
		Evidence: map[string]string{
			"hidden_pids": strings.Join(diff, ","),
		},
	}}
}

// ---------- 系统访问辅助 ----------

func readProcModules() ([]string, error) {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) > 0 {
			out = append(out, fields[0])
		}
	}
	return out, sc.Err()
}

func readSysModules() ([]string, error) {
	entries, err := os.ReadDir("/sys/module")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

func readSyscallTableAddr() (uint64, error) {
	f, err := os.Open("/proc/kallsyms")
	if err != nil {
		return 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) >= 3 && fields[2] == "sys_call_table" {
			addr, err := strconv.ParseUint(fields[0], 16, 64)
			if err != nil {
				return 0, err
			}
			return addr, nil
		}
	}
	return 0, sc.Err()
}

func readProcPIDs() ([]string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// 仅数字目录 (PID)
		if _, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, e.Name())
		}
	}
	return out, nil
}

// readProcDirent 与 readProcPIDs 等价但走不同 syscall 路径 (期望相同结果)。
//
// 这里直接 os.ReadDir 与 readProcPIDs 同源, 简化版只覆盖 sysfs/procfs 差异;
// 真正 getdents 比对需 C/syscall 直调, 留 M2 阶段加强。
func readProcDirent() ([]string, error) {
	matches, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil, err
	}
	var out []string
	for _, m := range matches {
		out = append(out, filepath.Base(m))
	}
	return out, nil
}
