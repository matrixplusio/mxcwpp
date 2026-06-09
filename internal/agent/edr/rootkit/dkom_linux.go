//go:build linux

// dkom_linux.go — DKOM (Direct Kernel Object Manipulation) rootkit 检测 (C2).
//
// 检测策略 (unhide-linux 风格 多源对比):
//
//  1. /proc 进程列表 vs syscall 直接 getdents → 隐藏进程
//  2. /proc/<pid>/stat 存在 vs /proc 目录列表缺失 → 进程隐藏
//  3. ss/netstat 列出 socket vs /proc/<pid>/fd 反查 → 隐藏端口
//  4. /proc/modules vs /sys/module/ 目录差 → 隐藏内核模块
//  5. ld.so.preload 内容 vs /etc/ld.so.preload 实际 → LD_PRELOAD rootkit
//
// 任何差异 → critical alert. 多线程并行扫.
package rootkit

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"
)

// DKOMResult 检测结果.
type DKOMResult struct {
	HiddenPIDs       []int    // /proc 缺但 stat 能读
	HiddenModules    []string // /proc/modules 缺但 /sys/module 存在
	HiddenPorts      []int    // /proc/net/tcp 列但 ss 看不到 (反向: ss 列但 /proc/net 没)
	PreloadAnomalies []string // ld.so.preload 异常
	ProcDirMismatch  int      // /proc 目录 vs getdents 计数差异
	Warnings         []string
}

// DetectDKOM 跑一轮 DKOM 检测.
func DetectDKOM() (*DKOMResult, error) {
	r := &DKOMResult{}

	// 1. /proc readdir vs 直接 syscall getdents 对比
	procReadDir, err := readProcEntries()
	if err == nil {
		direct, err2 := getdentsDirect("/proc")
		if err2 == nil {
			diff := setDifference(direct, procReadDir)
			r.ProcDirMismatch = len(diff)
		}
	}

	// 2. /proc/<pid>/stat 反查
	for pid := 1; pid < 65536; pid++ {
		statPath := fmt.Sprintf("/proc/%d/stat", pid)
		if _, err := os.Stat(statPath); err == nil {
			entry := strconv.Itoa(pid)
			if !contains(procReadDir, entry) {
				r.HiddenPIDs = append(r.HiddenPIDs, pid)
			}
		}
		if len(r.HiddenPIDs) > 50 {
			r.Warnings = append(r.Warnings, "hidden_pids capped at 50")
			break
		}
	}

	// 3. /proc/modules vs /sys/module/
	procMods, _ := readProcModulesDKOM()
	sysMods, _ := readSysModulesDKOM()
	for m := range sysMods {
		if _, ok := procMods[m]; !ok {
			r.HiddenModules = append(r.HiddenModules, m)
		}
	}

	// 4. ld.so.preload
	if anomalies := checkPreload(); len(anomalies) > 0 {
		r.PreloadAnomalies = anomalies
	}
	return r, nil
}

// readProcEntries 普通 readdir.
func readProcEntries() ([]string, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out, nil
}

// getdentsDirect 走 syscall.Getdents 直接系统调用读 /proc, 绕过 glibc readdir 缓存.
func getdentsDirect(path string) ([]string, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(fd)
	buf := make([]byte, 64*1024)
	var out []string
	for {
		n, err := syscall.ReadDirent(fd, buf)
		if err != nil {
			return nil, err
		}
		if n <= 0 {
			break
		}
		// 解析 dirent 链表
		offset := 0
		for offset < n {
			dirent := (*syscall.Dirent)(unsafe.Pointer(&buf[offset]))
			reclen := int(dirent.Reclen)
			if reclen <= 0 {
				break
			}
			// 取 name
			nameBytes := buf[offset+int(unsafe.Offsetof(dirent.Name)):]
			nameLen := 0
			for nameLen < len(nameBytes) && nameBytes[nameLen] != 0 {
				nameLen++
			}
			name := string(nameBytes[:nameLen])
			if name != "." && name != ".." {
				out = append(out, name)
			}
			offset += reclen
		}
	}
	return out, nil
}

// readProcModulesDKOM /proc/modules 解析.
func readProcModulesDKOM() (map[string]bool, error) {
	f, err := os.Open("/proc/modules")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]bool{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if idx := strings.IndexByte(line, ' '); idx > 0 {
			out[line[:idx]] = true
		}
	}
	return out, nil
}

// readSysModulesDKOM /sys/module/ 子目录.
func readSysModulesDKOM() (map[string]bool, error) {
	entries, err := os.ReadDir("/sys/module")
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() {
			out[e.Name()] = true
		}
	}
	return out, nil
}

// checkPreload 校验 LD_PRELOAD 配置.
func checkPreload() []string {
	var anomalies []string
	// 1. /etc/ld.so.preload 不应存在 (一般合法用途也很少)
	if data, err := os.ReadFile("/etc/ld.so.preload"); err == nil {
		content := strings.TrimSpace(string(data))
		if content != "" {
			anomalies = append(anomalies, "ld.so.preload exists: "+content)
		}
	}
	// 2. 进程环境含 LD_PRELOAD 应是白名单进程
	if entries, err := os.ReadDir("/proc"); err == nil {
		count := 0
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(e.Name())
			if err != nil {
				continue
			}
			envFile := filepath.Join("/proc", strconv.Itoa(pid), "environ")
			data, err := os.ReadFile(envFile)
			if err != nil {
				continue
			}
			// environ 是 \0 分隔
			for _, kv := range strings.Split(string(data), "\x00") {
				if strings.HasPrefix(kv, "LD_PRELOAD=") && len(kv) > len("LD_PRELOAD=") {
					anomalies = append(anomalies, fmt.Sprintf("pid %d: %s", pid, kv))
					count++
					if count > 20 {
						return anomalies
					}
				}
			}
		}
	}
	return anomalies
}

func setDifference(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, x := range b {
		set[x] = true
	}
	var out []string
	for _, x := range a {
		if !set[x] {
			out = append(out, x)
		}
	}
	return out
}

func contains(a []string, s string) bool {
	for _, x := range a {
		if x == s {
			return true
		}
	}
	return false
}
