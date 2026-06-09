//go:build linux

// Anti-LD_PRELOAD 检测 (P3-13).
//
// LD_PRELOAD 库注入是用户态 rootkit 常见技术 (libprocesshider/cymothoa 等).
//
// 检测维度:
//
//  1. /etc/ld.so.preload 文件存在 + 非空 (持久化 LD_PRELOAD)
//  2. Agent 自身 /proc/self/maps 含未知 .so 库注入
//  3. /proc/<pid>/environ LD_PRELOAD 变量异常
//  4. 已知 rootkit .so 名命中 (libprocesshider.so / libzaclr.so / ...)
//
// 命中策略:
//   - Agent 自身被注入 → critical + 触发 self-terminate (systemd 拉新进程)
//   - 其他进程被注入 → high 告警上报
package antidebug

import (
	"bufio"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"go.uber.org/zap"
)

// KnownInjectionLibs 已知 LD_PRELOAD rootkit/工具的 .so 名片单.
var KnownInjectionLibs = []string{
	"libprocesshider.so",
	"libzaclr.so",
	"libzeus.so",
	"libcymothoa.so",
	"libdcrypt.so",
	"libmedusa.so",
	"libsetuid.so",
	"libcrowbar.so",
	"libreptile.so",
	"libdelete_module.so",
	"libntwgw.so",
	"libxhfs.so",
}

// LDPreloadIndicator 单个检测指标.
type LDPreloadIndicator struct {
	Category string // ld_so_preload / proc_maps_injection / environ_inject / known_lib
	Severity string // critical / high / medium
	Detail   string
	Evidence map[string]string
}

// LDPreloadScanner Anti-LD_PRELOAD 扫描器.
type LDPreloadScanner struct {
	logger *zap.Logger
	// 白名单: 系统 .so 路径前缀 (排除误报)
	whitelistPrefixes []string
	// 已知坏库名 (lowercase)
	knownBadLibs map[string]struct{}
}

// NewLDPreloadScanner 构造.
func NewLDPreloadScanner(logger *zap.Logger) *LDPreloadScanner {
	if logger == nil {
		logger = zap.NewNop()
	}
	s := &LDPreloadScanner{
		logger: logger,
		whitelistPrefixes: []string{
			"/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/", "/usr/local/lib/",
			"/usr/local/lib64/", "/opt/mxsec/", "/proc/", "/dev/shm/mxsec_",
		},
		knownBadLibs: make(map[string]struct{}, len(KnownInjectionLibs)),
	}
	for _, n := range KnownInjectionLibs {
		s.knownBadLibs[strings.ToLower(n)] = struct{}{}
	}
	return s
}

// ScanSelf 检测 Agent 自身是否被 LD_PRELOAD 注入.
//
// 命中 → 严重事件; 调用方应触发 self-terminate + systemd 拉新进程.
func (s *LDPreloadScanner) ScanSelf() []LDPreloadIndicator {
	var out []LDPreloadIndicator

	// 1. /etc/ld.so.preload 文件检查
	if data, err := os.ReadFile("/etc/ld.so.preload"); err == nil {
		content := strings.TrimSpace(string(data))
		if content != "" {
			out = append(out, LDPreloadIndicator{
				Category: "ld_so_preload",
				Severity: "critical",
				Detail:   "/etc/ld.so.preload 非空 (全局 LD_PRELOAD 持久化)",
				Evidence: map[string]string{"content": content},
			})
		}
	}

	// 2. 自身 /proc/self/environ
	if envInd := s.checkEnviron("/proc/self/environ"); envInd != nil {
		out = append(out, *envInd)
	}

	// 3. /proc/self/maps 异常 .so
	if mapsInd := s.checkProcMaps("/proc/self/maps"); mapsInd != nil {
		out = append(out, *mapsInd)
	}

	return out
}

// ScanPID 检测指定 PID 是否被注入 (用于 Agent 主动巡检其他进程).
func (s *LDPreloadScanner) ScanPID(pid int) []LDPreloadIndicator {
	var out []LDPreloadIndicator
	envPath := filepath.Join("/proc", itoaStr(pid), "environ")
	if ind := s.checkEnviron(envPath); ind != nil {
		out = append(out, *ind)
	}
	mapsPath := filepath.Join("/proc", itoaStr(pid), "maps")
	if ind := s.checkProcMaps(mapsPath); ind != nil {
		out = append(out, *ind)
	}
	return out
}

// checkEnviron 解析 environ NUL-separated 找 LD_PRELOAD=.
func (s *LDPreloadScanner) checkEnviron(path string) *LDPreloadIndicator {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 64*1024))
	if err != nil {
		return nil
	}
	for _, part := range strings.Split(string(data), "\x00") {
		if !strings.HasPrefix(part, "LD_PRELOAD=") {
			continue
		}
		val := strings.TrimPrefix(part, "LD_PRELOAD=")
		val = strings.TrimSpace(val)
		if val == "" {
			continue
		}
		return &LDPreloadIndicator{
			Category: "environ_inject",
			Severity: "high",
			Detail:   "进程 LD_PRELOAD 环境变量非空",
			Evidence: map[string]string{
				"LD_PRELOAD": val,
				"path":       path,
			},
		}
	}
	return nil
}

// checkProcMaps 扫 /proc/<pid>/maps 找可执行 .so 不在白名单的.
func (s *LDPreloadScanner) checkProcMaps(path string) *LDPreloadIndicator {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var unknownLibs []string
	var knownBad []string
	sc := bufio.NewScanner(f)
	seen := make(map[string]struct{})
	for sc.Scan() {
		line := sc.Text()
		// 取行末路径
		idx := strings.LastIndex(line, " /")
		if idx < 0 {
			continue
		}
		soPath := line[idx+1:]
		if !strings.HasSuffix(soPath, ".so") &&
			!strings.Contains(soPath, ".so.") {
			continue
		}
		if _, ok := seen[soPath]; ok {
			continue
		}
		seen[soPath] = struct{}{}
		// 已知坏名命中
		base := filepath.Base(soPath)
		if _, hit := s.knownBadLibs[strings.ToLower(base)]; hit {
			knownBad = append(knownBad, soPath)
			continue
		}
		// 白名单前缀
		if s.isWhitelisted(soPath) {
			continue
		}
		// 非系统路径 + .so → 可疑
		if !strings.HasPrefix(soPath, "/usr/") &&
			!strings.HasPrefix(soPath, "/lib") &&
			!strings.HasPrefix(soPath, "/opt/mxsec/") {
			unknownLibs = append(unknownLibs, soPath)
		}
	}
	if len(knownBad) > 0 {
		return &LDPreloadIndicator{
			Category: "known_lib",
			Severity: "critical",
			Detail:   "已知 LD_PRELOAD rootkit 库命中",
			Evidence: map[string]string{
				"libraries": strings.Join(knownBad, ","),
				"path":      path,
			},
		}
	}
	if len(unknownLibs) > 0 {
		return &LDPreloadIndicator{
			Category: "proc_maps_injection",
			Severity: "high",
			Detail:   "进程加载的 .so 库不在系统路径 + 不在白名单",
			Evidence: map[string]string{
				"libraries": strings.Join(unknownLibs, ","),
				"path":      path,
			},
		}
	}
	return nil
}

func (s *LDPreloadScanner) isWhitelisted(path string) bool {
	for _, p := range s.whitelistPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// itoaStr int → string 不引 strconv.
func itoaStr(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [12]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

var _ = errors.New
