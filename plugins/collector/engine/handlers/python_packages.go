package handlers

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// METADATA 文件大小上限 5MB
const pythonMaxFileSize = 5 * 1024 * 1024

// Python interpreter 探取 sys.path 的执行超时
const pythonSysPathTimeout = 3 * time.Second

// rpm -qf / dpkg -S 批量查询超时
const pythonOSPkgQueryTimeout = 5 * time.Second

// 单批 rpm -qf 路径数（防 ARG_MAX）
const pythonOSPkgBatchSize = 200

// PythonPackagesHandler 扫描"运行中 Python 进程"实际可见的 pip 包
//
// 设计原则（P0-4）：
//   - CWPP 扫"运行的东西"。无 Python 进程在跑 → 不扫（避免装了 venv 但不用的 dist-info 残留误报）。
//   - 仅扫每个运行 interpreter 的 sys.path 目录（其真实可 import 的包路径）。
//   - 排除被 rpm/dpkg "拥有"的 dist-info（如 RHEL 自带的 python3-* RPM 包），让 software handler
//     按 OS 包语义出 CVE，避免双重上报与 OS-pkg 维度漏洞误归类到 pip。
//
// 解决的实测误报（G02-UAT 3 台）：
//   - 主机无 Python 应用进程但 site-packages 残留 dist-info → 旧版误报 1485 个虚假 pip 包
//   - python3-libslirp RPM 装的 site-packages 元数据 → 同时被旧版 python_packages 当作 pip 上报，
//     OSV PURL pkg:pypi/libslirp 匹配不存在的 PyPI 包导致漏洞误报
type PythonPackagesHandler struct {
	Logger *zap.Logger
}

// pythonProc 单个运行中的 Python 进程
type pythonProc struct {
	pid    int
	binary string // exe 实际路径
}

// Collect 实现 engine.Handler 接口
func (h *PythonPackagesHandler) Collect(ctx context.Context) ([]interface{}, error) {
	// 1. 找出运行中的 Python 进程（按 binary 去重，同 interpreter 多实例只跑一次 sys.path）
	procs := findRunningPythonProcs(h.Logger)
	if len(procs) == 0 {
		h.Logger.Debug("python_packages: no running python interpreter, skip")
		return nil, nil
	}

	// 2. 对每个唯一 interpreter binary 拿 sys.path
	type interpInfo struct {
		anyPID  int
		sysPath []string
	}
	interps := make(map[string]*interpInfo) // binary → info
	for _, p := range procs {
		if _, ok := interps[p.binary]; ok {
			continue // 同 binary 不重复 exec
		}
		paths := getSysPath(ctx, p.binary)
		if len(paths) == 0 {
			h.Logger.Debug("python_packages: sys.path empty, skip",
				zap.String("binary", p.binary), zap.Int("pid", p.pid))
			continue
		}
		interps[p.binary] = &interpInfo{anyPID: p.pid, sysPath: paths}
	}

	if len(interps) == 0 {
		h.Logger.Debug("python_packages: 0 interpreter yielded sys.path, skip")
		return nil, nil
	}

	// 3. 汇总所有需要扫的 site-packages 目录
	//    siteDir → 来源 pid (取首个，作为关联 pid)
	siteDirs := make(map[string]int)
	for bin, info := range interps {
		for _, p := range info.sysPath {
			if !isValidSysPathDir(p) {
				continue
			}
			if _, ok := siteDirs[p]; !ok {
				siteDirs[p] = info.anyPID
			}
		}
		_ = bin
	}
	if len(siteDirs) == 0 {
		return nil, nil
	}

	// 4. 一次性枚举所有 dist-info 候选 + 收集路径列表用于批量查 OS 包归属
	type distInfoCandidate struct {
		path string // dist-info / egg-info 目录绝对路径
		pid  int    // 关联运行进程 PID
	}
	var candidates []distInfoCandidate
	for dir, pid := range siteDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			n := e.Name()
			if !strings.HasSuffix(n, ".dist-info") && !strings.HasSuffix(n, ".egg-info") {
				continue
			}
			candidates = append(candidates, distInfoCandidate{
				path: filepath.Join(dir, n),
				pid:  pid,
			})
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	// 5. 批量查 OS 包归属（owned dist-info 全部跳过，避免与 rpm/dpkg handler 重复）
	pathsToQuery := make([]string, 0, len(candidates))
	for _, c := range candidates {
		pathsToQuery = append(pathsToQuery, c.path)
	}
	owned := queryOSOwnedPaths(ctx, pathsToQuery, h.Logger)

	// 6. 解析 + 输出
	var (
		results []interface{}
		seen    = make(map[string]struct{}) // name@version 去重
		skipped = 0
	)
	for _, c := range candidates {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		if _, isOwned := owned[c.path]; isOwned {
			skipped++
			continue
		}

		pkg, ok := parsePythonDistInfo(c.path)
		if !ok {
			continue
		}

		nameStr, _ := pkg["name"].(string)
		verStr, _ := pkg["version"].(string)
		key := nameStr + "@" + verStr
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		pkg["scope"] = "system"
		pkg["source_handler"] = "python"
		pkg["host_process_pid"] = c.pid
		results = append(results, pkg)
	}

	h.Logger.Info("python_packages 扫描完成",
		zap.Int("interpreters", len(interps)),
		zap.Int("site_dirs", len(siteDirs)),
		zap.Int("candidates", len(candidates)),
		zap.Int("os_owned_skipped", skipped),
		zap.Int("reported", len(results)))

	return results, nil
}

// findRunningPythonProcs 扫 /proc/*/exe 找含 "python" 的 exe（去重 binary 路径）。
// 返回值：每个 binary 至少有 1 个 pid，多实例只保留首个 pid（用于关联）。
func findRunningPythonProcs(logger *zap.Logger) []pythonProc {
	if _, err := os.Stat("/proc"); err != nil {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		logger.Debug("read /proc failed", zap.Error(err))
		return nil
	}

	seen := make(map[string]int) // binary → first pid
	var out []pythonProc

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// PID 目录名必为数字
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		realPath, err := os.Readlink("/proc/" + e.Name() + "/exe")
		if err != nil {
			continue
		}
		if strings.HasSuffix(realPath, " (deleted)") {
			continue
		}
		realPath = stripProcRoot(realPath)
		if realPath == "" || !filepath.IsAbs(realPath) {
			continue
		}

		// Python interpreter basename 匹配：python / python3 / python3.x / pypy / pypy3 / uwsgi (内嵌 python)
		base := strings.ToLower(filepath.Base(realPath))
		if !isPythonBinary(base) {
			continue
		}

		if _, dup := seen[realPath]; dup {
			continue
		}
		seen[realPath] = pid
		out = append(out, pythonProc{pid: pid, binary: realPath})
	}

	return out
}

// stripProcRoot 去掉 /proc/{pid}/root/ 前缀（容器内进程的宿主视角）
// "/proc/1234/root/usr/bin/python3" → "/usr/bin/python3"
// 非该前缀直接返回原值。
func stripProcRoot(p string) string {
	if !strings.HasPrefix(p, "/proc/") {
		return p
	}
	rest := p[len("/proc/"):]
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return p
	}
	pidPart := rest[:slash]
	if _, err := strconv.Atoi(pidPart); err != nil {
		return p
	}
	tail := rest[slash+1:]
	if !strings.HasPrefix(tail, "root/") && tail != "root" {
		return p
	}
	stripped := strings.TrimPrefix(tail, "root")
	if stripped == "" {
		return p
	}
	return stripped
}

// isPythonBinary 判定 basename 是否为 Python 解释器
//
// 覆盖：python / python3 / python3.x / python2 / pypy / pypy3。
// 不覆盖：uwsgi、gunicorn 等 wrapper（它们通常 exec 真实 python 解释器，会被独立采集到）。
func isPythonBinary(base string) bool {
	switch {
	case base == "python", base == "python3", base == "python2":
		return true
	case strings.HasPrefix(base, "python3."), strings.HasPrefix(base, "python2."):
		// python3.8 / python3.11 / python2.7 等
		return true
	case base == "pypy", base == "pypy3", strings.HasPrefix(base, "pypy3."):
		return true
	}
	return false
}

// getSysPath 执行 `<pythonBin> -c "import sys; print('\n'.join(sys.path))"` 拿 sys.path。
//
// 失败原因常见：
//   - SELinux/AppArmor 限制 agent 运行任意 binary
//   - python interpreter 启动报错（依赖缺失）
//   - 超时（CPU 饥饿）
//
// 失败返回 nil，调用方静默跳过该 interpreter。
func getSysPath(ctx context.Context, pythonBin string) []string {
	cctx, cancel := context.WithTimeout(ctx, pythonSysPathTimeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, pythonBin, "-c", "import sys\nfor p in sys.path: print(p)")
	out, err := cmd.Output()
	if err != nil {
		return nil
	}

	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		p := strings.TrimSpace(line)
		if p == "" {
			continue
		}
		paths = append(paths, p)
	}
	return paths
}

// isValidSysPathDir 判定 sys.path 一项是否为可扫的目录
//
// 跳过：空字符串（CWD）、相对路径、zip 文件、不存在的路径。
func isValidSysPathDir(p string) bool {
	if p == "" || !filepath.IsAbs(p) {
		return false
	}
	if strings.HasSuffix(strings.ToLower(p), ".zip") {
		return false
	}
	info, err := os.Stat(p)
	if err != nil || !info.IsDir() {
		return false
	}
	return true
}

// queryOSOwnedPaths 批量查询路径是否属于 rpm/dpkg 管理的包，返回 owned 集合。
//
// 调用 `rpm -qf <paths...>` 或 `dpkg -S <paths>`。出错时返回空集（保守做法：不去重，宁可少量重复也不丢真实 pip 包）。
//
// 行为差异：
//   - rpm -qf：每条输入对应一行，"<path>: file ... is not owned by any package" 表示非 owned
//   - dpkg -S：按 path 反查，未 owned 时 exit code != 0 但 stdout 仍可能为空
func queryOSOwnedPaths(ctx context.Context, paths []string, logger *zap.Logger) map[string]struct{} {
	owned := make(map[string]struct{})
	if len(paths) == 0 {
		return owned
	}

	// 优先尝试 rpm，缺失再 fallback dpkg
	if _, err := exec.LookPath("rpm"); err == nil {
		queryRPMOwnership(ctx, paths, owned, logger)
		return owned
	}
	if _, err := exec.LookPath("dpkg"); err == nil {
		queryDpkgOwnership(ctx, paths, owned, logger)
		return owned
	}
	// 两者皆缺：返回空集，调用方按"全不属于 OS"处理
	logger.Debug("python_packages: neither rpm nor dpkg available, skip OS-owned dedup")
	return owned
}

// queryRPMOwnership 调用 `rpm -qf path1 path2 ...`，分批避免 ARG_MAX。
func queryRPMOwnership(ctx context.Context, paths []string, owned map[string]struct{}, logger *zap.Logger) {
	for i := 0; i < len(paths); i += pythonOSPkgBatchSize {
		end := i + pythonOSPkgBatchSize
		if end > len(paths) {
			end = len(paths)
		}
		batch := paths[i:end]

		cctx, cancel := context.WithTimeout(ctx, pythonOSPkgQueryTimeout)
		args := append([]string{"-qf", "--qf", "%{NAME}\n"}, batch...)
		cmd := exec.CommandContext(cctx, "rpm", args...)
		out, _ := cmd.Output() // 即使有 not owned 也只是 exit code != 0，仍读 stdout
		cancel()

		// rpm -qf 输出行顺序与输入路径一一对应：
		//   owned → 包名（含字符）
		//   not owned → "error: file ... is not owned by any package" 写到 stderr，stdout 该行可能缺失
		// 我们不依赖 stderr，仅按 stdout 行数对齐到 batch 路径
		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		for j, line := range lines {
			if j >= len(batch) {
				break
			}
			ln := strings.TrimSpace(line)
			if ln == "" {
				continue
			}
			// 排除 "is not owned" / "no path" 等 stderr 风格内容（rpm 偶尔混到 stdout）
			if strings.HasPrefix(ln, "error:") || strings.Contains(ln, "is not owned") || strings.Contains(ln, "No such") {
				continue
			}
			owned[batch[j]] = struct{}{}
		}
	}
	logger.Debug("python_packages: rpm ownership query done",
		zap.Int("paths", len(paths)),
		zap.Int("owned", len(owned)))
}

// queryDpkgOwnership 调用 `dpkg -S` 反查。-S 接受多路径但分隔较慢，按 batch 调。
func queryDpkgOwnership(ctx context.Context, paths []string, owned map[string]struct{}, logger *zap.Logger) {
	for i := 0; i < len(paths); i += pythonOSPkgBatchSize {
		end := i + pythonOSPkgBatchSize
		if end > len(paths) {
			end = len(paths)
		}
		batch := paths[i:end]

		cctx, cancel := context.WithTimeout(ctx, pythonOSPkgQueryTimeout)
		args := append([]string{"-S"}, batch...)
		cmd := exec.CommandContext(cctx, "dpkg", args...)
		out, _ := cmd.Output()
		cancel()

		// dpkg -S 输出格式：<pkg>: <path>
		// 未 owned 的 path 不会出现在 stdout
		for _, line := range strings.Split(string(out), "\n") {
			idx := strings.Index(line, ": ")
			if idx <= 0 {
				continue
			}
			pathPart := strings.TrimSpace(line[idx+2:])
			if pathPart == "" {
				continue
			}
			owned[pathPart] = struct{}{}
		}
	}
	logger.Debug("python_packages: dpkg ownership query done",
		zap.Int("paths", len(paths)),
		zap.Int("owned", len(owned)))
}

// parsePythonDistInfo 解析 dist-info / egg-info 目录内的 METADATA / PKG-INFO 文件。
//
// 输出 map 不含 scope / source_handler / host_process_pid —— 这些由 Collect 主流程统一附加，
// 便于复用本函数（如未来 container 内部 Python 包扫描场景）。
func parsePythonDistInfo(distDir string) (map[string]interface{}, bool) {
	candidates := []string{
		filepath.Join(distDir, "METADATA"),
		filepath.Join(distDir, "PKG-INFO"),
	}

	var metaPath string
	var metaInfo os.FileInfo
	for _, p := range candidates {
		info, err := os.Stat(p)
		if err != nil || info.IsDir() {
			continue
		}
		metaPath = p
		metaInfo = info
		break
	}
	if metaPath == "" {
		return nil, false
	}

	if metaInfo.Size() <= 0 || metaInfo.Size() > pythonMaxFileSize {
		return nil, false
	}

	f, err := os.Open(metaPath)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	var name, version string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break // RFC 822 头部以空行结束
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue // 续行忽略
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "Name":
			if name == "" {
				name = val
			}
		case "Version":
			if version == "" {
				version = val
			}
		}
		if name != "" && version != "" {
			break
		}
	}

	if name == "" || version == "" {
		return nil, false
	}

	lowerName := strings.ToLower(name)
	return map[string]interface{}{
		"name":         lowerName,
		"version":      version,
		"collected_at": time.Now().Format(time.RFC3339),
		"package_type": "pip",
		"ecosystem":    "PyPI",
		"purl":         fmt.Sprintf("pkg:pypi/%s@%s", url.PathEscape(lowerName), url.PathEscape(version)),
		"source_file":  distDir,
	}, true
}
