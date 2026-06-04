package handlers

import (
	"context"
	"encoding/json"
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

// package.json 大小上限 5MB
const nodeMaxFileSize = 5 * 1024 * 1024

// 沿父目录上溯找 node_modules 的最大层数（防文件系统根方向遍历过头）
const nodeAncestorLookupMaxDepth = 10

// rpm -qf / dpkg -S 批量查询超时（与 python 一致）
const nodeOSPkgQueryTimeout = 5 * time.Second

// 单批 OS 包归属查询路径数
const nodeOSPkgBatchSize = 200

// NodePackagesHandler 扫描"运行中 Node 进程"实际可见的 npm 包
//
// 设计原则（P0-5）：
//   - CWPP 扫"运行的东西"。无 node 进程在跑 → 不扫（避免全局 node_modules
//     残留 + 老项目目录里的 node_modules 漏报为运行资产）。
//   - 仅扫每个运行 node 进程实际使用的 node_modules 树。Node 模块解析规则是
//     从入口脚本所在目录向父目录每层查 node_modules，本采集器复刻该规则。
//   - 排除被 rpm/dpkg 拥有的 package.json 路径（如某些 RHEL 自带 node-* RPM）。
//
// 解决的实测误报（G02-UAT 3 台）：
//   - 主机无 node 进程，旧版报 135 个虚假 npm 包（多为开发目录 node_modules 残留）
//   - 服务器只装了 nvm 但没 node 应用在跑 → 旧版扫 /home/*/.nvm/lib 全局包误报
type NodePackagesHandler struct {
	Logger *zap.Logger
}

// nodeProc 单个运行中的 node 进程及其 node_modules 候选根目录
type nodeProc struct {
	pid          int
	binary       string   // exe 实际路径
	moduleRoots  []string // 从入口脚本/cwd 上溯找到的 node_modules 路径列表
	relatedScope string   // 关联进程描述（首个入口脚本路径，便于日志/排查）
}

// Collect 实现 engine.Handler 接口
func (h *NodePackagesHandler) Collect(ctx context.Context) ([]interface{}, error) {
	procs := findRunningNodeProcs(h.Logger)
	if len(procs) == 0 {
		h.Logger.Debug("node_packages: no running node process, skip")
		return nil, nil
	}

	// 1. 汇总所有 node_modules 根目录（按 path 去重，记录关联 pid）
	rootToPID := make(map[string]int)
	for _, p := range procs {
		for _, root := range p.moduleRoots {
			if _, ok := rootToPID[root]; ok {
				continue
			}
			rootToPID[root] = p.pid
		}
	}
	if len(rootToPID) == 0 {
		h.Logger.Debug("node_packages: 0 node_modules root identified, skip",
			zap.Int("procs", len(procs)))
		return nil, nil
	}

	// 2. 枚举每个 node_modules 下一级 package.json
	type pkgCandidate struct {
		pkgJSONPath string
		pid         int
	}
	var candidates []pkgCandidate
	for root, pid := range rootToPID {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, e := range entries {
			n := e.Name()
			if !e.IsDir() {
				continue
			}
			// 跳过 .bin / .cache / 隐藏目录
			if strings.HasPrefix(n, ".") {
				continue
			}
			// scope 目录（@org）：再下一级才是真实包
			if strings.HasPrefix(n, "@") {
				scopeDir := filepath.Join(root, n)
				scopeEntries, err := os.ReadDir(scopeDir)
				if err != nil {
					continue
				}
				for _, se := range scopeEntries {
					if !se.IsDir() {
						continue
					}
					candidates = append(candidates, pkgCandidate{
						pkgJSONPath: filepath.Join(scopeDir, se.Name(), "package.json"),
						pid:         pid,
					})
				}
				continue
			}
			candidates = append(candidates, pkgCandidate{
				pkgJSONPath: filepath.Join(root, n, "package.json"),
				pid:         pid,
			})
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}

	// 3. 批量 OS 包归属查询，被 rpm/dpkg 拥有的 package.json 跳过
	pathsToQuery := make([]string, 0, len(candidates))
	for _, c := range candidates {
		pathsToQuery = append(pathsToQuery, c.pkgJSONPath)
	}
	owned := queryOSOwnedPathsNode(ctx, pathsToQuery, h.Logger)

	// 4. 解析 + 输出
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

		if _, isOwned := owned[c.pkgJSONPath]; isOwned {
			skipped++
			continue
		}

		pkg, ok := parseNodePackageJSON(c.pkgJSONPath)
		if !ok {
			continue
		}

		name, _ := pkg["name"].(string)
		ver, _ := pkg["version"].(string)
		key := name + "@" + ver
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}

		pkg["scope"] = "system"
		pkg["source_handler"] = "node"
		pkg["host_process_pid"] = c.pid
		results = append(results, pkg)
	}

	h.Logger.Info("node_packages 扫描完成",
		zap.Int("procs", len(procs)),
		zap.Int("module_roots", len(rootToPID)),
		zap.Int("candidates", len(candidates)),
		zap.Int("os_owned_skipped", skipped),
		zap.Int("reported", len(results)))

	return results, nil
}

// findRunningNodeProcs 扫 /proc/*/exe 找 node binary，并对每个进程推断 node_modules 根。
//
// Node module resolution 规则：从入口脚本所在目录或当前工作目录起，逐层向父目录查找
// node_modules，找到的全部都算（一个进程可能加载多个层级的 node_modules）。
//
// 入口脚本来源：
//   - /proc/{pid}/cmdline 第二个 argv（`node app.js` 形式）
//   - 失败时 fallback 到 /proc/{pid}/cwd
//
// 已知漏报：
//   - bundle.js / webpack 打包后启动方式（运行时无 node_modules 引用）→ 无法识别原始包；
//     这是结构性限制，业界（包括 Wazuh）均无解。CWPP 主机侧不强制覆盖该场景，容器
//     镜像扫场景下由 image scan 兜底。
func findRunningNodeProcs(logger *zap.Logger) []nodeProc {
	if _, err := os.Stat("/proc"); err != nil {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		logger.Debug("read /proc failed", zap.Error(err))
		return nil
	}

	var out []nodeProc
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		exeLink := "/proc/" + e.Name() + "/exe"
		realPath, err := os.Readlink(exeLink)
		if err != nil {
			continue
		}
		if strings.HasSuffix(realPath, " (deleted)") {
			continue
		}
		realPath = stripProcRootForNode(realPath)
		if realPath == "" || !filepath.IsAbs(realPath) {
			continue
		}

		base := strings.ToLower(filepath.Base(realPath))
		if !isNodeBinary(base) {
			continue
		}

		// 找入口脚本目录（cmdline argv[1]）；失败 fallback 到 cwd
		entryDir, entryHint := nodeEntryDir(pid)
		if entryDir == "" {
			continue
		}

		roots := findAncestorNodeModules(entryDir)
		if len(roots) == 0 {
			// 入口附近无 node_modules，可能是 webpack 打包后启动 → 无法采集
			continue
		}

		out = append(out, nodeProc{
			pid:          pid,
			binary:       realPath,
			moduleRoots:  roots,
			relatedScope: entryHint,
		})
	}

	return out
}

// isNodeBinary basename 匹配 node 解释器（node / nodejs）
//
// 不覆盖 npm/yarn/pnpm 等 CLI（它们 spawn 子进程跑 node，会被独立采到）。
func isNodeBinary(base string) bool {
	return base == "node" || base == "nodejs"
}

// nodeEntryDir 推断 node 进程的入口脚本目录
//
// 优先策略：
//  1. /proc/{pid}/cmdline 找第一个非 flag 的 argv（跳过 -e/-r/--inspect 等），把它作为入口脚本路径
//  2. 上述失败 → /proc/{pid}/cwd 作为兜底
//
// 返回 (dir, hint)：dir 为搜索起点，hint 给日志用（首选入口路径或 cwd）。
func nodeEntryDir(pid int) (string, string) {
	cmdlineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err == nil && len(cmdlineBytes) > 0 {
		// argv 以 \0 分隔
		argv := strings.Split(strings.TrimRight(string(cmdlineBytes), "\x00"), "\x00")
		// 跳过 argv[0] (node 本体)，找第一个看起来像脚本的 argv
		for i := 1; i < len(argv); i++ {
			a := argv[i]
			if a == "" {
				continue
			}
			// node 常见 flag，逐个跳过
			if strings.HasPrefix(a, "-") {
				continue
			}
			// 取绝对/相对路径都行；相对路径以 cwd 解析
			scriptPath := a
			if !filepath.IsAbs(scriptPath) {
				cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
				if err == nil {
					scriptPath = filepath.Join(cwd, scriptPath)
				}
			}
			if info, err := os.Stat(scriptPath); err == nil && !info.IsDir() {
				return filepath.Dir(scriptPath), scriptPath
			}
		}
	}

	// fallback：cwd
	cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	if err != nil {
		return "", ""
	}
	cwd = stripProcRootForNode(cwd)
	if cwd == "" || !filepath.IsAbs(cwd) {
		return "", ""
	}
	if info, err := os.Stat(cwd); err != nil || !info.IsDir() {
		return "", ""
	}
	return cwd, cwd + " (cwd)"
}

// findAncestorNodeModules 从 startDir 沿父目录向上查找 node_modules
//
// 复刻 Node 模块解析规则：每层都看，全部存在的都纳入扫描列表。
// 限制：
//   - 最多上溯 nodeAncestorLookupMaxDepth 层（防遍历到 / 浪费 IO）
//   - 跳过 startDir 本身就是 node_modules 内部的情况（避免扫到嵌套 node_modules
//     里的 vendor 目录 — node 通常不会从那里启动）
func findAncestorNodeModules(startDir string) []string {
	if startDir == "" || !filepath.IsAbs(startDir) {
		return nil
	}
	// 如果 startDir 本身含 node_modules，先 trim 到 node_modules 父目录
	dir := startDir
	if idx := strings.Index(dir, "/node_modules/"); idx >= 0 {
		dir = dir[:idx]
	}

	var roots []string
	for i := 0; i < nodeAncestorLookupMaxDepth; i++ {
		candidate := filepath.Join(dir, "node_modules")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			roots = append(roots, candidate)
		}
		parent := filepath.Dir(dir)
		if parent == dir || parent == "/" {
			break
		}
		dir = parent
	}
	return roots
}

// stripProcRootForNode 去 /proc/{pid}/root/ 前缀（独立私有实现，避免与其他 handler 重名冲突）
func stripProcRootForNode(p string) string {
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

// queryOSOwnedPathsNode 批量查 package.json 是否属于 rpm/dpkg 管的包
//
// 实现与 python_packages 的 queryOSOwnedPaths 等价，独立函数避免跨 handler 耦合
// （等所有 P0 合并后再统一抽公共）。
func queryOSOwnedPathsNode(ctx context.Context, paths []string, logger *zap.Logger) map[string]struct{} {
	owned := make(map[string]struct{})
	if len(paths) == 0 {
		return owned
	}
	if _, err := exec.LookPath("rpm"); err == nil {
		queryRPMOwnershipNode(ctx, paths, owned, logger)
		return owned
	}
	if _, err := exec.LookPath("dpkg"); err == nil {
		queryDpkgOwnershipNode(ctx, paths, owned, logger)
		return owned
	}
	logger.Debug("node_packages: neither rpm nor dpkg available, skip OS-owned dedup")
	return owned
}

func queryRPMOwnershipNode(ctx context.Context, paths []string, owned map[string]struct{}, logger *zap.Logger) {
	for i := 0; i < len(paths); i += nodeOSPkgBatchSize {
		end := i + nodeOSPkgBatchSize
		if end > len(paths) {
			end = len(paths)
		}
		batch := paths[i:end]
		cctx, cancel := context.WithTimeout(ctx, nodeOSPkgQueryTimeout)
		args := append([]string{"-qf", "--qf", "%{NAME}\n"}, batch...)
		out, _ := exec.CommandContext(cctx, "rpm", args...).Output()
		cancel()

		lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
		for j, line := range lines {
			if j >= len(batch) {
				break
			}
			ln := strings.TrimSpace(line)
			if ln == "" {
				continue
			}
			if strings.HasPrefix(ln, "error:") || strings.Contains(ln, "is not owned") || strings.Contains(ln, "No such") {
				continue
			}
			owned[batch[j]] = struct{}{}
		}
	}
	logger.Debug("node_packages: rpm ownership query done",
		zap.Int("paths", len(paths)), zap.Int("owned", len(owned)))
}

func queryDpkgOwnershipNode(ctx context.Context, paths []string, owned map[string]struct{}, logger *zap.Logger) {
	for i := 0; i < len(paths); i += nodeOSPkgBatchSize {
		end := i + nodeOSPkgBatchSize
		if end > len(paths) {
			end = len(paths)
		}
		batch := paths[i:end]
		cctx, cancel := context.WithTimeout(ctx, nodeOSPkgQueryTimeout)
		args := append([]string{"-S"}, batch...)
		out, _ := exec.CommandContext(cctx, "dpkg", args...).Output()
		cancel()

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
	logger.Debug("node_packages: dpkg ownership query done",
		zap.Int("paths", len(paths)), zap.Int("owned", len(owned)))
}

// parseNodePackageJSON 解析 package.json 拿 name / version
//
// 输出 map 不含 scope / source_handler / host_process_pid —— 由 Collect 主流程附加。
func parseNodePackageJSON(pjPath string) (map[string]interface{}, bool) {
	info, err := os.Stat(pjPath)
	if err != nil || info.IsDir() {
		return nil, false
	}
	if info.Size() <= 0 || info.Size() > nodeMaxFileSize {
		return nil, false
	}

	raw, err := os.ReadFile(pjPath)
	if err != nil {
		return nil, false
	}

	var meta struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(raw, &meta); err != nil {
		return nil, false
	}
	if meta.Name == "" || meta.Version == "" {
		return nil, false
	}

	return map[string]interface{}{
		"name":         meta.Name,
		"version":      meta.Version,
		"collected_at": time.Now().Format(time.RFC3339),
		"package_type": "npm",
		"ecosystem":    "npm",
		"purl":         buildNPMPURL(meta.Name, meta.Version),
		"source_file":  pjPath,
	}, true
}

// buildNPMPURL 生成 npm 包 PURL，保留 @scope/name 语义
// 规范：pkg:npm/{namespace}/{name}@{version} 或 pkg:npm/{name}@{version}
func buildNPMPURL(name, version string) string {
	if strings.HasPrefix(name, "@") {
		// @scope/pkg → namespace=@scope, name=pkg
		slash := strings.Index(name, "/")
		if slash > 0 {
			scope := name[:slash]
			pkg := name[slash+1:]
			return fmt.Sprintf("pkg:npm/%s/%s@%s",
				url.PathEscape(scope),
				url.PathEscape(pkg),
				url.PathEscape(version))
		}
	}
	return fmt.Sprintf("pkg:npm/%s@%s", url.PathEscape(name), url.PathEscape(version))
}
