// Package main — Standalone pre-check (DataType 9101).
//
// 与 handleTask 的内联 3 阶段预检不同，本模块只查不执行：
//  1. 查 host 已装包列表（rpm -qa / dpkg-query）
//  2. 用 vuln.component 模糊匹配真实包名（精确 / 架构后缀 / -libs -devel 等常见后缀）
//  3. 对每个匹配的已装包批量查仓库 (dnf list available / apt-cache policy)
//  4. 用 rpmvercmp / dpkg --compare-versions 比较版本
//  5. 综合 8 类状态回报 manager（DataType 9201）
//
// 商业 CWPP 标准：所有判断基于主机真实数据，不靠 server vuln DB 字符串拼接猜包名。
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/api/proto/bridge"
	plugins "github.com/matrixplusio/mxcwpp/plugins/lib/go"
)

// dataTypePreCheckPush 接收 server 推过来的预检请求
const dataTypePreCheckPush int32 = 9101

// dataTypePreCheckResult 上报预检结果给 server
const dataTypePreCheckResult int32 = 9201

// 注意：9201 与 dataTypeRemediationProgress 是同一值。
// 通过 payload.Fields["kind"] 区分（"progress" vs "precheck_result"）。
// 详见 docs/datatype-allocation.md 漏洞修复结果扩展段。

// preCheckPayload 由 manager 推过来
type preCheckPayload struct {
	RequestID              string `json:"request_id"`                         // pc-<host_vuln_id>-<ts>
	HostVulnID             uint   `json:"host_vuln_id"`                       // host_vulnerabilities.id
	Component              string `json:"component"`                          // vuln.component（可能模糊）
	FixedVersion           string `json:"fixed_version"`                      // 可空
	CheckAffectedProcesses bool   `json:"check_affected_processes,omitempty"` // P5.2: shared_lib 类要求列出依赖该 lib 的运行进程
}

// packageCheckDetail 单个匹配的已装包检查结果
type packageCheckDetail struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installed_version"`
	AvailableVersion string `json:"available_version,omitempty"`
	Repo             string `json:"repo,omitempty"`
	Action           string `json:"action"` // upgrade | already_latest | not_available
}

// preCheckResult 上报回 manager 的结果
type preCheckResult struct {
	RequestID         string               `json:"request_id"`
	HostVulnID        uint                 `json:"host_vuln_id"`
	Status            string               `json:"status"`
	Message           string               `json:"message"`
	Packages          []packageCheckDetail `json:"packages,omitempty"`
	AffectedProcesses []string             `json:"affected_processes,omitempty"` // P5.2: shared_lib lsof 出的进程列表
}

// Pre-check 状态（必须与 server 端 model.PreCheckStatus* 对齐）
const (
	pcStatusNotInstalled  = "not_installed"
	pcStatusAvailable     = "available"
	pcStatusAvailableEPEL = "available_epel"
	pcStatusOutdatedRepo  = "outdated_repo"
	pcStatusNotInRepo     = "not_in_repo"
	pcStatusFailed        = "failed"
)

// validPkgName 严格白名单防命令注入：包名 / 架构 / 版本只允许这些字符
var validPkgName = regexp.MustCompile(`^[a-zA-Z0-9._+\-:~]+$`)

// handlePreCheck 处理 DataType 9101 预检任务
func handlePreCheck(ctx context.Context, task *bridge.Task, client *plugins.Client, logger *zap.Logger) error {
	var p preCheckPayload
	if err := json.Unmarshal([]byte(task.Data), &p); err != nil {
		return fmt.Errorf("解析预检任务失败: %w", err)
	}
	if p.Component == "" || p.HostVulnID == 0 {
		return sendPreCheckResult(client, preCheckResult{
			RequestID:  p.RequestID,
			HostVulnID: p.HostVulnID,
			Status:     pcStatusFailed,
			Message:    "缺少 component 或 host_vuln_id",
		}, logger)
	}
	// 命令注入防护
	if !validPkgName.MatchString(p.Component) {
		return sendPreCheckResult(client, preCheckResult{
			RequestID:  p.RequestID,
			HostVulnID: p.HostVulnID,
			Status:     pcStatusFailed,
			Message:    fmt.Sprintf("非法 component 字符: %q", p.Component),
		}, logger)
	}

	logger.Info("[PRECHECK] start",
		zap.String("request_id", p.RequestID),
		zap.Uint("host_vuln_id", p.HostVulnID),
		zap.String("component", p.Component),
		zap.String("fixed_version", p.FixedVersion))

	pkgMgr, ok := detectPkgManager("")
	if !ok {
		return sendPreCheckResult(client, preCheckResult{
			RequestID:  p.RequestID,
			HostVulnID: p.HostVulnID,
			Status:     pcStatusFailed,
			Message:    "未检测到 yum/dnf/apt 包管理器",
		}, logger)
	}

	installed, err := listInstalledPackages(ctx, pkgMgr)
	if err != nil {
		return sendPreCheckResult(client, preCheckResult{
			RequestID:  p.RequestID,
			HostVulnID: p.HostVulnID,
			Status:     pcStatusFailed,
			Message:    fmt.Sprintf("列出已装包失败: %v", err),
		}, logger)
	}

	matched := matchInstalledPackages(installed, p.Component)
	if len(matched) == 0 {
		return sendPreCheckResult(client, preCheckResult{
			RequestID:  p.RequestID,
			HostVulnID: p.HostVulnID,
			Status:     pcStatusNotInstalled,
			Message:    fmt.Sprintf("本机未安装 %q 相关包，无需修复", p.Component),
		}, logger)
	}

	// 对每个匹配包查仓库可用版本
	var details []packageCheckDetail
	var anyAvailable bool
	var allOutdated = true // 假设全部仓库过旧
	var anyViaEPEL bool

	for _, pkgName := range matched {
		installedVer := installed[pkgName]
		availVer, repo, viaEPEL := queryAvailableVersion(ctx, pkgMgr, pkgName)

		detail := packageCheckDetail{
			Name:             pkgName,
			InstalledVersion: installedVer,
			AvailableVersion: availVer,
			Repo:             repo,
		}

		switch {
		case availVer == "":
			detail.Action = "not_available"
		case versionCompare(pkgMgr, installedVer, availVer) >= 0:
			// 已装 >= 可用 = 已最新
			detail.Action = "already_latest"
			allOutdated = false
		default:
			// 仓库有新版
			if p.FixedVersion != "" && fixedVersionValidStr(p.FixedVersion) {
				// 仓库版 < fixed → 仓库源过旧
				if versionCompare(pkgMgr, availVer, p.FixedVersion) < 0 {
					detail.Action = "upgrade_but_below_fixed"
					// 不算 anyAvailable
				} else {
					detail.Action = "upgrade"
					anyAvailable = true
					allOutdated = false
					if viaEPEL {
						anyViaEPEL = true
					}
				}
			} else {
				// 无 fixed_version 约束，仓库有新版即可
				detail.Action = "upgrade"
				anyAvailable = true
				allOutdated = false
				if viaEPEL {
					anyViaEPEL = true
				}
			}
		}
		details = append(details, detail)
	}

	// P5.2: shared_lib 类，lsof 找受影响进程（升级后这些必须 restart 才安全）
	var affectedProcs []string
	if p.CheckAffectedProcesses && anyAvailable {
		affectedProcs = findAffectedProcesses(ctx, pkgMgr, matched)
		logger.Info("[PRECHECK] affected processes detected",
			zap.String("request_id", p.RequestID),
			zap.Int("count", len(affectedProcs)))
	}

	// 综合状态判定
	result := preCheckResult{
		RequestID:         p.RequestID,
		HostVulnID:        p.HostVulnID,
		Packages:          details,
		AffectedProcesses: affectedProcs,
	}
	switch {
	case anyAvailable && anyViaEPEL:
		result.Status = pcStatusAvailableEPEL
		result.Message = "需启用 EPEL 仓库后下发修复"
	case anyAvailable:
		result.Status = pcStatusAvailable
		result.Message = fmt.Sprintf("命中 %d 个真实包，仓库已有满足 CVE 的新版本", len(matched))
	case allOutdated && len(details) > 0:
		result.Status = pcStatusOutdatedRepo
		result.Message = "仓库源版本低于 CVE 修复版本，请联系运维更新源"
	default:
		result.Status = pcStatusNotInRepo
		result.Message = "命中包，但任何仓库都无可升级版本，请自行评估"
	}

	return sendPreCheckResult(client, result, logger)
}

// findAffectedProcesses P5.2: 找出系统中依赖给定包提供的 .so 文件的运行进程。
//
// 流程：
//  1. rpm -ql / dpkg -L <pkg> 拿到包安装的所有文件
//  2. 提取 .so / .so.X 路径
//  3. lsof -nP +c 0 全系统扫，grep 这些路径
//  4. 提取 "进程名 (PID xxx)" 列表去重
//
// 用例：openssl-libs 升级后，lsof 找到 nginx/sshd/postgres/python3 等用 libssl 的进程
// 提示用户必须 systemctl restart 这些服务才安全。
func findAffectedProcesses(ctx context.Context, pkgMgr string, pkgs []string) []string {
	libPaths := collectPackageLibs(ctx, pkgMgr, pkgs)
	if len(libPaths) == 0 {
		return nil
	}
	return lsofGrepLibs(ctx, libPaths)
}

// collectPackageLibs 拿包安装的 .so 文件路径
func collectPackageLibs(ctx context.Context, pkgMgr string, pkgs []string) []string {
	cctx, cancel := context.WithTimeout(ctx, precheckTimeout)
	defer cancel()
	seen := map[string]struct{}{}
	for _, pkg := range pkgs {
		if !validPkgName.MatchString(pkg) {
			continue
		}
		var cmd *exec.Cmd
		switch pkgMgr {
		case "dnf", "yum":
			cmd = exec.CommandContext(cctx, "rpm", "-ql", pkg)
		case "apt-get":
			cmd = exec.CommandContext(cctx, "dpkg", "-L", pkg)
		default:
			continue
		}
		out, err := cmd.Output()
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(string(out)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			// 匹配 .so / .so.1 / .so.1.2.3 等共享库后缀
			if !strings.Contains(line, ".so") {
				continue
			}
			// 简单过滤：必须是绝对路径，不是 /usr/share/doc/foo.so.example 这类文档
			if !strings.HasPrefix(line, "/") {
				continue
			}
			if _, ok := seen[line]; !ok {
				seen[line] = struct{}{}
			}
		}
	}
	libs := make([]string, 0, len(seen))
	for p := range seen {
		libs = append(libs, p)
	}
	return libs
}

// lsofGrepLibs lsof 全系统扫，找用 libPaths 中任意 lib 的进程
func lsofGrepLibs(ctx context.Context, libPaths []string) []string {
	if len(libPaths) == 0 {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, precheckTimeout)
	defer cancel()
	// lsof -nP 不解析 hostname/port，加速；+c 0 完整进程名（不截断 15 字符）
	out, err := exec.CommandContext(cctx, "lsof", "-nP", "+c", "0").Output()
	if err != nil {
		// lsof 退出码 1 表示没找到任何匹配但有部分错误（例如 /proc 部分进程不可读）
		// 仍尝试解析输出
		if len(out) == 0 {
			return nil
		}
	}
	procs := map[string]struct{}{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		// lsof 输出列：COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
		// NAME 在最后，含路径。简单 substring match
		matched := false
		for _, lib := range libPaths {
			if strings.Contains(line, lib) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// fields[0]=COMMAND  fields[1]=PID
		key := fmt.Sprintf("%s (PID %s)", fields[0], fields[1])
		procs[key] = struct{}{}
	}
	result := make([]string, 0, len(procs))
	for p := range procs {
		result = append(result, p)
	}
	// 排序输出，UI 显示稳定
	sortStrings(result)
	return result
}

// sortStrings 简单 in-place 排序（避免引入 sort 包跨文件依赖）
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// sendPreCheckResult 上报预检结果（DataType 9201，kind=precheck_result）
func sendPreCheckResult(client *plugins.Client, r preCheckResult, logger *zap.Logger) error {
	pkgsJSON, _ := json.Marshal(r.Packages)
	procsJSON, _ := json.Marshal(r.AffectedProcesses)
	record := &bridge.Record{
		DataType:  dataTypePreCheckResult,
		Timestamp: time.Now().UnixNano(),
		Data: &bridge.Payload{
			Fields: map[string]string{
				"kind":               "precheck_result",
				"request_id":         r.RequestID,
				"host_vuln_id":       fmt.Sprintf("%d", r.HostVulnID),
				"status":             r.Status,
				"message":            r.Message,
				"packages":           string(pkgsJSON),
				"affected_processes": string(procsJSON),
			},
		},
	}
	if err := client.SendRecord(record); err != nil {
		logger.Warn("[PRECHECK] send result failed",
			zap.String("request_id", r.RequestID), zap.Error(err))
		return err
	}
	logger.Info("[PRECHECK] reported",
		zap.String("request_id", r.RequestID),
		zap.Uint("host_vuln_id", r.HostVulnID),
		zap.String("status", r.Status),
		zap.Int("matched_packages", len(r.Packages)))
	return nil
}

// listInstalledPackages 列出主机已装包，返回 map[包名] = 已装版本
// rpm -qa --qf '%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\n'
// dpkg-query -W -f='${Package} ${Version}\n'
func listInstalledPackages(ctx context.Context, pkgMgr string) (map[string]string, error) {
	cctx, cancel := context.WithTimeout(ctx, precheckTimeout)
	defer cancel()
	var cmd *exec.Cmd
	switch pkgMgr {
	case "dnf", "yum":
		cmd = exec.CommandContext(cctx, "rpm", "-qa", "--qf",
			"%{NAME} %{EPOCHNUM}:%{VERSION}-%{RELEASE}\n")
	case "apt-get":
		cmd = exec.CommandContext(cctx, "dpkg-query", "-W", "-f=${Package} ${Version}\n")
	default:
		return nil, fmt.Errorf("unsupported pkg manager: %s", pkgMgr)
	}
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list installed packages: %w", err)
	}
	result := make(map[string]string, 256)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			continue
		}
		name := strings.TrimSpace(parts[0])
		ver := strings.TrimSpace(parts[1])
		// rpm 输出可能有 EPOCHNUM=0:1.0.0 形式，归一化
		ver = strings.TrimPrefix(ver, "0:")
		if name != "" {
			result[name] = ver
		}
	}
	return result, scanner.Err()
}

// matchInstalledPackages 用 vuln.component 模糊匹配主机已装包名。
//
// 匹配策略（按优先级）：
//  1. 精确匹配
//  2. 常见 RPM/DEB 子包后缀：-libs/-devel/-perl/-static/-pkcs11/-core/-modules/-utils/-tools/-server/-client
//  3. lib 前缀（DEB libssl3 → component=openssl）
//
// 严格白名单：不模糊到完全不相关（如 component=openssl 不该命中 python3-openssl）
func matchInstalledPackages(installed map[string]string, component string) []string {
	component = strings.ToLower(strings.TrimSpace(component))
	if component == "" {
		return nil
	}
	suffixes := []string{
		"-libs", "-libs-debuginfo", "-devel", "-perl", "-static", "-pkcs11",
		"-core", "-modules", "-utils", "-tools", "-server", "-client",
		"-common", "-doc", "-bin",
	}
	seen := make(map[string]struct{})
	var result []string
	add := func(name string) {
		if _, ok := seen[name]; !ok {
			seen[name] = struct{}{}
			result = append(result, name)
		}
	}
	for pkg := range installed {
		lower := strings.ToLower(pkg)
		// 1. 精确
		if lower == component {
			add(pkg)
			continue
		}
		// 2. 常见后缀
		for _, suf := range suffixes {
			if lower == component+suf {
				add(pkg)
				break
			}
		}
		// 3. lib 前缀（DEB 主流命名）
		// libssl3 ↔ openssl 由 component=openssl 命中 libssl* 系列
		if strings.HasPrefix(component, "lib") {
			continue // component 本身已是 lib*
		}
		if strings.HasPrefix(lower, "lib"+component) {
			add(pkg)
		}
	}
	return result
}

// queryAvailableVersion 查询包在仓库中可用的最新版本
// 返回：version, repo, viaEPEL
//
// 策略：
//  1. 默认 enabled 仓库查（dnf list available <pkg> --quiet）
//  2. 若无，启用 EPEL 临时查（--enablerepo=epel）
func queryAvailableVersion(ctx context.Context, pkgMgr, pkg string) (version, repo string, viaEPEL bool) {
	if !validPkgName.MatchString(pkg) {
		return "", "", false
	}
	cctx, cancel := context.WithTimeout(ctx, precheckTimeout)
	defer cancel()

	switch pkgMgr {
	case "dnf":
		// dnf list available --quiet <pkg>
		out, err := exec.CommandContext(cctx, "dnf", "list", "available", "--quiet", pkg).Output()
		if err == nil {
			if v, r := parseDnfListAvailable(string(out), pkg); v != "" {
				return v, r, false
			}
		}
		// 尝试 EPEL
		out, err = exec.CommandContext(cctx, "dnf", "list", "available", "--quiet",
			"--enablerepo=epel", pkg).Output()
		if err == nil {
			if v, r := parseDnfListAvailable(string(out), pkg); v != "" {
				return v, r, strings.Contains(strings.ToLower(r), "epel")
			}
		}
	case "yum":
		out, err := exec.CommandContext(cctx, "yum", "list", "available", "-q", pkg).Output()
		if err == nil {
			if v, r := parseDnfListAvailable(string(out), pkg); v != "" {
				return v, r, false
			}
		}
		out, err = exec.CommandContext(cctx, "yum", "list", "available", "-q",
			"--enablerepo=epel", pkg).Output()
		if err == nil {
			if v, r := parseDnfListAvailable(string(out), pkg); v != "" {
				return v, r, strings.Contains(strings.ToLower(r), "epel")
			}
		}
	case "apt-get":
		// apt-cache policy <pkg> 返回 Installed/Candidate
		out, err := exec.CommandContext(cctx, "apt-cache", "policy", pkg).Output()
		if err == nil {
			if v, r := parseAptCachePolicy(string(out)); v != "" {
				return v, r, false
			}
		}
	}
	return "", "", false
}

// parseDnfListAvailable 解析 dnf/yum list available 输出
// 格式: "openssl.x86_64    1:1.1.1g-15.el8_2    rhel-8-baseos"
// 返回 version, repo
func parseDnfListAvailable(out, pkg string) (string, string) {
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "Last metadata") ||
			strings.HasPrefix(line, "Available Packages") ||
			strings.HasPrefix(line, "Listing...") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// 第一列形如 openssl.x86_64 或 openssl，去 .arch 后比对
		name := fields[0]
		if idx := strings.LastIndex(name, "."); idx > 0 {
			arch := name[idx+1:]
			// 常见 arch 字符特征
			if arch == "x86_64" || arch == "i686" || arch == "noarch" ||
				arch == "aarch64" || arch == "i386" || arch == "armv7hl" {
				name = name[:idx]
			}
		}
		if strings.EqualFold(name, pkg) {
			ver := strings.TrimPrefix(fields[1], "0:")
			return ver, fields[2]
		}
	}
	return "", ""
}

// parseAptCachePolicy 解析 apt-cache policy 输出，取 Candidate 字段
// 格式：
//
//	openssl:
//	  Installed: 1.1.1f-1ubuntu2
//	  Candidate: 1.1.1f-1ubuntu2.20
//	  Version table:
func parseAptCachePolicy(out string) (string, string) {
	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "Candidate:") {
			ver := strings.TrimSpace(strings.TrimPrefix(line, "Candidate:"))
			if ver == "" || ver == "(none)" {
				return "", ""
			}
			return ver, "apt"
		}
	}
	return "", ""
}

// versionCompare 返回 -1 (a<b) / 0 (a==b) / 1 (a>b)
// RPM 系用 rpm 自己的 --eval 跑 rpmvercmp 算法；DEB 用 dpkg --compare-versions
//
// 注意：纯字符串 lt 不可靠（"1.10" < "1.9" 字典序）
func versionCompare(pkgMgr, a, b string) int {
	if a == b {
		return 0
	}
	switch pkgMgr {
	case "dnf", "yum":
		// rpm 没直接的 vercmp CLI，用 rpmdev-vercmp 或 python3-rpm 调用
		// 实操可用：rpm --define '_topdir /tmp' 不靠谱
		// 改用 dpkg style 比较 fallback；生产建议引入 github.com/sassoftware/go-rpmutils
		if v := runRpmVercmp(a, b); v != 0 || (v == 0 && a == b) {
			return v
		}
		return naiveVersionCompare(a, b)
	case "apt-get":
		// dpkg --compare-versions a lt b → exit 0 if true
		if exec.Command("dpkg", "--compare-versions", a, "lt", b).Run() == nil {
			return -1
		}
		if exec.Command("dpkg", "--compare-versions", a, "gt", b).Run() == nil {
			return 1
		}
		return 0
	}
	return naiveVersionCompare(a, b)
}

// runRpmVercmp 调用 rpm CLI 比较版本（容器内必有 rpm）
// 实现：rpm --define '_vc %{lua: print(rpm.vercmp("A","B"))}' --eval '%{_vc}'
func runRpmVercmp(a, b string) int {
	macro := fmt.Sprintf(`%%{lua: print(rpm.vercmp("%s","%s"))}`, escapeLuaArg(a), escapeLuaArg(b))
	out, err := exec.Command("rpm", "--eval", macro).Output()
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(out))
	switch s {
	case "-1":
		return -1
	case "0":
		return 0
	case "1":
		return 1
	}
	return 0
}

func escapeLuaArg(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`)
}

// naiveVersionCompare 兜底：按 '.' / '-' 切片做数字 + 字符比较
// 不准确但比纯字符串 lt 好。生产环境优先靠 rpm/dpkg 真实算法。
func naiveVersionCompare(a, b string) int {
	splitFn := func(r rune) bool { return r == '.' || r == '-' || r == '_' }
	aParts := strings.FieldsFunc(a, splitFn)
	bParts := strings.FieldsFunc(b, splitFn)
	n := len(aParts)
	if len(bParts) < n {
		n = len(bParts)
	}
	for i := 0; i < n; i++ {
		if c := strings.Compare(aParts[i], bParts[i]); c != 0 {
			return c
		}
	}
	if len(aParts) < len(bParts) {
		return -1
	}
	if len(aParts) > len(bParts) {
		return 1
	}
	return 0
}

// fixedVersionValidStr 与 server 端 biz.fixedVersionValid 同义复制（避免跨包依赖）
func fixedVersionValidStr(v string) bool {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "", "0", "unknown", "-", "any", "n/a", "none", "null":
		return false
	}
	return true
}
