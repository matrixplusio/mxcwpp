// Package handlers 提供各类资产采集器的实现
package handlers

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/matrixplusio/mxcwpp/plugins/collector/engine"
)

// BinaryProbeHandler 是二进制探针采集器
//
// 解决源码安装 / make install / tar 解压 装的应用扫描盲点。
// RPM/DEB 包管理器看不到 /usr/local 和 /opt 下的源码装应用（OpenResty/Tomcat/源码 nginx 等），
// 本采集器扫常见安装前缀（/opt, /usr/local, /srv）下的已知服务二进制，
// 执行 -V/--version 并用正则解析版本号，输出 PackageType=binary 的 SoftwareAsset。
type BinaryProbeHandler struct {
	Logger *zap.Logger
}

// BinaryProbe 描述一个待探测的二进制
type BinaryProbe struct {
	Name            string   // 服务名（如 openresty / nginx / tomcat）
	BinaryNames     []string // 可能的二进制文件名
	InstallPaths    []string // 探测前缀（直接拼 binary 名）
	Args            []string // -V / --version 等参数
	VersionRegex    string   // 提取版本正则
	ProductOverride string   // 输出 Name 覆盖（如 OpenResty 探测 nginx -V 输出含 openresty/X.Y.Z，名字仍为 openresty）
	StderrFirst     bool     // 是否优先读 stderr（nginx -V 输出在 stderr）
	UseGlob         bool     // InstallPaths 是否含 glob 通配符（如 /opt/jdk*/bin/java）
}

// 单次二进制执行超时
const binaryProbeExecTimeout = 3 * time.Second

// 并发上限
const binaryProbeConcurrency = 8

// defaultProbes 返回内置探针列表
//
// 覆盖商业产品里源码装常见的中间件 / 语言运行时 / 容器运行时（共 19 个），
// 包括 OpenResty / 源码 nginx / Tomcat / MySQL / Redis / PostgreSQL / MongoDB /
// Kafka / HAProxy / PHP / Python / Ruby / Node / Java / Go / Docker / containerd / kubelet / etcd。
func defaultProbes() []BinaryProbe {
	return []BinaryProbe{
		// OpenResty：nginx -V 输出在 stderr，含 openresty/X.Y.Z
		{
			Name:            "openresty",
			BinaryNames:     []string{"nginx", "openresty"},
			InstallPaths:    []string{"/usr/local/openresty/nginx/sbin", "/opt/openresty/nginx/sbin", "/usr/local/openresty/bin", "/opt/openresty/bin"},
			Args:            []string{"-V"},
			VersionRegex:    `openresty/(\S+)`,
			ProductOverride: "openresty",
			StderrFirst:     true,
		},
		// 源码 nginx
		{
			Name:         "nginx",
			BinaryNames:  []string{"nginx"},
			InstallPaths: []string{"/usr/local/nginx/sbin", "/opt/nginx/sbin", "/usr/local/sbin", "/opt/nginx/bin"},
			Args:         []string{"-v"},
			VersionRegex: `nginx version: nginx/(\S+)`,
			StderrFirst:  true,
		},
		// Tomcat: bin/version.sh 输出 "Server version: Apache Tomcat/X.Y.Z"
		{
			Name:         "tomcat",
			BinaryNames:  []string{"version.sh"},
			InstallPaths: []string{"/opt/tomcat/bin", "/usr/local/tomcat/bin", "/srv/tomcat/bin"},
			Args:         nil,
			VersionRegex: `Server version:\s+Apache Tomcat/(\S+)`,
		},
		// Redis
		{
			Name:         "redis",
			BinaryNames:  []string{"redis-server"},
			InstallPaths: []string{"/usr/local/bin", "/usr/local/redis/bin", "/opt/redis/bin", "/opt/redis/src"},
			Args:         []string{"--version"},
			VersionRegex: `Redis server v=(\S+)`,
		},
		// MySQL / MariaDB
		{
			Name:         "mysql",
			BinaryNames:  []string{"mysqld"},
			InstallPaths: []string{"/usr/local/mysql/bin", "/opt/mysql/bin", "/usr/local/mariadb/bin", "/opt/mariadb/bin"},
			Args:         []string{"--version"},
			VersionRegex: `Ver\s+(\S+)`,
		},
		// PostgreSQL
		{
			Name:         "postgres",
			BinaryNames:  []string{"postgres"},
			InstallPaths: []string{"/usr/local/pgsql/bin", "/opt/postgresql/bin", "/usr/local/postgres/bin", "/opt/pgsql/bin"},
			Args:         []string{"--version"},
			VersionRegex: `postgres \(PostgreSQL\)\s+(\S+)`,
		},
		// MongoDB
		{
			Name:         "mongodb",
			BinaryNames:  []string{"mongod"},
			InstallPaths: []string{"/usr/local/bin", "/usr/local/mongodb/bin", "/opt/mongodb/bin"},
			Args:         []string{"--version"},
			VersionRegex: `db version v(\S+)`,
		},
		// Kafka: 取 libs/kafka_*.jar 的版本，sh 启动脚本本身不带版本
		// 此处仅做存在性探测，版本走 jar 文件名解析（在 walk 阶段特判）
		{
			Name:         "kafka",
			BinaryNames:  []string{"kafka-server-start.sh"},
			InstallPaths: []string{"/opt/kafka/bin", "/usr/local/kafka/bin", "/srv/kafka/bin"},
			Args:         nil,
			VersionRegex: ``,
		},
		// HAProxy
		{
			Name:         "haproxy",
			BinaryNames:  []string{"haproxy"},
			InstallPaths: []string{"/usr/local/sbin", "/usr/local/bin", "/opt/haproxy/sbin", "/opt/haproxy/bin"},
			Args:         []string{"-v"},
			VersionRegex: `HAProxy version (\S+)`,
		},
		// PHP
		{
			Name:         "php",
			BinaryNames:  []string{"php"},
			InstallPaths: []string{"/usr/local/bin", "/opt/php/bin", "/usr/local/php/bin"},
			Args:         []string{"-v"},
			VersionRegex: `PHP (\S+)`,
		},
		// Python 源码（含 python3.x 通配）
		{
			Name:         "python",
			BinaryNames:  []string{"python3", "python3.8", "python3.9", "python3.10", "python3.11", "python3.12", "python3.13", "python"},
			InstallPaths: []string{"/usr/local/bin", "/opt/python/bin"},
			Args:         []string{"--version"},
			VersionRegex: `Python (\S+)`,
		},
		// Ruby
		{
			Name:         "ruby",
			BinaryNames:  []string{"ruby"},
			InstallPaths: []string{"/usr/local/bin", "/opt/ruby/bin"},
			Args:         []string{"--version"},
			VersionRegex: `ruby (\S+)`,
		},
		// Node.js
		{
			Name:         "nodejs",
			BinaryNames:  []string{"node"},
			InstallPaths: []string{"/usr/local/bin", "/opt/node/bin", "/opt/nodejs/bin"},
			Args:         []string{"--version"},
			VersionRegex: `v?(\d+\.\d+\.\d+)`,
		},
		// Java：JDK glob 路径需特殊展开
		{
			Name:         "java",
			BinaryNames:  []string{"java"},
			InstallPaths: []string{"/usr/local/java/bin", "/usr/local/jdk/bin", "/opt/jdk*/bin", "/opt/java/bin", "/opt/jdk/bin"},
			Args:         []string{"-version"},
			VersionRegex: `version "([^"]+)"`,
			StderrFirst:  true,
			UseGlob:      true,
		},
		// Go
		{
			Name:         "golang",
			BinaryNames:  []string{"go"},
			InstallPaths: []string{"/usr/local/go/bin", "/opt/go/bin"},
			Args:         []string{"version"},
			VersionRegex: `go version go(\S+)`,
		},
		// Docker（dockerd / docker 客户端）
		{
			Name:         "docker",
			BinaryNames:  []string{"dockerd", "docker"},
			InstallPaths: []string{"/usr/local/bin", "/opt/docker/bin"},
			Args:         []string{"--version"},
			VersionRegex: `version (\S+?),?`,
		},
		// containerd
		{
			Name:         "containerd",
			BinaryNames:  []string{"containerd"},
			InstallPaths: []string{"/usr/local/bin", "/opt/containerd/bin"},
			Args:         []string{"--version"},
			VersionRegex: `containerd\s+\S+\s+(v?\S+)`,
		},
		// kubelet
		{
			Name:         "kubelet",
			BinaryNames:  []string{"kubelet"},
			InstallPaths: []string{"/usr/local/bin", "/opt/kubernetes/bin", "/opt/kube/bin"},
			Args:         []string{"--version"},
			VersionRegex: `Kubernetes v(\S+)`,
		},
		// etcd
		{
			Name:         "etcd",
			BinaryNames:  []string{"etcd"},
			InstallPaths: []string{"/usr/local/bin", "/opt/etcd/bin"},
			Args:         []string{"--version"},
			VersionRegex: `etcd Version:\s+(\S+)`,
		},
	}
}

// probeJob 单次探测任务
type probeJob struct {
	probe      BinaryProbe
	binaryPath string
}

// Collect 执行二进制探测采集
//
// 三重确认（防误报）：
//  1. 二进制文件存在于探针配置路径（discoverBinaries 已确认）
//  2. 进程在跑 — readlink /proc/*/exe 命中此路径，或同名 basename 在跑
//  3. 探针 -V/--version 出版本号
//
// 任一不满足即跳过，避免将"装了但不跑"或"残留死文件"上报为运行资产。
// 同时合并旧 proc_scanner 职责：CWPP 仅关心"运行的二进制"，不维护磁盘清单。
func (h *BinaryProbeHandler) Collect(ctx context.Context) ([]interface{}, error) {
	probes := defaultProbes()

	// 1. 扫 /proc/*/exe 拿主机当前运行的二进制集合（real path + basename）
	runningPaths, runningBasenames := collectRunningBinaries(h.Logger)
	h.Logger.Debug("binary probe: running binaries collected",
		zap.Int("paths", len(runningPaths)),
		zap.Int("basenames", len(runningBasenames)))

	// 2. 解析所有候选二进制路径（含 glob 展开）
	allJobs := h.discoverBinaries(ctx, probes)
	if len(allJobs) == 0 {
		h.Logger.Debug("binary probe: no candidate binaries found on disk")
		return nil, nil
	}

	// 3. gate 1：仅保留"在跑"的候选（路径直接命中 或 basename 命中）
	jobs := filterRunningJobs(allJobs, runningPaths, runningBasenames)
	if len(jobs) == 0 {
		h.Logger.Debug("binary probe: 0 candidates are actually running, skip",
			zap.Int("discovered", len(allJobs)))
		return nil, nil
	}

	h.Logger.Debug("binary probe: candidates after running gate",
		zap.Int("discovered", len(allJobs)),
		zap.Int("running", len(jobs)))

	// 4. 并发探测（chan 收集结果，最多 binaryProbeConcurrency 个 goroutine）
	resultCh := make(chan *engine.SoftwareAsset, len(jobs))
	sem := make(chan struct{}, binaryProbeConcurrency)
	var wg sync.WaitGroup

	for _, job := range jobs {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(j probeJob) {
			defer wg.Done()
			defer func() { <-sem }()

			asset := h.probeOne(ctx, j)
			if asset != nil {
				resultCh <- asset
			}
		}(job)
	}

	wg.Wait()
	close(resultCh)

	// 3. 收集结果（同 name+version+path 去重）
	seen := make(map[string]struct{})
	var out []interface{}
	for asset := range resultCh {
		key := asset.Name + "@" + asset.Version + "@" + asset.PURL
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, asset)
	}

	h.Logger.Info("binary probe completed",
		zap.Int("candidates_on_disk", len(allJobs)),
		zap.Int("candidates_running", len(jobs)),
		zap.Int("identified", len(out)))

	return out, nil
}

// collectRunningBinaries 扫描 /proc/*/exe，返回主机当前运行的二进制路径集合 + basename 集合
//
// 主路径集（key=real path）：用于直接路径命中（探针路径 == 进程 exe 实际指向）
// basename 集（key=basename）：用于跨路径软命中（探针扫 /opt/openresty/bin/nginx，
// 实际进程 exe 是 /usr/local/openresty/nginx/sbin/nginx —— 路径不同但 basename 相同）
//
// 权限不足或非 Linux 平台失败时返回空集，让上层判定为"无运行二进制"自然跳过整个探测。
func collectRunningBinaries(logger *zap.Logger) (map[string]struct{}, map[string]struct{}) {
	paths := make(map[string]struct{})
	basenames := make(map[string]struct{})

	if _, err := os.Stat("/proc"); err != nil {
		// 非 Linux 环境，无 /proc，返回空集
		return paths, basenames
	}

	entries, err := os.ReadDir("/proc")
	if err != nil {
		logger.Debug("collectRunningBinaries: read /proc failed", zap.Error(err))
		return paths, basenames
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		// PID 目录名必为数字
		name := e.Name()
		if !isAllDigits(name) {
			continue
		}

		exeLink := "/proc/" + name + "/exe"
		realPath, err := os.Readlink(exeLink)
		if err != nil {
			// 权限不足 / 内核线程 / 已退出：跳过
			continue
		}

		// 跳过被删除二进制（"/usr/bin/foo (deleted)"）
		if strings.HasSuffix(realPath, " (deleted)") {
			continue
		}

		// 去掉 /proc/{pid}/root/ 前缀（容器内进程的宿主视角）
		realPath = stripProcRootPrefix(realPath)
		if realPath == "" || !filepath.IsAbs(realPath) {
			continue
		}

		paths[realPath] = struct{}{}
		basenames[filepath.Base(realPath)] = struct{}{}
	}

	return paths, basenames
}

// filterRunningJobs 三重确认 gate 1：仅保留 binary 在跑的探测任务
//
// 命中规则（任一即可）：
//  1. 探针 binary 路径直接出现在 /proc/*/exe 集合中（最强证据）
//  2. 探针 binary 的 basename 出现在运行 basename 集合中（容忍探针配置路径与实际安装路径不一致）
//
// Kafka 特判：kafka-server-start.sh 启动 JVM，/proc/*/exe 指向 java 而不是脚本本身，
// 故对 Kafka 不强求路径/basename 命中，靠 detectKafkaVersion 解析 jar 文件名。
func filterRunningJobs(jobs []probeJob, runningPaths, runningBasenames map[string]struct{}) []probeJob {
	if len(runningPaths) == 0 && len(runningBasenames) == 0 {
		return nil
	}

	filtered := make([]probeJob, 0, len(jobs))
	for _, j := range jobs {
		if j.probe.Name == "kafka" {
			// 启动脚本拉起 JVM，无独立运行进程，靠 jar 名取版本
			filtered = append(filtered, j)
			continue
		}

		if _, ok := runningPaths[j.binaryPath]; ok {
			filtered = append(filtered, j)
			continue
		}

		base := filepath.Base(j.binaryPath)
		if _, ok := runningBasenames[base]; ok {
			filtered = append(filtered, j)
			continue
		}
	}
	return filtered
}

// isAllDigits 全为 0-9 字符则返回 true（用于判定 /proc/{pid} 目录名）
func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// stripProcRootPrefix 去掉 /proc/{pid}/root/ 前缀（容器内进程的宿主视角）
// 例："/proc/1234/root/usr/bin/nginx" -> "/usr/bin/nginx"
// 非该前缀直接返回原值。
func stripProcRootPrefix(p string) string {
	if !strings.HasPrefix(p, "/proc/") {
		return p
	}
	rest := p[len("/proc/"):]
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 {
		return p
	}
	pidPart := rest[:slash]
	if !isAllDigits(pidPart) {
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

// discoverBinaries 解析配置中的 InstallPaths，找出实际存在的可执行候选
func (h *BinaryProbeHandler) discoverBinaries(ctx context.Context, probes []BinaryProbe) []probeJob {
	var jobs []probeJob

	for _, p := range probes {
		select {
		case <-ctx.Done():
			return jobs
		default:
		}

		paths := p.InstallPaths
		// glob 展开（如 /opt/jdk*/bin）
		if p.UseGlob {
			expanded := make([]string, 0, len(paths))
			for _, pat := range paths {
				if strings.ContainsAny(pat, "*?[") {
					matches, err := filepath.Glob(pat)
					if err == nil {
						expanded = append(expanded, matches...)
					}
				} else {
					expanded = append(expanded, pat)
				}
			}
			paths = expanded
		}

		for _, dir := range paths {
			for _, binName := range p.BinaryNames {
				full := filepath.Join(dir, binName)
				if !isExecutableFile(full) {
					continue
				}
				jobs = append(jobs, probeJob{probe: p, binaryPath: full})
			}
		}
	}

	return jobs
}

// isExecutableFile 判断路径是否为可执行普通文件
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	if !info.Mode().IsRegular() {
		return false
	}
	// 任一执行位（owner/group/other）即认为可执行
	return info.Mode().Perm()&0o111 != 0
}

// probeOne 探测单个二进制，返回 SoftwareAsset；失败返回 nil
func (h *BinaryProbeHandler) probeOne(ctx context.Context, job probeJob) *engine.SoftwareAsset {
	p := job.probe

	// Kafka 特判：版本来自 libs/kafka_*.jar 文件名
	if p.Name == "kafka" {
		version := detectKafkaVersion(job.binaryPath)
		if version == "" {
			return nil
		}
		return buildAsset(p, version, job.binaryPath)
	}

	// 执行 -V/--version，3s 超时
	execCtx, cancel := context.WithTimeout(ctx, binaryProbeExecTimeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, job.binaryPath, p.Args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// 部分二进制（如 nginx -V）退出码非 0 仍输出版本，继续尝试解析
		h.Logger.Debug("binary probe: command failed (will still try output)",
			zap.String("binary", job.binaryPath),
			zap.Error(err))
	}

	// 选择输出源
	primary := stdout.String()
	secondary := stderr.String()
	if p.StderrFirst {
		primary, secondary = secondary, primary
	}

	output := primary
	if strings.TrimSpace(output) == "" {
		output = secondary
	}

	if p.VersionRegex == "" {
		return nil
	}

	re, err := regexp.Compile(p.VersionRegex)
	if err != nil {
		h.Logger.Warn("binary probe: invalid version regex",
			zap.String("name", p.Name),
			zap.String("regex", p.VersionRegex),
			zap.Error(err))
		return nil
	}

	// 优先在 primary 输出里找，找不到再去 secondary 里找
	version := extractVersion(re, output)
	if version == "" && secondary != "" {
		version = extractVersion(re, secondary)
	}
	// 兜底：合并两个流再扫一次（覆盖 OpenResty 探测时 nginx -V 同时写两端的情况）
	if version == "" {
		version = extractVersion(re, primary+"\n"+secondary)
	}
	if version == "" {
		h.Logger.Debug("binary probe: version not parsed",
			zap.String("binary", job.binaryPath),
			zap.String("name", p.Name))
		return nil
	}

	return buildAsset(p, version, job.binaryPath)
}

// extractVersion 从输出文本里抽取版本号（取第一个匹配组）
func extractVersion(re *regexp.Regexp, output string) string {
	matches := re.FindStringSubmatch(output)
	if len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(matches[1])
}

// detectKafkaVersion 从 kafka 安装目录的 libs/kafka_*.jar 文件名解析版本
//
// 典型：/opt/kafka/libs/kafka_2.13-3.7.0.jar -> 版本 3.7.0
func detectKafkaVersion(binaryPath string) string {
	// bin/kafka-server-start.sh 的上一级即 kafka home
	binDir := filepath.Dir(binaryPath)
	libsDir := filepath.Join(filepath.Dir(binDir), "libs")
	entries, err := os.ReadDir(libsDir)
	if err != nil {
		return ""
	}
	re := regexp.MustCompile(`^kafka_[\d.]+-(\d+\.\d+\.\d+(?:\.\w+)?)\.jar$`)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := re.FindStringSubmatch(e.Name())
		if len(m) >= 2 {
			return m[1]
		}
	}
	return ""
}

// buildAsset 构造 SoftwareAsset
func buildAsset(p BinaryProbe, version, binaryPath string) *engine.SoftwareAsset {
	name := p.Name
	if p.ProductOverride != "" {
		name = p.ProductOverride
	}

	asset := &engine.SoftwareAsset{
		Asset: engine.Asset{
			CollectedAt: time.Now(),
		},
		Name:        name,
		Version:     version,
		PackageType: "binary",
		PURL:        buildBinaryPURL(name, version, binaryPath),
	}
	return asset
}

// buildBinaryPURL 生成源码装应用的 Package URL
//
// 格式：pkg:generic/{name}@{version}?probe=binary&path={escaped path}
// 漏洞匹配引擎可识别 pkg:generic/openresty@1.25.3.1 -> CVE-2024-XXXXX。
func buildBinaryPURL(name, version, sourcePath string) string {
	purl := fmt.Sprintf("pkg:generic/%s@%s?probe=binary", url.PathEscape(name), url.PathEscape(version))
	if sourcePath != "" {
		purl += "&path=" + url.QueryEscape(sourcePath)
	}
	return purl
}
