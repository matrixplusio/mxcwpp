package handlers

import (
	"archive/zip"
	"bufio"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/zap"
)

// jar 文件大小上限，超过则跳过（fat jar 解压慢且 RAM 占用大）
const jarMaxFileSize = 100 * 1024 * 1024

// jar 后缀（含 war / ear，Spring Boot 与 Java EE 部署常见）
var jarExtensions = map[string]struct{}{
	".jar": {},
	".war": {},
	".ear": {},
}

// JDK/JRE 自带 jar 路径片段：命中其一即跳过（与业务依赖无关，扫了纯增噪声）
var jdkPathFragments = []string{
	"/jdk", "/jre", "/jvm",
	"/java/lib/", "/java-1.", "/java-2.",
	"/zulu", "/temurin", "/openjdk", "/adoptium",
	"/graalvm", "/corretto",
}

// JarScannerHandler 扫描"运行中 java 进程"实际加载的 jar/war/ear，并解析其 BOM
//
// 设计原则（P0-6）：
//   - CWPP 扫"运行的东西"。无 java 进程在跑 → 不扫（不维护磁盘 jar 清单）。
//   - 业界共识：Log4j / Jetty / Netty 等 Java 依赖 CVE 必须能扫到 fat jar 内嵌
//     依赖；但只对真实运行 JVM 加载的 jar 扫，避免 /opt 下备份 jar / 测试 jar /
//     旧版本 war 全部入库造成误报。
//   - jar 来源三路：cmdline 的 -jar 与 -cp/-classpath、/proc/{pid}/fd 打开的
//     .jar、/proc/{pid}/maps mmap 的 .jar（防 cmdline 隐藏路径）。
//
// 解决的实测误报（G02-UAT 等）：
//   - /opt 旧部署目录残留 jar 全扫报 96k+ 条
//   - skywalking-agent / apollo / spring boot 等 fat jar 内嵌依赖重复
type JarScannerHandler struct {
	Logger *zap.Logger
}

// javaProc 单个运行中的 java 进程及其加载的 jar 集合
type javaProc struct {
	pid  int
	jars map[string]struct{} // jar 绝对路径集合（去重）
}

// Collect 实现 engine.Handler 接口
func (h *JarScannerHandler) Collect(ctx context.Context) ([]interface{}, error) {
	procs := findRunningJavaProcs(h.Logger)
	if len(procs) == 0 {
		h.Logger.Debug("jar_scanner: no running java process, skip")
		return nil, nil
	}

	// 1. 汇总所有 jar 路径（按 path 去重，记录关联 pid — 同 jar 多进程共享时取首个）
	jarToPID := make(map[string]int)
	for _, p := range procs {
		for jarPath := range p.jars {
			if _, ok := jarToPID[jarPath]; ok {
				continue
			}
			jarToPID[jarPath] = p.pid
		}
	}
	if len(jarToPID) == 0 {
		h.Logger.Debug("jar_scanner: 0 jars identified across procs, skip")
		return nil, nil
	}

	// 2. 解析每个 jar → 多条 BOM 输出（fat jar 内嵌 pom.properties 全部采集）
	//    全局去重 key = group:artifact:version（无 group 时退化为 name:version）
	var (
		results []interface{}
		seen    = make(map[string]struct{})
	)
	for jarPath, pid := range jarToPID {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		info, err := os.Stat(jarPath)
		if err != nil || info.IsDir() {
			continue
		}
		if info.Size() == 0 || info.Size() > jarMaxFileSize {
			continue
		}

		pkgs, err := parseJarBOM(jarPath)
		if err != nil {
			h.Logger.Debug("jar 解析失败", zap.String("path", jarPath), zap.Error(err))
			continue
		}

		for _, pkg := range pkgs {
			name, _ := pkg["name"].(string)
			ver, _ := pkg["version"].(string)
			key := name + "@" + ver
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}

			pkg["scope"] = "system"
			pkg["source_handler"] = "jar_scanner"
			pkg["host_process_pid"] = pid
			results = append(results, pkg)
		}
	}

	h.Logger.Info("jar_scanner 扫描完成",
		zap.Int("procs", len(procs)),
		zap.Int("unique_jars", len(jarToPID)),
		zap.Int("packages", len(results)))

	return results, nil
}

// findRunningJavaProcs 扫 /proc/*/exe 找 java 进程，并对每个进程提取加载的 jar 集合
//
// jar 来源三路（任一命中即纳入）：
//  1. /proc/{pid}/cmdline 中的 -jar <path>、-cp <a:b:c>、--class-path <...>，以及最后一个
//     argv（部分 Maven Shade 启动器把 jar 当主类参数）
//  2. /proc/{pid}/fd 中已打开的 .jar 文件链接
//  3. /proc/{pid}/maps 中 mmap 的 .jar（含 lazy 加载未列入 fd 的依赖）
//
// 自动过滤 JDK/JRE 自带 jar（rt.jar / tools.jar / charsets.jar / 在 jdk*/jre* 路径下的所有）。
func findRunningJavaProcs(logger *zap.Logger) []javaProc {
	if _, err := os.Stat("/proc"); err != nil {
		return nil
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		logger.Debug("read /proc failed", zap.Error(err))
		return nil
	}

	var out []javaProc
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
		realPath = stripProcRootForJar(realPath)
		if realPath == "" || !filepath.IsAbs(realPath) {
			continue
		}

		base := strings.ToLower(filepath.Base(realPath))
		if base != "java" {
			continue
		}

		jars := make(map[string]struct{})

		// 1. cmdline 路径
		if paths := jarsFromCmdline(pid); len(paths) > 0 {
			for _, p := range paths {
				if isAcceptableJar(p) {
					jars[p] = struct{}{}
				}
			}
		}
		// 2. /proc/{pid}/fd
		if paths := jarsFromProcFD(pid); len(paths) > 0 {
			for _, p := range paths {
				if isAcceptableJar(p) {
					jars[p] = struct{}{}
				}
			}
		}
		// 3. /proc/{pid}/maps
		if paths := jarsFromProcMaps(pid); len(paths) > 0 {
			for _, p := range paths {
				if isAcceptableJar(p) {
					jars[p] = struct{}{}
				}
			}
		}

		if len(jars) == 0 {
			continue
		}
		out = append(out, javaProc{pid: pid, jars: jars})
	}

	return out
}

// jarsFromCmdline 从 /proc/{pid}/cmdline 提取 -jar / -cp / --class-path 中的 jar 路径
//
// 处理：
//   - argv 之间 \0 分隔
//   - cwd 解析相对路径（/proc/{pid}/cwd readlink）
//   - -cp / -classpath 后跟用 : 分隔的多路径
//   - 最后一个 argv 兜底（某些 maven shade 启动器把 jar 当主类参数）
func jarsFromCmdline(pid int) []string {
	cmdlineBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil || len(cmdlineBytes) == 0 {
		return nil
	}
	argv := strings.Split(strings.TrimRight(string(cmdlineBytes), "\x00"), "\x00")

	cwd, _ := os.Readlink(fmt.Sprintf("/proc/%d/cwd", pid))
	cwd = stripProcRootForJar(cwd)

	resolve := func(p string) string {
		if p == "" {
			return ""
		}
		if !filepath.IsAbs(p) {
			if cwd == "" {
				return ""
			}
			p = filepath.Join(cwd, p)
		}
		return p
	}

	var out []string
	for i := 1; i < len(argv); i++ {
		a := argv[i]
		if a == "" {
			continue
		}

		switch {
		case a == "-jar":
			if i+1 < len(argv) {
				if r := resolve(argv[i+1]); r != "" {
					out = append(out, r)
				}
				i++
			}
		case a == "-cp", a == "-classpath", a == "--class-path":
			if i+1 < len(argv) {
				for _, p := range strings.Split(argv[i+1], ":") {
					if r := resolve(p); r != "" && hasJarExtension(r) {
						out = append(out, r)
					}
				}
				i++
			}
		case strings.HasPrefix(a, "-cp=") || strings.HasPrefix(a, "-classpath="):
			// 极少见但合法
			eq := strings.IndexByte(a, '=')
			for _, p := range strings.Split(a[eq+1:], ":") {
				if r := resolve(p); r != "" && hasJarExtension(r) {
					out = append(out, r)
				}
			}
		default:
			// argv 中其他可能是 jar 路径的（最后一个 argv 兜底）
			if hasJarExtension(a) {
				if r := resolve(a); r != "" {
					out = append(out, r)
				}
			}
		}
	}
	return out
}

// jarsFromProcFD 从 /proc/{pid}/fd 找已打开的 jar 文件
//
// 仅看链接目标的扩展名；权限不足或 fd 已关闭时静默跳过。
func jarsFromProcFD(pid int) []string {
	fdDir := fmt.Sprintf("/proc/%d/fd", pid)
	entries, err := os.ReadDir(fdDir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join(fdDir, e.Name()))
		if err != nil {
			continue
		}
		target = stripProcRootForJar(target)
		if target == "" || !filepath.IsAbs(target) {
			continue
		}
		if !hasJarExtension(target) {
			continue
		}
		out = append(out, target)
	}
	return out
}

// jarsFromProcMaps 从 /proc/{pid}/maps 找 mmap 进来的 jar
//
// maps 每行格式：address perms offset dev inode pathname
// 仅看 pathname 含 .jar/.war/.ear 后缀的（大小写不敏感）。
func jarsFromProcMaps(pid int) []string {
	mapsBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return nil
	}
	seen := make(map[string]struct{})
	var out []string
	for _, line := range strings.Split(string(mapsBytes), "\n") {
		// 第 5 列之后是 pathname；用 fields 处理
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		pathPart := fields[5]
		if !filepath.IsAbs(pathPart) {
			continue
		}
		if !hasJarExtension(pathPart) {
			continue
		}
		if _, dup := seen[pathPart]; dup {
			continue
		}
		seen[pathPart] = struct{}{}
		out = append(out, pathPart)
	}
	return out
}

// hasJarExtension 判定路径是否以 .jar / .war / .ear 结尾（大小写不敏感）
func hasJarExtension(p string) bool {
	ext := strings.ToLower(filepath.Ext(p))
	_, ok := jarExtensions[ext]
	return ok
}

// isAcceptableJar 排除 JDK/JRE 自带 jar 与显然不是业务依赖的特殊文件
func isAcceptableJar(p string) bool {
	if p == "" {
		return false
	}
	low := strings.ToLower(p)
	for _, frag := range jdkPathFragments {
		if strings.Contains(low, frag) {
			return false
		}
	}
	base := strings.ToLower(filepath.Base(p))
	switch base {
	case "rt.jar", "tools.jar", "charsets.jar", "resources.jar", "jsse.jar", "jce.jar":
		return false
	}
	return true
}

// stripProcRootForJar 去 /proc/{pid}/root/ 前缀（独立私有实现）
func stripProcRootForJar(p string) string {
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

// parseJarBOM 用 archive/zip 读 jar 内部 BOM 信息
//
// pom.properties 优先（最权威 — 含 groupId:artifactId:version），其次 MANIFEST.MF。
// 输出每条 map 不含 scope / source_handler / host_process_pid（由 Collect 主流程附加）。
func parseJarBOM(path string) ([]map[string]interface{}, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("zip open: %w", err)
	}
	defer zr.Close()

	var (
		pomPkgs     []map[string]interface{}
		manifestPkg map[string]interface{}
	)

	for _, f := range zr.File {
		name := f.Name
		switch {
		case strings.HasPrefix(name, "META-INF/maven/") && strings.HasSuffix(name, "/pom.properties"):
			pkg, ok := readJarPomProperties(f, path)
			if ok {
				pomPkgs = append(pomPkgs, pkg)
			}
		case name == "META-INF/MANIFEST.MF" && manifestPkg == nil:
			pkg, ok := readJarManifest(f, path)
			if ok {
				manifestPkg = pkg
			}
		}
	}

	if len(pomPkgs) > 0 {
		return pomPkgs, nil
	}
	if manifestPkg != nil {
		return []map[string]interface{}{manifestPkg}, nil
	}
	return nil, nil
}

// readJarPomProperties 解析 META-INF/maven/{group}/{artifact}/pom.properties
func readJarPomProperties(f *zip.File, jarPath string) (map[string]interface{}, bool) {
	rc, err := f.Open()
	if err != nil {
		return nil, false
	}
	defer rc.Close()

	var groupID, artifactID, version string
	scanner := bufio.NewScanner(rc)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, "=")
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "groupId":
			groupID = val
		case "artifactId":
			artifactID = val
		case "version":
			version = val
		}
	}

	if artifactID == "" || version == "" {
		return nil, false
	}

	var name, purl string
	if groupID != "" {
		name = groupID + ":" + artifactID
		purl = fmt.Sprintf("pkg:maven/%s/%s@%s",
			url.PathEscape(groupID),
			url.PathEscape(artifactID),
			url.PathEscape(version))
	} else {
		name = artifactID
		purl = fmt.Sprintf("pkg:generic/%s@%s",
			url.PathEscape(artifactID),
			url.PathEscape(version))
	}

	return map[string]interface{}{
		"name":         name,
		"version":      version,
		"collected_at": time.Now().Format(time.RFC3339),
		"package_type": "jar",
		"ecosystem":    "Maven",
		"purl":         purl,
		"source_file":  jarPath,
	}, true
}

// readJarManifest 解析 META-INF/MANIFEST.MF
//
// 优先 Bundle-SymbolicName/Bundle-Version（OSGi），其次 Implementation-Title/Implementation-Version。
func readJarManifest(f *zip.File, jarPath string) (map[string]interface{}, bool) {
	rc, err := f.Open()
	if err != nil {
		return nil, false
	}
	defer rc.Close()

	const maxManifestSize = 1 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(rc, maxManifestSize))
	if err != nil {
		return nil, false
	}

	attrs := parseManifestAttrs(data)

	var name, version string
	if v, ok := attrs["Bundle-SymbolicName"]; ok {
		if idx := strings.Index(v, ";"); idx > 0 {
			v = strings.TrimSpace(v[:idx])
		}
		name = v
		version = attrs["Bundle-Version"]
	}
	if name == "" || version == "" {
		if v, ok := attrs["Implementation-Title"]; ok && v != "" {
			name = v
			version = attrs["Implementation-Version"]
		}
	}

	if name == "" || version == "" {
		return nil, false
	}

	return map[string]interface{}{
		"name":         name,
		"version":      version,
		"collected_at": time.Now().Format(time.RFC3339),
		"package_type": "jar",
		"ecosystem":    "Maven",
		"purl":         fmt.Sprintf("pkg:generic/%s@%s", url.PathEscape(name), url.PathEscape(version)),
		"source_file":  jarPath,
	}, true
}

// parseManifestAttrs 解析 jar manifest（RFC 822 风格），处理续行（前导空格）
func parseManifestAttrs(data []byte) map[string]string {
	attrs := make(map[string]string)
	lines := strings.Split(string(data), "\n")

	var curKey, curVal string
	flush := func() {
		if curKey != "" {
			attrs[curKey] = strings.TrimSpace(curVal)
		}
		curKey, curVal = "", ""
	}

	for _, raw := range lines {
		line := strings.TrimRight(raw, "\r")
		if line == "" {
			// 主属性段结束（manifest 主段 + per-entry 段以空行分隔）
			flush()
			break
		}
		if strings.HasPrefix(line, " ") {
			curVal += line[1:]
			continue
		}
		flush()
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		curKey = strings.TrimSpace(line[:idx])
		curVal = strings.TrimSpace(line[idx+1:])
	}
	flush()

	return attrs
}
