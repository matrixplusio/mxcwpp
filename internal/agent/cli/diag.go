package cli

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// DiagOptions --diag 子命令选项
type DiagOptions struct {
	OutputPath string // 输出 tar.gz 路径，空时自动生成
	LogDir     string // 日志目录，默认 DefaultLogDir
	WorkDir    string // 工作目录，默认 DefaultWorkDir
}

// RunDiag 执行 --diag 子命令
//
// 打包内容（可读则收，权限不足则跳过并在 manifest 中记录）：
//   - 最近 7 天的 agent.log* 文件
//   - agent_id 文件
//   - systemctl status / journalctl --since 1h 输出
//   - uname -a、网络监听快照
//   - manifest.txt 记录版本/时间/收集失败项
func RunDiag(opts CommonOptions, dopts DiagOptions, stdout, stderr io.Writer) (string, error) {
	logDir := dopts.LogDir
	if logDir == "" {
		logDir = DefaultLogDir
	}
	workDir := dopts.WorkDir
	if workDir == "" {
		workDir = DefaultWorkDir
	}
	outPath := dopts.OutputPath
	if outPath == "" {
		host, _ := os.Hostname()
		ts := time.Now().Format("20060102-150405")
		outPath = fmt.Sprintf("/tmp/mxsec-agent-diag-%s-%s.tar.gz", sanitize(host), ts)
	}

	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return "", fmt.Errorf("创建输出文件失败: %w", err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	manifest := newManifest(opts)

	// 1. 收集日志（最近 7 天）
	if err := addLogFiles(tw, logDir, 7*24*time.Hour, manifest); err != nil {
		manifest.recordError("log files", err)
	}

	// 2. agent_id
	if err := addFile(tw, filepath.Join(workDir, "agent_id"), "agent_id"); err != nil {
		manifest.recordError("agent_id", err)
	}

	// 3. systemctl / journalctl / uname / ss
	addCommandOutput(tw, "systemctl-status.txt", "systemctl", "status", SystemdUnit, "--no-pager")
	addCommandOutput(tw, "journalctl.txt", "journalctl", "-u", SystemdUnit, "--since", "1 hour ago", "--no-pager")
	addCommandOutput(tw, "uname.txt", "uname", "-a")
	addCommandOutput(tw, "ss.txt", "ss", "-tnlp")

	// 4. manifest
	manifestBytes := []byte(manifest.String())
	_ = tw.WriteHeader(&tar.Header{
		Name:    "manifest.txt",
		Mode:    0600,
		Size:    int64(len(manifestBytes)),
		ModTime: time.Now(),
	})
	if _, err := tw.Write(manifestBytes); err != nil {
		return "", err
	}

	fmt.Fprintf(stdout, "诊断包已生成: %s\n", outPath)
	fmt.Fprintf(stdout, "提示: 包含日志和系统状态，上传前请检查敏感信息。\n")
	return outPath, nil
}

// addLogFiles 把 dir 下满足 mtime > now-maxAge 的 *.log* 文件加入 tar
func addLogFiles(tw *tar.Writer, dir string, maxAge time.Duration, m *diagManifest) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	cutoff := time.Now().Add(-maxAge)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.Contains(name, "agent") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			continue
		}
		src := filepath.Join(dir, name)
		if err := addFile(tw, src, "logs/"+name); err != nil {
			m.recordError("logs/"+name, err)
		}
	}
	return nil
}

// addFile 把单文件加入 tar，目标路径为 destName
func addFile(tw *tar.Writer, src, destName string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	hdr := &tar.Header{
		Name:    destName,
		Mode:    int64(info.Mode().Perm()),
		Size:    info.Size(),
		ModTime: info.ModTime(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err = io.Copy(tw, f)
	return err
}

// addCommandOutput 跑命令并把输出写入 tar
func addCommandOutput(tw *tar.Writer, dest, name string, args ...string) {
	out, err := execCommand(name, args...)
	if err != nil {
		out = fmt.Appendf(out, "\n[ERROR] %s\n", err.Error())
	}
	hdr := &tar.Header{
		Name:    "system/" + dest,
		Mode:    0600,
		Size:    int64(len(out)),
		ModTime: time.Now(),
	}
	if err := tw.WriteHeader(hdr); err == nil {
		_, _ = tw.Write(out)
	}
}

// diagManifest 记录收集元数据
type diagManifest struct {
	opts   CommonOptions
	at     time.Time
	host   string
	errors []string
}

func newManifest(opts CommonOptions) *diagManifest {
	h, _ := os.Hostname()
	return &diagManifest{opts: opts, at: time.Now(), host: h}
}

func (m *diagManifest) recordError(item string, err error) {
	m.errors = append(m.errors, fmt.Sprintf("%s: %v", item, err))
}

func (m *diagManifest) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "mxsec-agent diagnostic bundle\n")
	fmt.Fprintf(&b, "Generated at: %s\n", m.at.Format(time.RFC3339))
	fmt.Fprintf(&b, "Hostname: %s\n", m.host)
	fmt.Fprintf(&b, "Build version: %s\n", versionString(m.opts.BuildVersion))
	fmt.Fprintf(&b, "Build time: %s\n", m.opts.BuildTime)
	fmt.Fprintf(&b, "Server host: %s\n", m.opts.ServerHost)
	if len(m.errors) > 0 {
		fmt.Fprintf(&b, "\nCollection errors:\n")
		for _, e := range m.errors {
			fmt.Fprintf(&b, "  - %s\n", e)
		}
	}
	return b.String()
}

// sanitize 把 hostname 中不适合做文件名的字符替换为 _
func sanitize(s string) string {
	if s == "" {
		return "host"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '.':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}
