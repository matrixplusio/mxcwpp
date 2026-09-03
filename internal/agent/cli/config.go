package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// ConfigReport --config 输出的配置快照
//
// 注意：远程配置（cfg.Remote）仅在 Agent 运行期由 Server 通过 gRPC 下发到内存，
// 不持久化到磁盘。独立的 CLI 进程无法读取，因此只显示构建时嵌入 + 文件系统快照。
type ConfigReport struct {
	BuildVersion  string `json:"build_version"`
	BuildTime     string `json:"build_time"`
	ServerHost    string `json:"server_host"`
	WorkDir       string `json:"work_dir"`
	LogFile       string `json:"log_file"`
	IDFile        string `json:"id_file"`
	AgentID       string `json:"agent_id"`
	CertDir       string `json:"cert_dir"`
	HasCertBundle bool   `json:"has_cert_bundle"`
}

// RunConfig 执行 --config 子命令
func RunConfig(opts CommonOptions, out io.Writer) error {
	r := collectConfig(opts)
	if opts.JSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(r)
	}
	_, err := io.WriteString(out, formatConfigText(r))
	return err
}

func collectConfig(opts CommonOptions) *ConfigReport {
	certDir := DefaultWorkDir + "/certs"
	return &ConfigReport{
		BuildVersion:  versionString(opts.BuildVersion),
		BuildTime:     opts.BuildTime,
		ServerHost:    opts.ServerHost,
		WorkDir:       DefaultWorkDir,
		LogFile:       DefaultLogFile,
		IDFile:        DefaultIDFile,
		AgentID:       readFileTrim(DefaultIDFile),
		CertDir:       certDir,
		HasCertBundle: hasCertBundle(certDir),
	}
}

func hasCertBundle(dir string) bool {
	for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
		if _, err := readFile(dir + "/" + name); err != nil {
			return false
		}
	}
	return true
}

func formatConfigText(r *ConfigReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "mxcwpp-agent config\n")
	fmt.Fprintf(&b, "  Build version: %s\n", r.BuildVersion)
	if r.BuildTime != "" {
		fmt.Fprintf(&b, "  Build time:    %s\n", r.BuildTime)
	}
	fmt.Fprintf(&b, "  Server:        %s\n", emptyDash(r.ServerHost))
	fmt.Fprintf(&b, "  Work dir:      %s\n", r.WorkDir)
	fmt.Fprintf(&b, "  Log file:      %s\n", r.LogFile)
	fmt.Fprintf(&b, "  ID file:       %s\n", r.IDFile)
	fmt.Fprintf(&b, "  Agent ID:      %s\n", emptyDash(r.AgentID))
	fmt.Fprintf(&b, "  Cert dir:      %s (bundle: %s)\n", r.CertDir, boolYesNo(r.HasCertBundle))
	fmt.Fprintf(&b, "\n注: 远程配置由 Server 运行时下发，不持久化到磁盘，故此处不显示。\n")
	return b.String()
}
