// Package cli 实现 Agent 辅助命令行子功能（--status / --logs / --config / --diag）
//
// 这些子命令独立于 Agent 服务主路径，由 cmd/agent/main.go 在 flag.Parse 后早返回，
// 不启动心跳、连接管理等模块。
package cli

const (
	// DefaultLogFile Agent 默认日志路径（与 cmd/agent/main.go logger.Init 对齐）
	DefaultLogFile = "/var/log/mxcwpp-agent/agent.log"
	// DefaultLogDir Agent 日志目录（轮转后的历史文件位于此处）
	DefaultLogDir = "/var/log/mxcwpp-agent"
	// DefaultIDFile Agent ID 文件
	DefaultIDFile = "/var/lib/mxcwpp-agent/agent_id"
	// DefaultWorkDir Agent 工作目录
	DefaultWorkDir = "/var/lib/mxcwpp-agent"
	// SystemdUnit systemd 单元名
	SystemdUnit = "mxcwpp-agent"
)

// CommonOptions 各子命令共享的元数据（构建时嵌入值）
type CommonOptions struct {
	BuildVersion string // 构建时嵌入版本（main.buildVersion）
	BuildTime    string // 构建时间
	ServerHost   string // 构建时嵌入 Server gRPC 地址
	JSON         bool   // 输出 JSON 格式
}

// versionString 在版本为空时返回 "dev"，与 main.printVersion 一致
func versionString(v string) string {
	if v == "" {
		return "dev"
	}
	return v
}

// readFileTrim 读文件并裁掉末尾换行，找不到返回 ""
func readFileTrim(path string) string {
	b, err := readFile(path)
	if err != nil {
		return ""
	}
	for len(b) > 0 && (b[len(b)-1] == '\n' || b[len(b)-1] == '\r') {
		b = b[:len(b)-1]
	}
	return string(b)
}
