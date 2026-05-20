package biz

import (
	"strings"
)

// diagnosisRule 错误诊断规则
type diagnosisRule struct {
	Keywords  []string // stderr/stdout 中匹配的关键词（任一匹配即命中）
	Diagnosis string   // 中文诊断提示
}

// diagnosisRules 常见修复失败的错误模式及诊断
var diagnosisRules = []diagnosisRule{
	{
		Keywords:  []string{"No package", "No match for argument", "Error: Nothing to do"},
		Diagnosis: "软件包在当前源中不存在。请检查 yum/dnf 源配置是否包含该包，或确认包名和版本号是否正确。",
	},
	{
		Keywords:  []string{"Unable to locate package", "E: Unable to locate"},
		Diagnosis: "apt 源中找不到该包。请先执行 apt-get update 刷新索引，或检查 sources.list 配置。",
	},
	{
		Keywords:  []string{"Could not resolve host", "Cannot retrieve", "Could not retrieve", "Failed to download", "Couldn't resolve host"},
		Diagnosis: "无法连接软件源，可能是网络问题或 DNS 解析失败。请检查主机网络连通性和源地址配置。",
	},
	{
		Keywords:  []string{"Nothing to do", "already the newest version", "already installed and latest version"},
		Diagnosis: "当前版本已是最新或与目标版本一致，无需升级。如仍存在漏洞风险，请确认目标修复版本是否正确。",
	},
	{
		Keywords:  []string{"Depsolve Error", "dependency problems", "unmet dependencies", "requires:", "conflicts with"},
		Diagnosis: "存在依赖冲突，无法自动解决。请人工登录主机排查依赖关系，或考虑使用 --skip-broken 等选项。",
	},
	{
		Keywords:  []string{"Permission denied", "needs to be root", "Operation not permitted", "Access denied"},
		Diagnosis: "权限不足。请确认 Agent 以 root 权限运行，或检查目标文件/目录的权限设置。",
	},
	{
		Keywords:  []string{"Disk quota exceeded", "No space left on device"},
		Diagnosis: "磁盘空间不足，无法完成安装。请清理磁盘空间后重试。",
	},
	{
		Keywords:  []string{"command not found"},
		Diagnosis: "包管理器命令未找到。请确认主机上已安装对应的包管理工具（yum/dnf/apt-get）。",
	},
	{
		Keywords:  []string{"Repository not found", "repo not found", "404 Not Found", "repodata", "Failed to synchronize cache"},
		Diagnosis: "软件源仓库地址无效或已失效（404）。请检查 repo 配置文件中的 baseurl 是否可访问。",
	},
	{
		Keywords:  []string{"GPG check FAILED", "Public key", "GPG key", "signature could not be verified"},
		Diagnosis: "GPG 签名校验失败。请导入对应的 GPG 公钥，或确认源的签名配置。",
	},
	{
		Keywords:  []string{"Could not get lock", "another process", "waiting for lock"},
		Diagnosis: "包管理器被其他进程锁定。请检查是否有其他 yum/dnf/apt 进程正在运行，待其完成后重试。",
	},
	{
		Keywords:  []string{"命令执行超时"},
		Diagnosis: "命令执行超时（超过 10 分钟）。可能是网络下载缓慢或包体过大，请检查网络后重试。",
	},
}

// DiagnoseError 分析修复失败的输出，返回中文诊断信息
// 如果无法匹配任何已知模式，返回空字符串
func DiagnoseError(stdout, stderr string) string {
	combined := stdout + "\n" + stderr
	combinedLower := strings.ToLower(combined)

	for _, rule := range diagnosisRules {
		for _, keyword := range rule.Keywords {
			if strings.Contains(combinedLower, strings.ToLower(keyword)) {
				return rule.Diagnosis
			}
		}
	}

	return ""
}
