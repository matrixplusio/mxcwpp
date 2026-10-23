package rasp

// Python RASP 检测扩展 (Sprint 4 PR71).
//
// Agent 端 sys.settrace + PEP 578 audit hooks 监控:
//   - exec / eval / compile     → 代码执行
//   - os.system / subprocess    → shell 调用
//   - importlib.import_module   → 动态导入恶意模块
//   - pickle.loads              → 反序列化攻击
//   - open(..., 'w')            → 向 web 根写 webshell
//
// 仍严格 read-only: 仅采集 + 上报, 不抛异常打断 Python 进程。

// PythonDangerousAudits 是 PEP 578 audit event → 风险描述映射。
//
// 参考 https://docs.python.org/3/library/audit_events.html
var PythonDangerousAudits = map[string]string{
	"exec":                "code 对象执行",
	"compile":             "代码编译 (常见动态代码生成)",
	"subprocess.Popen":    "子进程创建",
	"os.system":           "shell 调用",
	"os.exec":             "execve 系列",
	"os.spawn":            "spawn 系列",
	"socket.connect":      "出站连接 (反弹 shell 关注)",
	"socket.bind":         "监听端口 (后门关注)",
	"pickle.find_class":   "pickle 反序列化",
	"marshal.loads":       "marshal 反序列化",
	"importlib.find_spec": "动态导入",
	"urllib.Request":      "出站 HTTP",
	"open":                "文件打开 (写模式时关注)",
}

// PythonSuspiciousImport 检测可疑动态 import。
func PythonSuspiciousImport(moduleName string) string {
	suspect := []string{
		"ctypes",   // 直接调 libc
		"resource", // 资源限制操作
		"pty",      // 伪终端 (反弹 shell)
		"telnetlib",
		"paramiko",
		"crypt",
	}
	for _, s := range suspect {
		if moduleName == s {
			return "suspect_dynamic_import:" + s
		}
	}
	return ""
}

// PythonReverseShellPattern 检测反弹 shell 经典代码模式。
//
// 命中模式: socket+os.dup2+pty.spawn /bin/sh
func PythonReverseShellPattern(stack []string) bool {
	hasSocket, hasDup2, hasPtySpawn := false, false, false
	for _, frame := range stack {
		switch {
		case containsCaseInsensitive(frame, "socket.socket"):
			hasSocket = true
		case containsCaseInsensitive(frame, "os.dup2"):
			hasDup2 = true
		case containsCaseInsensitive(frame, "pty.spawn"),
			containsCaseInsensitive(frame, "subprocess.call"),
			containsCaseInsensitive(frame, "os.system"):
			hasPtySpawn = true
		}
	}
	return hasSocket && hasDup2 && hasPtySpawn
}
