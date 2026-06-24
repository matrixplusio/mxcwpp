package rasp

// PHP RASP 检测扩展 (Sprint 4 PR71).
//
// Agent 端 Zend extension (libmxcwpp_rasp_php.so) hook:
//   - zend_compile_string  → 检测 eval/assert 动态执行
//   - php_execute_internal → 检测 system/exec/shell_exec/passthru/popen/proc_open
//   - include/require      → 检测 LFI/RFI (远程 URL include)
//   - file_put_contents    → 检测向 web 根目录写 .php
//
// 仍严格 read-only: 只采集 + 上报, 不阻断 PHP 执行流。

// PHPDangerousFunctions 是 PHP 常见命令执行/代码执行函数集。
var PHPDangerousFunctions = map[string]string{
	"eval":               "动态代码执行",
	"assert":             "断言注入 (assert(\\$user_input))",
	"system":             "shell 调用",
	"exec":               "shell 调用",
	"shell_exec":         "反引号等效",
	"passthru":           "shell 调用",
	"popen":              "管道 shell",
	"proc_open":          "进程创建",
	"pcntl_exec":         "fork+exec",
	"create_function":    "代码注入向量 (已废弃但仍存在)",
	"preg_replace":       "/e modifier 代码执行 (PHP < 7)",
	"include":            "可能 LFI/RFI",
	"include_once":       "可能 LFI/RFI",
	"require":            "可能 LFI/RFI",
	"require_once":       "可能 LFI/RFI",
	"file_put_contents":  "向 web 根写 webshell",
	"fwrite":             "向 web 根写 webshell",
	"move_uploaded_file": "上传组件",
}

// PHPSuspiciousArgs 检测函数参数中的可疑模式。
//
// 返回非空 → 高度可疑;空 → 正常调用。
func PHPSuspiciousArgs(fn string, args []string) []string {
	var hits []string
	for _, a := range args {
		al := toLower(a)
		switch {
		case containsCaseInsensitive(al, "base64_decode("):
			hits = append(hits, "arg_contains_base64_decode")
		case containsCaseInsensitive(al, "/etc/passwd"),
			containsCaseInsensitive(al, "/proc/self/environ"):
			hits = append(hits, "arg_contains_sensitive_path")
		case containsCaseInsensitive(al, "http://"),
			containsCaseInsensitive(al, "https://"),
			containsCaseInsensitive(al, "ftp://"),
			containsCaseInsensitive(al, "data://"),
			containsCaseInsensitive(al, "php://input"):
			if fn == "include" || fn == "include_once" || fn == "require" || fn == "require_once" {
				hits = append(hits, "rfi_remote_include")
			}
		case containsCaseInsensitive(al, "<?php"),
			containsCaseInsensitive(al, "<?="):
			if fn == "file_put_contents" || fn == "fwrite" {
				hits = append(hits, "webshell_write_attempt")
			}
		}
	}
	return hits
}
