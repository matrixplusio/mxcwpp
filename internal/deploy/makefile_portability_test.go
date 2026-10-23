package deploy

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestMakefileUsesPortableRedirect Makefile 里不得使用 bash 专有的 &> 重定向。
//
// make 默认用 /bin/sh 执行配方。在 Debian/Ubuntu 上那是 dash，它不认 `&>`——
// 会把 `command -v protoc &> /dev/null` 解析成"后台执行 command -v，再重定向"，
// 于是判断恒为假，一个装好的工具被报成没装。
//
// 这个缺陷在 macOS 上看不出来（那里 /bin/sh 是 bash），只有在 Linux CI 上才暴露：
// 六处工具探测全部失效，protoc 明明在 /usr/bin/protoc 也照样报 "protoc not found"。
//
// 可移植写法是 `>/dev/null 2>&1`。
func TestMakefileUsesPortableRedirect(t *testing.T) {
	root := repoRootFromDeploy(t)
	data, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("读取 Makefile 失败: %v", err)
	}

	// 只匹配重定向语义的 &>，不误伤 `a &&  b` 或 shell 里的 `2>&1`
	bashOnly := regexp.MustCompile(`[^&>]&>[^&]`)

	var bad []string
	for i, line := range strings.Split(string(data), "\n") {
		if bashOnly.MatchString(line) {
			bad = append(bad, strings.TrimSpace(line)+"    ← Makefile:"+itoa(i+1))
		}
	}
	if len(bad) > 0 {
		t.Errorf("Makefile 使用了 bash 专有的 &> 重定向，共 %d 处。\n"+
			"make 用 /bin/sh 执行配方，在 dash 上 &> 不是重定向，条件判断会静默失效。\n"+
			"改用 >/dev/null 2>&1。\n\n  %s",
			len(bad), strings.Join(bad, "\n  "))
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
