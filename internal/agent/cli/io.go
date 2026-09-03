package cli

import "os"

// readFile 包装 os.ReadFile，便于测试时替换
var readFile = func(path string) ([]byte, error) {
	return os.ReadFile(path)
}
