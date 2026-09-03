//go:build linux

package metrics

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// readRSS 读 /proc/self/status 取 VmRSS (kB).
func readRSS() uint64 {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			kb, _ := strconv.ParseUint(parts[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}

// readFDCount 数 /proc/self/fd 下文件描述符.
func readFDCount() int {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return 0
	}
	return len(entries)
}
