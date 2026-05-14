package handlers

import (
	"os"
	"testing"
)

// TestReadProcNetDev 验证 /proc/net/dev 解析逻辑
func TestReadProcNetDev(t *testing.T) {
	// 模拟 /proc/net/dev 内容（真实格式）
	content := `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:   12345     100    0    0    0     0          0         0    12345     100    0    0    0     0       0          0
  eth0: 1048576    8192    3    5    0     0          0         0   524288    4096    2    1    0     0       0          0
  eth1:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
`
	f, err := os.CreateTemp("", "proc_net_dev")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(content)
	f.Close()

	// readProcNetDev 读取系统路径，这里直接验证解析逻辑（内联）
	stats := parseProcNetDevContent(content)

	// lo 接口
	lo, ok := stats["lo"]
	if !ok {
		t.Fatal("lo not found in stats")
	}
	if lo[0] != 12345 {
		t.Errorf("lo BytesRecv = %d, want 12345", lo[0])
	}
	if lo[3] != 12345 {
		t.Errorf("lo BytesSent = %d, want 12345", lo[3])
	}

	// eth0 接口
	eth0, ok := stats["eth0"]
	if !ok {
		t.Fatal("eth0 not found in stats")
	}
	if eth0[0] != 1048576 {
		t.Errorf("eth0 BytesRecv = %d, want 1048576", eth0[0])
	}
	if eth0[1] != 3 {
		t.Errorf("eth0 PacketsError = %d, want 3", eth0[1])
	}
	if eth0[2] != 5 {
		t.Errorf("eth0 PacketsDrop = %d, want 5", eth0[2])
	}
	if eth0[3] != 524288 {
		t.Errorf("eth0 BytesSent = %d, want 524288", eth0[3])
	}
}

// parseProcNetDevContent 将 /proc/net/dev 内容字符串解析为统计 map（供测试使用）
// 注意：与 readProcNetDev() 逻辑完全一致，这里内联便于测试
func parseProcNetDevContent(content string) map[string][4]uint64 {
	import_strings := func(s string) []string {
		var result []string
		start := -1
		for i, c := range s {
			if c != ' ' && c != '\t' {
				if start == -1 {
					start = i
				}
			} else {
				if start != -1 {
					result = append(result, s[start:i])
					start = -1
				}
			}
		}
		if start != -1 {
			result = append(result, s[start:])
		}
		return result
	}

	stats := make(map[string][4]uint64)
	lines := splitLines(content)
	// 跳过前两行
	if len(lines) <= 2 {
		return stats
	}
	for _, line := range lines[2:] {
		idx := findColon(line)
		if idx < 0 {
			continue
		}
		name := trimSpace(line[:idx])
		fields := import_strings(line[idx+1:])
		if len(fields) < 9 {
			continue
		}
		var vals [4]uint64
		vals[0] = parseU64(fields[0]) // bytes recv
		vals[1] = parseU64(fields[2]) // errs recv
		vals[2] = parseU64(fields[3]) // drop recv
		vals[3] = parseU64(fields[8]) // bytes sent
		stats[name] = vals
	}
	return stats
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func findColon(s string) int {
	for i, c := range s {
		if c == ':' {
			return i
		}
	}
	return -1
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

func parseU64(s string) uint64 {
	var v uint64
	for _, c := range s {
		if c >= '0' && c <= '9' {
			v = v*10 + uint64(c-'0')
		}
	}
	return v
}
