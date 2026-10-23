package sanitize

import "testing"

// 每条进程事件都要过一遍，盯住常见命令行的开销。
func BenchmarkCmdlineTypical(b *testing.B) {
	s := "/usr/bin/python3 /opt/app/worker.py --config /etc/app/worker.yaml --log-level info --workers 4"
	for i := 0; i < b.N; i++ {
		Cmdline(s)
	}
}
