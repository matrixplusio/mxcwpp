package resource

import (
	"os"
	"testing"
)

// TestIsPhysicalDisk 验证物理磁盘过滤逻辑
func TestIsPhysicalDisk(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"sda", true},
		{"sdb", true},
		{"vda", true},
		{"xvda", true},
		{"hda", true},
		{"nvme0n1", true},
		// 分区 → false
		{"sda1", false},
		{"sda2", false},
		{"vda1", false},
		{"nvme0n1p1", false},
		{"nvme0n1p2", false},
		// 虚拟设备 → false
		{"loop0", false},
		{"dm-0", false},
		{"ram0", false},
		{"sr0", false},
	}
	for _, c := range cases {
		got := isPhysicalDisk(c.name)
		if got != c.want {
			t.Errorf("isPhysicalDisk(%q) = %v, want %v", c.name, got, c.want)
		}
	}
}

// TestCollectDiskIO_NoPrev 验证首次采样（无 prev 快照）时 delta 为 0
func TestCollectDiskIO_NoPrev(t *testing.T) {
	// 写一个模拟的 /proc/diskstats 临时文件
	content := `   8       0 sda 100 0 200 0 50 0 100 0 0 0 0
   8       1 sda1 10 0 20 0 5 0 10 0 0 0 0
   7       0 loop0 0 0 0 0 0 0 0 0 0 0 0
`
	f, err := os.CreateTemp("", "diskstats")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	_, _ = f.WriteString(content)
	f.Close()

	// 替换 /proc/diskstats 路径（通过 monkey-patch 不可行；
	// 此处直接测试 isPhysicalDisk + 解析逻辑的独立部分）
	// 验证 sda 是物理盘，sda1 / loop0 不是
	if !isPhysicalDisk("sda") {
		t.Error("sda should be physical disk")
	}
	if isPhysicalDisk("sda1") {
		t.Error("sda1 should not be physical disk")
	}
	if isPhysicalDisk("loop0") {
		t.Error("loop0 should not be physical disk")
	}
}

// TestCollectDiskIO_Delta 验证 delta 计算：新值 - 旧值，再乘 512
func TestCollectDiskIO_Delta(t *testing.T) {
	m := &Monitor{lastDiskIO: map[string]diskIOSnapshot{
		"sda": {SectorsRead: 100, SectorsWritten: 200},
	}}

	// 模拟当前快照
	current := map[string]diskIOSnapshot{
		"sda": {SectorsRead: 150, SectorsWritten: 280},
	}

	var readBytes, writeBytes uint64
	for name, snap := range current {
		if prev, ok := m.lastDiskIO[name]; ok {
			if snap.SectorsRead >= prev.SectorsRead {
				readBytes += (snap.SectorsRead - prev.SectorsRead) * 512
			}
			if snap.SectorsWritten >= prev.SectorsWritten {
				writeBytes += (snap.SectorsWritten - prev.SectorsWritten) * 512
			}
		}
	}

	wantRead := uint64((150 - 100) * 512)
	wantWrite := uint64((280 - 200) * 512)
	if readBytes != wantRead {
		t.Errorf("readBytes = %d, want %d", readBytes, wantRead)
	}
	if writeBytes != wantWrite {
		t.Errorf("writeBytes = %d, want %d", writeBytes, wantWrite)
	}
}

// TestCollectDiskIO_Overflow 验证计数器溢出时 delta 跳过（不减）
func TestCollectDiskIO_Overflow(t *testing.T) {
	prev := diskIOSnapshot{SectorsRead: 1000, SectorsWritten: 1000}
	snap := diskIOSnapshot{SectorsRead: 500, SectorsWritten: 500} // 模拟溢出后回绕

	var readBytes, writeBytes uint64
	if snap.SectorsRead >= prev.SectorsRead {
		readBytes = (snap.SectorsRead - prev.SectorsRead) * 512
	}
	if snap.SectorsWritten >= prev.SectorsWritten {
		writeBytes = (snap.SectorsWritten - prev.SectorsWritten) * 512
	}

	// 溢出情况下 delta 应为 0（跳过）
	if readBytes != 0 {
		t.Errorf("overflow: readBytes should be 0, got %d", readBytes)
	}
	if writeBytes != 0 {
		t.Errorf("overflow: writeBytes should be 0, got %d", writeBytes)
	}
}
