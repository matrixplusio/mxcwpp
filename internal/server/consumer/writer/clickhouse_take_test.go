package writer

import "testing"

// 取走的批次不能再被后来写入的行改动。
//
// 取走之后、写入 ClickHouse 之前，新的行会继续追加进缓冲。两者共用底层数组的话，
// 新行会覆盖还没写出去的旧行：旧的丢失，新的入库两次。
func TestTakeRowsDetachesBatch(t *testing.T) {
	buf := make([]int, 0, 8)
	buf = append(buf, 1, 2, 3)

	taken := takeRows(&buf, 4)
	if len(buf) != 0 || cap(buf) != 4 {
		t.Fatalf("取走后缓冲应为空、容量按给定值：len=%d cap=%d", len(buf), cap(buf))
	}
	buf = append(buf, 7, 8, 9)

	if len(taken) != 3 || taken[0] != 1 || taken[1] != 2 || taken[2] != 3 {
		t.Fatalf("取走的批次被后来的写入改了：%v", taken)
	}
	if buf[0] != 7 {
		t.Fatalf("新缓冲内容不对：%v", buf)
	}
}

// 空的缓冲不换数组：空刷盘很频繁，每次都分配是白费。
func TestTakeRowsLeavesEmptyBufferAlone(t *testing.T) {
	buf := make([]int, 0, 8)
	if taken := takeRows(&buf, 4); taken != nil || cap(buf) != 8 {
		t.Fatalf("空缓冲不该被换掉：taken=%v cap=%d", taken, cap(buf))
	}
}
