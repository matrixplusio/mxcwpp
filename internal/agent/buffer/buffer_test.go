package buffer

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/imkerbos/mxsec-platform/api/proto/grpc"
)

func makeRecord(dataType int32) *grpc.EncodedRecord {
	return &grpc.EncodedRecord{
		DataType:  dataType,
		Timestamp: 1000,
		Data:      []byte("test"),
	}
}

func TestWriteAndReadAll(t *testing.T) {
	rb := New()

	// 写入 100 条
	for i := 0; i < 100; i++ {
		ok := rb.WriteEncodedRecord(makeRecord(int32(i)))
		assert.True(t, ok)
	}

	assert.Equal(t, 100, rb.Len())

	// 批量读取
	records := rb.ReadAll()
	require.Len(t, records, 100)
	for i, rec := range records {
		assert.Equal(t, int32(i), rec.DataType)
	}

	// 读取后缓冲区为空
	assert.Equal(t, 0, rb.Len())
	assert.Nil(t, rb.ReadAll())
}

func TestReadAllEmpty(t *testing.T) {
	rb := New()
	records := rb.ReadAll()
	assert.Nil(t, records)
	assert.Equal(t, 0, rb.Len())
}

func TestWriteEncodedRecord_Overflow(t *testing.T) {
	rb := New()

	// 写满 2048 条
	for i := 0; i < BufSize; i++ {
		ok := rb.WriteEncodedRecord(makeRecord(int32(i)))
		assert.True(t, ok)
	}

	assert.Equal(t, BufSize, rb.Len())

	// 第 2049 条应被丢弃
	ok := rb.WriteEncodedRecord(makeRecord(9999))
	assert.False(t, ok)
	assert.Equal(t, uint64(1), rb.OverflowCount())

	// 缓冲区仍然是 2048 条，且不包含被丢弃的数据
	records := rb.ReadAll()
	require.Len(t, records, BufSize)
	assert.Equal(t, int32(0), records[0].DataType)
	assert.Equal(t, int32(BufSize-1), records[BufSize-1].DataType)
}

func TestWriteRecord_Overflow(t *testing.T) {
	rb := New()

	// 写满 2048 条
	for i := 0; i < BufSize; i++ {
		rb.WriteRecord(makeRecord(int32(i)))
	}

	assert.Equal(t, BufSize, rb.Len())

	// 心跳数据满溢时覆盖 buf[0]
	rb.WriteRecord(makeRecord(9999))
	assert.Equal(t, uint64(1), rb.OverflowCount())

	records := rb.ReadAll()
	require.Len(t, records, BufSize)
	// buf[0] 应被覆盖为 9999
	assert.Equal(t, int32(9999), records[0].DataType)
	// buf[1] 仍是原来的 1
	assert.Equal(t, int32(1), records[1].DataType)
}

func TestClear(t *testing.T) {
	rb := New()

	for i := 0; i < 500; i++ {
		rb.WriteEncodedRecord(makeRecord(int32(i)))
	}
	assert.Equal(t, 500, rb.Len())

	rb.Clear()
	assert.Equal(t, 0, rb.Len())
	assert.Nil(t, rb.ReadAll())
}

func TestOverflowCountReset(t *testing.T) {
	rb := New()

	// 写满并溢出 5 次
	for i := 0; i < BufSize+5; i++ {
		rb.WriteEncodedRecord(makeRecord(int32(i)))
	}
	assert.Equal(t, uint64(5), rb.OverflowCount())

	// 重置
	n := rb.ResetOverflowCount()
	assert.Equal(t, uint64(5), n)
	assert.Equal(t, uint64(0), rb.OverflowCount())
}

func TestConcurrentSafety(t *testing.T) {
	rb := New()
	var writerWg sync.WaitGroup

	// 5 个写入 goroutine（模拟 3 插件 + 1 心跳 + 1 其他）
	writers := 5
	recordsPerWriter := 500
	writerWg.Add(writers)

	for w := 0; w < writers; w++ {
		go func(writerID int) {
			defer writerWg.Done()
			for i := 0; i < recordsPerWriter; i++ {
				rec := makeRecord(int32(writerID*1000 + i))
				if writerID == 0 {
					// 模拟心跳写入
					rb.WriteRecord(rec)
				} else {
					rb.WriteEncodedRecord(rec)
				}
			}
		}(w)
	}

	// 1 个读取 goroutine（模拟 sendData ticker）
	var totalRead int
	stopReader := make(chan struct{})
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			records := rb.ReadAll()
			if records != nil {
				totalRead += len(records)
			}
			select {
			case <-stopReader:
				// 最后再读一次，确保清空
				if remaining := rb.ReadAll(); remaining != nil {
					totalRead += len(remaining)
				}
				return
			default:
			}
		}
	}()

	writerWg.Wait()
	close(stopReader)
	<-readerDone // 等待 reader goroutine 完全退出后再访问 totalRead

	// 由于并发 + 满溢丢弃，读取总数 <= 写入总数
	totalWritten := writers * recordsPerWriter
	t.Logf("written=%d, read=%d, overflow=%d", totalWritten, totalRead, rb.OverflowCount())
	assert.LessOrEqual(t, totalRead, totalWritten)
	assert.Equal(t, 0, rb.Len()) // 最终缓冲区应为空
}

func TestMultipleReadAllCycles(t *testing.T) {
	rb := New()

	// 模拟多个 ticker 周期
	for cycle := 0; cycle < 10; cycle++ {
		// 每周期写入 50 条
		for i := 0; i < 50; i++ {
			rb.WriteEncodedRecord(makeRecord(int32(cycle*100 + i)))
		}

		records := rb.ReadAll()
		require.Len(t, records, 50, fmt.Sprintf("cycle %d", cycle))

		// 读取后缓冲区为空
		assert.Equal(t, 0, rb.Len())
	}
}

func BenchmarkWriteEncodedRecord(b *testing.B) {
	rb := New()
	rec := makeRecord(1000)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		rb.WriteEncodedRecord(rec)
		if rb.Len() >= BufSize-1 {
			rb.ReadAll()
		}
	}
}

func BenchmarkReadAll(b *testing.B) {
	rb := New()
	// 预填充
	for i := 0; i < 100; i++ {
		rb.WriteEncodedRecord(makeRecord(int32(i)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rb.ReadAll()
		// 重新填充
		for j := 0; j < 100; j++ {
			rb.WriteEncodedRecord(makeRecord(int32(j)))
		}
	}
}

func BenchmarkConcurrentWriteRead(b *testing.B) {
	rb := New()
	rec := makeRecord(1000)

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			rb.WriteEncodedRecord(rec)
			if rb.Len() >= 100 {
				rb.ReadAll()
			}
		}
	})
}
