package compressor

import (
	"bytes"
	"fmt"
	"io"
	"sync"
	"testing"

	"google.golang.org/grpc/encoding"
)

func get(t *testing.T) encoding.Compressor {
	t.Helper()
	c := encoding.GetCompressor(Name)
	if c == nil {
		t.Fatalf("压缩器 %q 未注册", Name)
	}
	return c
}

// TestRoundTrip 压缩后解压必须还原原始字节。
func TestRoundTrip(t *testing.T) {
	c := get(t)
	payload := bytes.Repeat([]byte("agent-event-payload;"), 500)

	var buf bytes.Buffer
	w, err := c.Compress(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := c.Decompress(&buf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("还原后与原始数据不一致: %d 字节 vs %d 字节", len(got), len(payload))
	}
}

// TestReadAfterEOFDoesNotDoublePool 读到 EOF 之后再读一次，
// 不得把同一个 reader 二次放回池中。
//
// io.Reader 允许调用方在 EOF 之后继续调用 Read，仍返回 EOF。
// 若每次 EOF 都执行一次 Put，同一个 reader 会在池里出现两份，
// 于是两个并发的 gRPC 流会拿到同一个对象——一个流的 Reset
// 会把另一个流的数据源换掉，表现为随机的解压失败或串包。
func TestReadAfterEOFDoesNotDoublePool(t *testing.T) {
	c := get(t)

	var buf bytes.Buffer
	w, _ := c.Compress(&buf)
	_, _ = w.Write([]byte("x"))
	_ = w.Close()

	r, err := c.Decompress(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(r); err != nil {
		t.Fatal(err)
	}

	// 此时 r 已因 EOF 入池。再读一次——这是合法调用。
	p := make([]byte, 1)
	_, _ = r.Read(p)
	_, _ = r.Read(p)

	// 池里若有重复对象，连续 Get 会拿到同一个指针。
	seen := map[any]int{}
	for i := 0; i < 8; i++ {
		got, err := c.Decompress(bytes.NewReader(nil))
		if err != nil {
			t.Fatal(err)
		}
		seen[got]++
	}
	for obj, n := range seen {
		if n > 1 {
			t.Fatalf("同一个 reader %p 被取出 %d 次——它在池中存在多份副本，"+
				"并发流之间会互相覆盖数据源", obj, n)
		}
	}
}

// TestCloseTwiceDoesNotDoublePool 重复 Close 不得把同一个 writer 放回池两次。
//
// 与 reader 同一类隐患：池里出现重复对象后，两个并发流会写进同一个 writer，
// 输出互相穿插，接收端解压得到的是两条消息的混合。
func TestCloseTwiceDoesNotDoublePool(t *testing.T) {
	c := get(t)

	var buf bytes.Buffer
	w, err := c.Compress(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	seen := map[any]int{}
	for i := 0; i < 8; i++ {
		got, err := c.Compress(io.Discard)
		if err != nil {
			t.Fatal(err)
		}
		seen[got]++
	}
	for obj, n := range seen {
		if n > 1 {
			t.Fatalf("同一个 writer %p 被取出 %d 次——池中存在重复副本，"+
				"并发流的输出会互相穿插", obj, n)
		}
	}
}

// TestWriteAfterCloseIsRejected Close 之后再写必须报错，而不是 panic，
// 也不是悄悄写进一个已归还的 writer。
func TestWriteAfterCloseIsRejected(t *testing.T) {
	c := get(t)

	var buf bytes.Buffer
	w, _ := c.Compress(&buf)
	if _, err := w.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("second")); err == nil {
		t.Fatal("Close 之后写入返回了 nil error——调用方会以为数据已发出")
	}
}

// TestConcurrentStreamsDoNotShareBuffers 并发压缩/解压各自还原自己的数据。
//
// 池复用一旦出错，症状就是这里：A 流解出 B 流的内容。
func TestConcurrentStreamsDoNotShareBuffers(t *testing.T) {
	c := get(t)
	const n = 32

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			want := bytes.Repeat([]byte{byte(i)}, 4096)

			var buf bytes.Buffer
			w, err := c.Compress(&buf)
			if err != nil {
				errs <- err
				return
			}
			if _, err := w.Write(want); err != nil {
				errs <- err
				return
			}
			if err := w.Close(); err != nil {
				errs <- err
				return
			}

			r, err := c.Decompress(&buf)
			if err != nil {
				errs <- err
				return
			}
			got, err := io.ReadAll(r)
			if err != nil {
				errs <- err
				return
			}
			if !bytes.Equal(got, want) {
				errs <- fmt.Errorf("流 %d 还原出的数据不是自己写入的", i)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
