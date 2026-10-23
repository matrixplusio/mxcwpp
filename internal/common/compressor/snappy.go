// Package compressor 提供 gRPC 流压缩支持
//
// 参考 Elkeid agent/transport/compressor/snappy.go 设计：
// 通过 gRPC encoding.RegisterCompressor 注册 Snappy 压缩器，
// 使用 sync.Pool 复用 writer/reader 减少 GC 压力。
//
// 使用方式：
//
//	Agent 端: import _ "github.com/matrixplusio/mxcwpp/internal/common/compressor"
//	          client.Transfer(ctx, grpc.UseCompressor("snappy"))
//	Server 端: import _ "github.com/matrixplusio/mxcwpp/internal/common/compressor"
//	          （注册解压器，自动协商）
package compressor

import (
	"io"
	"sync"

	"github.com/golang/snappy"
	"google.golang.org/grpc/encoding"
)

const Name = "snappy"

func init() {
	c := &compressor{}
	c.writerPool.New = func() any {
		return snappy.NewBufferedWriter(io.Discard)
	}
	c.readerPool.New = func() any {
		return snappy.NewReader(nil)
	}
	encoding.RegisterCompressor(c)
}

type compressor struct {
	writerPool sync.Pool
	readerPool sync.Pool
}

func (c *compressor) Name() string {
	return Name
}

func (c *compressor) Compress(w io.Writer) (io.WriteCloser, error) {
	wr := c.writerPool.Get().(*snappy.Writer)
	wr.Reset(w)
	return &writer{Writer: wr, pool: &c.writerPool}, nil
}

func (c *compressor) Decompress(r io.Reader) (io.Reader, error) {
	rd := c.readerPool.Get().(*snappy.Reader)
	rd.Reset(r)
	return &reader{Reader: rd, pool: &c.readerPool}, nil
}

// writer 是一次性句柄，语义与 reader 相同：Close 只归还一次。
type writer struct {
	*snappy.Writer
	pool *sync.Pool
}

func (w *writer) Write(p []byte) (int, error) {
	if w.Writer == nil {
		return 0, io.ErrClosedPipe
	}
	return w.Writer.Write(p)
}

func (w *writer) Close() error {
	if w.Writer == nil {
		return nil
	}
	err := w.Writer.Close()
	w.Writer.Reset(io.Discard)
	w.pool.Put(w.Writer)
	w.Writer = nil
	return err
}

// reader 是一次性句柄：它借用池中的 snappy.Reader，读到 EOF 时归还一次。
//
// 句柄本身不入池。若把归还标记放在被复用的对象上，归还之后它可能已被
// 另一个流取走并 Reset 到别的数据源，此时原持有者再读就会读到别人的数据；
// io.Reader 允许在 EOF 之后继续调用 Read，所以这不是假设的调用序列。
type reader struct {
	*snappy.Reader
	pool *sync.Pool
}

func (r *reader) Read(p []byte) (n int, err error) {
	if r.Reader == nil {
		return 0, io.EOF
	}
	n, err = r.Reader.Read(p)
	if err == io.EOF {
		r.Reader.Reset(nil)
		r.pool.Put(r.Reader)
		r.Reader = nil
	}
	return n, err
}
