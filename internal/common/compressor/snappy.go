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
		return &writer{
			Writer: snappy.NewBufferedWriter(io.Discard),
			pool:   &c.writerPool,
		}
	}
	c.readerPool.New = func() any {
		return &reader{
			Reader: snappy.NewReader(nil),
			pool:   &c.readerPool,
		}
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
	wr := c.writerPool.Get().(*writer)
	wr.Writer.Reset(w)
	return wr, nil
}

func (c *compressor) Decompress(r io.Reader) (io.Reader, error) {
	rd := c.readerPool.Get().(*reader)
	rd.Reader.Reset(r)
	return rd, nil
}

// writer wraps snappy.Writer with pool return on Close
type writer struct {
	*snappy.Writer
	pool *sync.Pool
}

func (w *writer) Close() error {
	err := w.Writer.Close()
	w.Writer.Reset(io.Discard)
	w.pool.Put(w)
	return err
}

// reader wraps snappy.Reader with pool return on EOF
type reader struct {
	*snappy.Reader
	pool *sync.Pool
}

func (r *reader) Read(p []byte) (n int, err error) {
	n, err = r.Reader.Read(p)
	if err == io.EOF {
		r.Reader.Reset(nil)
		r.pool.Put(r)
	}
	return n, err
}
