package outbound

// 阿里云 SLS LogGroup protobuf 手工编码 (P4-6).
//
// 替换原 JSON 简化实现, 用官方 protobuf wire 格式提升性能、降带宽.
//
// LogGroup 协议参考 (proto2):
//   message Log {
//     required uint32 Time = 1;
//     repeated Content Contents = 2;
//   }
//   message Content {
//     required string Key = 1;
//     required string Value = 2;
//   }
//   message LogGroup {
//     repeated Log   Logs    = 1;
//     optional string Topic  = 3;
//     optional string Source = 4;
//   }
//
// 手写编码, 不依赖 google.golang.org/protobuf, 避免重型依赖.

import (
	"encoding/binary"
)

const (
	wireVarint = 0
	wireBytes  = 2
)

// slsLogContent 一条 K/V.
type slsLogContent struct {
	Key   string
	Value string
}

// slsLog 一条日志.
type slsLog struct {
	Time     uint32
	Contents []slsLogContent
}

// slsLogGroup 一组日志.
type slsLogGroup struct {
	Logs   []slsLog
	Topic  string
	Source string
}

// Marshal LogGroup → protobuf bytes.
func (g *slsLogGroup) Marshal() []byte {
	var buf []byte
	for i := range g.Logs {
		logBytes := marshalLog(&g.Logs[i])
		buf = appendTag(buf, 1, wireBytes)
		buf = appendVarint(buf, uint64(len(logBytes)))
		buf = append(buf, logBytes...)
	}
	if g.Topic != "" {
		buf = appendTag(buf, 3, wireBytes)
		buf = appendVarint(buf, uint64(len(g.Topic)))
		buf = append(buf, g.Topic...)
	}
	if g.Source != "" {
		buf = appendTag(buf, 4, wireBytes)
		buf = appendVarint(buf, uint64(len(g.Source)))
		buf = append(buf, g.Source...)
	}
	return buf
}

func marshalLog(l *slsLog) []byte {
	var buf []byte
	// Time uint32 — 用 varint 编码
	buf = appendTag(buf, 1, wireVarint)
	buf = appendVarint(buf, uint64(l.Time))
	// Contents
	for i := range l.Contents {
		c := marshalContent(&l.Contents[i])
		buf = appendTag(buf, 2, wireBytes)
		buf = appendVarint(buf, uint64(len(c)))
		buf = append(buf, c...)
	}
	return buf
}

func marshalContent(c *slsLogContent) []byte {
	var buf []byte
	buf = appendTag(buf, 1, wireBytes)
	buf = appendVarint(buf, uint64(len(c.Key)))
	buf = append(buf, c.Key...)
	buf = appendTag(buf, 2, wireBytes)
	buf = appendVarint(buf, uint64(len(c.Value)))
	buf = append(buf, c.Value...)
	return buf
}

func appendTag(buf []byte, field, wireType int) []byte {
	return appendVarint(buf, uint64((field<<3)|wireType))
}

func appendVarint(buf []byte, v uint64) []byte {
	var b [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(b[:], v)
	return append(buf, b[:n]...)
}
