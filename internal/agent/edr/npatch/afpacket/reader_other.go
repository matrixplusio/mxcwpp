//go:build !linux

package afpacket

import (
	"errors"
	"time"
)

type Config struct {
	Interface string
	BlockSize int
	NumBlocks int
	FrameSize int
	Timeout   time.Duration
	Promisc   bool
	Filter    []byte
}

type Packet struct {
	Data      []byte
	Timestamp time.Time
	IfaceIdx  int
	Protocol  uint16
	Truncated bool
}

type Reader struct{}

func NewReader(_ Config) (*Reader, error) {
	return nil, errors.New("afpacket: linux only")
}

func (r *Reader) Packets() <-chan Packet  { return nil }
func (r *Reader) Stats() (uint64, uint64) { return 0, 0 }
func (r *Reader) Close() error            { return nil }

func BuildHTTPFilter() []byte { return nil }
