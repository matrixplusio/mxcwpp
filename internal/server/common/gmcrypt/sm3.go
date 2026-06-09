// Package gmcrypt 实现国密 SM2/SM3/SM4 算法 (P3-12).
//
// 信创合规要求商用密码 (国家密码管理局发布):
//
//	SM2 — 椭圆曲线非对称 (替代 RSA/ECDSA)
//	SM3 — 杂凑算法 256-bit (替代 SHA-256)
//	SM4 — 分组密码 128-bit (替代 AES-128)
//
// 设计:
//   - 纯 Go 实现, 不依赖 cgo
//   - 接口同 crypto/hash + crypto/cipher 习惯
//   - 后续可替换为 GmSSL/铜锁 等 cgo binding (性能 3-5x)
//
// 参考: GB/T 32905-2016 SM3, GB/T 32907-2016 SM4
package gmcrypt

import (
	"encoding/binary"
	"hash"
)

// SM3 杂凑算法实现.

const (
	sm3BlockSize = 64
	sm3Size      = 32
)

// IV 初始值 (GB/T 32905-2016 5.3.1).
var sm3IV = [8]uint32{
	0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600,
	0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E,
}

// digest SM3 状态.
type digest struct {
	state [8]uint32
	buf   [sm3BlockSize]byte
	nx    int
	len   uint64
}

// NewSM3 返回新 SM3 hasher.
func NewSM3() hash.Hash {
	d := &digest{}
	d.Reset()
	return d
}

// Reset 重置状态.
func (d *digest) Reset() {
	d.state = sm3IV
	d.nx = 0
	d.len = 0
}

// Size 输出大小 32 字节.
func (d *digest) Size() int { return sm3Size }

// BlockSize 块大小 64 字节.
func (d *digest) BlockSize() int { return sm3BlockSize }

// Write 写入数据.
func (d *digest) Write(p []byte) (int, error) {
	n := len(p)
	d.len += uint64(n)
	if d.nx > 0 {
		k := copy(d.buf[d.nx:], p)
		d.nx += k
		if d.nx == sm3BlockSize {
			d.block(d.buf[:])
			d.nx = 0
		}
		p = p[k:]
	}
	for len(p) >= sm3BlockSize {
		d.block(p[:sm3BlockSize])
		p = p[sm3BlockSize:]
	}
	if len(p) > 0 {
		copy(d.buf[:], p)
		d.nx = len(p)
	}
	return n, nil
}

// Sum 末态 hash.
func (d *digest) Sum(b []byte) []byte {
	// 复制状态避免改变
	d2 := *d
	hash := d2.checkSum()
	return append(b, hash[:]...)
}

func (d *digest) checkSum() [sm3Size]byte {
	// 填充: 0x80 + 0...0 + 64-bit length
	bitLen := d.len * 8
	d.buf[d.nx] = 0x80
	d.nx++
	if d.nx > 56 {
		for i := d.nx; i < sm3BlockSize; i++ {
			d.buf[i] = 0
		}
		d.block(d.buf[:])
		d.nx = 0
	}
	for i := d.nx; i < 56; i++ {
		d.buf[i] = 0
	}
	binary.BigEndian.PutUint64(d.buf[56:], bitLen)
	d.block(d.buf[:])

	var out [sm3Size]byte
	for i := 0; i < 8; i++ {
		binary.BigEndian.PutUint32(out[i*4:], d.state[i])
	}
	return out
}

// block 处理单个 64 字节块.
func (d *digest) block(p []byte) {
	var w [68]uint32
	var w1 [64]uint32

	for i := 0; i < 16; i++ {
		w[i] = binary.BigEndian.Uint32(p[i*4:])
	}
	for i := 16; i < 68; i++ {
		w[i] = p1(w[i-16]^w[i-9]^rotl(w[i-3], 15)) ^ rotl(w[i-13], 7) ^ w[i-6]
	}
	for i := 0; i < 64; i++ {
		w1[i] = w[i] ^ w[i+4]
	}

	A, B, C, D := d.state[0], d.state[1], d.state[2], d.state[3]
	E, F, G, H := d.state[4], d.state[5], d.state[6], d.state[7]

	for j := 0; j < 64; j++ {
		t := uint32(0x79CC4519)
		if j >= 16 {
			t = 0x7A879D8A
		}
		ss1 := rotl(rotl(A, 12)+E+rotl(t, j%32), 7)
		ss2 := ss1 ^ rotl(A, 12)
		var tt1, tt2 uint32
		if j < 16 {
			tt1 = ffj0(A, B, C) + D + ss2 + w1[j]
			tt2 = ggj0(E, F, G) + H + ss1 + w[j]
		} else {
			tt1 = ffj1(A, B, C) + D + ss2 + w1[j]
			tt2 = ggj1(E, F, G) + H + ss1 + w[j]
		}
		D = C
		C = rotl(B, 9)
		B = A
		A = tt1
		H = G
		G = rotl(F, 19)
		F = E
		E = p0(tt2)
	}
	d.state[0] ^= A
	d.state[1] ^= B
	d.state[2] ^= C
	d.state[3] ^= D
	d.state[4] ^= E
	d.state[5] ^= F
	d.state[6] ^= G
	d.state[7] ^= H
}

// 辅助函数 (GB/T 32905-2016 5.2)

func rotl(x uint32, n int) uint32 {
	n = n % 32
	return (x << n) | (x >> (32 - n))
}

func ffj0(x, y, z uint32) uint32 { return x ^ y ^ z }
func ffj1(x, y, z uint32) uint32 { return (x & y) | (x & z) | (y & z) }
func ggj0(x, y, z uint32) uint32 { return x ^ y ^ z }
func ggj1(x, y, z uint32) uint32 { return (x & y) | (^x & z) }

func p0(x uint32) uint32 { return x ^ rotl(x, 9) ^ rotl(x, 17) }
func p1(x uint32) uint32 { return x ^ rotl(x, 15) ^ rotl(x, 23) }

// SumSM3 便捷函数: 一次性计算 SM3.
func SumSM3(data []byte) [sm3Size]byte {
	d := &digest{}
	d.Reset()
	_, _ = d.Write(data)
	return d.checkSum()
}
