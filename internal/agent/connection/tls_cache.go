// Package connection — TLS cert + key cache (P1-7/P1-8 性能修复).
//
// 原 loadTLSConfig 每次重连都做:
//   - os.Stat 3 文件
//   - ReadFile + Parse CA / client cert / key
//   - tls.LoadX509KeyPair (重 PEM decode)
//
// 重连频繁场景 (网络抖动 / Agent 升级) 累计 10x 延迟. 本 cache:
//   - 启动 / 重连首次加载, 存 atomic.Value
//   - mtime 比对一次即跳过加载 (60s TTL)
//   - 证书 rotate (Server 下发新证书) 调用 InvalidateTLSCache() 强制重读
package connection

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// tlsCacheEntry 单次缓存的 TLS 证书.
type tlsCacheEntry struct {
	caPool     *x509.CertPool
	clientCert tls.Certificate
	loadedAt   time.Time
	caMtime    time.Time
	certMtime  time.Time
	keyMtime   time.Time
}

var (
	tlsCacheStore atomic.Pointer[tlsCacheEntry]
	tlsCacheMu    sync.Mutex
)

// tlsCacheTTL 缓存命中 TTL — 即便 mtime 没变也至少每分钟重读 1 次, 防 inode 复用 bug.
const tlsCacheTTL = 60 * time.Second

// loadTLSWithCache P1-8: 走 cache 加载 CA + client cert/key.
//
// 命中条件: caFile/certFile/keyFile mtime 都没变 + loadedAt < TTL.
func loadTLSWithCache(caFile, certFile, keyFile string) (*x509.CertPool, *tls.Certificate, error) {
	// 取 3 文件 mtime
	caStat, err := os.Stat(caFile)
	if err != nil {
		return nil, nil, err
	}
	certStat, err := os.Stat(certFile)
	if err != nil {
		return nil, nil, err
	}
	keyStat, err := os.Stat(keyFile)
	if err != nil {
		return nil, nil, err
	}
	// 检 cache
	if entry := tlsCacheStore.Load(); entry != nil {
		if entry.caMtime.Equal(caStat.ModTime()) &&
			entry.certMtime.Equal(certStat.ModTime()) &&
			entry.keyMtime.Equal(keyStat.ModTime()) &&
			time.Since(entry.loadedAt) < tlsCacheTTL {
			ce := entry.clientCert
			return entry.caPool, &ce, nil
		}
	}
	// miss → 双检 + 加载
	tlsCacheMu.Lock()
	defer tlsCacheMu.Unlock()
	if entry := tlsCacheStore.Load(); entry != nil {
		if entry.caMtime.Equal(caStat.ModTime()) &&
			entry.certMtime.Equal(certStat.ModTime()) &&
			entry.keyMtime.Equal(keyStat.ModTime()) &&
			time.Since(entry.loadedAt) < tlsCacheTTL {
			ce := entry.clientCert
			return entry.caPool, &ce, nil
		}
	}
	caBytes, err := os.ReadFile(caFile)
	if err != nil {
		return nil, nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caBytes) {
		return nil, nil, errInvalidPEM
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, err
	}
	entry := &tlsCacheEntry{
		caPool:     pool,
		clientCert: cert,
		loadedAt:   time.Now(),
		caMtime:    caStat.ModTime(),
		certMtime:  certStat.ModTime(),
		keyMtime:   keyStat.ModTime(),
	}
	tlsCacheStore.Store(entry)
	return pool, &cert, nil
}

// InvalidateTLSCache 证书 rotate 后调, 强制下次 loadTLSWithCache 重读.
func InvalidateTLSCache() {
	tlsCacheStore.Store(nil)
}

// errInvalidPEM 哨兵.
var errInvalidPEM = pemError("invalid CA PEM")

type pemError string

func (e pemError) Error() string { return string(e) }
