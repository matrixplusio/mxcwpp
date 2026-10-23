package handlers

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// 同一二进制只算一次；文件被替换（大小或修改时间变化）后必须重算。
func TestProcessHashCache(t *testing.T) {
	f := filepath.Join(t.TempDir(), "bin")
	if err := os.WriteFile(f, []byte("v1"), 0755); err != nil {
		t.Fatal(err)
	}
	h := &ProcessHandler{}

	h.next = map[string]cachedHash{}
	first, err := h.calculateMD5(f)
	if err != nil {
		t.Fatal(err)
	}
	h.hashes, h.next = h.next, map[string]cachedHash{}

	again, _ := h.calculateMD5(f)
	if again != first {
		t.Fatal("文件未变应沿用缓存结果")
	}
	if _, ok := h.next[f]; !ok {
		t.Fatal("本轮用到的缓存应带入下一轮")
	}

	if err := os.WriteFile(f, []byte("v2-replaced"), 0755); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	_ = os.Chtimes(f, future, future)
	changed, _ := h.calculateMD5(f)
	if changed == first {
		t.Fatal("文件被替换后必须重算 MD5")
	}
}
