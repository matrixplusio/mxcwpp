package metrics

import "testing"

// withCleanReadiness 隔离全局 readinessChecks：每个测试用干净的 map，结束后还原，
// 避免测试之间（以及对进程真实注册项的）污染。
func withCleanReadiness(t *testing.T) {
	t.Helper()
	readinessMu.Lock()
	saved := readinessChecks
	readinessChecks = map[string]func() bool{}
	readinessMu.Unlock()
	t.Cleanup(func() {
		readinessMu.Lock()
		readinessChecks = saved
		readinessMu.Unlock()
	})
}

// TestReadinessSnapshot 校验 /readyz 聚合逻辑：任一检查未就绪则整体未就绪，
// 全部就绪则整体就绪；结果按 name 排序稳定输出。
func TestReadinessSnapshot(t *testing.T) {
	withCleanReadiness(t)

	schemaReady := false
	RegisterReadiness("z_anomaly_schema", func() bool { return schemaReady })
	RegisterReadiness("a_always_ok", func() bool { return true })

	results, ready := readinessSnapshot()
	if ready {
		t.Error("有未就绪检查时整体应 not_ready")
	}
	if len(results) != 2 || results[0] != "a_always_ok=ready" || results[1] != "z_anomaly_schema=not_ready" {
		t.Errorf("结果应按 name 排序，got %v", results)
	}

	// 组件就绪后整体就绪。
	schemaReady = true
	if _, ready := readinessSnapshot(); !ready {
		t.Error("全部就绪时整体应 ready")
	}
}

// TestReadinessSnapshotPanicCallback 校验：某就绪回调 panic 时 readyz 不拖垮进程，
// 安全恢复并将该项标为 not_ready，其余检查仍正常聚合。
func TestReadinessSnapshotPanicCallback(t *testing.T) {
	withCleanReadiness(t)

	RegisterReadiness("boom", func() bool { panic("boom") })
	RegisterReadiness("ok", func() bool { return true })

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("readinessSnapshot 不应向上抛 panic，got %v", r)
		}
	}()

	results, ready := readinessSnapshot()
	if ready {
		t.Error("含 panic 回调时整体应 not_ready")
	}
	if len(results) != 2 || results[0] != "boom=not_ready" || results[1] != "ok=ready" {
		t.Errorf("panic 项应标 not_ready、其余不受影响，got %v", results)
	}
}
