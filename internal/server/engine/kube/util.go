package kube

// isSystemNamespace 判断是否系统命名空间。
// 行为与 manager/biz/kube_baseline_check.go 的同名函数保持一致;
// 由于 baseline_check 留在 biz 包,本副本作为 engine/kube 内部辅助函数。
func isSystemNamespace(ns string) bool {
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	return false
}
