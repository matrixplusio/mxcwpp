package advisory

// firstNonEmpty 返回参数列表中第一个非空字符串；全空返 ""。
// 多个 source parser 共用（rocky/ubuntu/osv 描述字段 fallback）。
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
