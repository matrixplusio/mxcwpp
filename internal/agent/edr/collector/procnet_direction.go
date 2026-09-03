package collector

// directionForLocalPort 按本地端口是否属监听端口集推断连接方向。
//
// 无 build tag（纯逻辑，跨平台可测）：procfs 采集(旧内核降级路径)无 eBPF 的
// tcp_accept/tcp_connect 语义，靠"本地端口是否在 LISTEN 集"补方向：
//   - 属监听端口 → 对端主动连入本机服务 → inbound
//   - 否则       → 本机用临时端口主动外联 → outbound
func directionForLocalPort(listenPorts map[int]struct{}, localPort int) string {
	if _, ok := listenPorts[localPort]; ok {
		return "inbound"
	}
	return "outbound"
}
