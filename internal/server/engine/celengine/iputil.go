package celengine

import "net"

// privateNets 预编译的 RFC 1918 / 环回 / 链路本地 / ULA 网段
var privateNets []*net.IPNet

func init() {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		// 链路本地。云厂商元数据服务（169.254.169.254）与部分云的内部 DNS 都在这里；
		// 漏掉它，agent 插件访问元数据就会被当成外网外联。
		"169.254.0.0/16",
		"::1/128",
		"fc00::/7",
		"fe80::/10",
	}
	for _, cidr := range cidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			panic("invalid CIDR: " + cidr)
		}
		privateNets = append(privateNets, ipNet)
	}
}

// isPrivateIP 判断 IP 地址字符串是否为私有/内网地址
func isPrivateIP(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
