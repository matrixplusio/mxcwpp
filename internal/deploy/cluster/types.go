package cluster

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

const (
	RoleControl = "control"
	RoleStorage = "storage"
	RoleKafka   = "kafka"
)

// Config 是 cluster.yaml 的顶层结构。
type Config struct {
	APIVersion     string         `yaml:"api_version"`
	Kind           string         `yaml:"kind"`
	Metadata       Metadata       `yaml:"metadata"`
	Release        Release        `yaml:"release"`
	Registry       Registry       `yaml:"registry"`
	OS             OS             `yaml:"os"`
	Network        Network        `yaml:"network"`
	App            App            `yaml:"app"`
	Infrastructure Infrastructure `yaml:"infrastructure"`
	ControlPlane   ControlPlane   `yaml:"control_plane"`
	Nodes          []Node         `yaml:"nodes"`
}

type Metadata struct {
	Name        string `yaml:"name"`
	Environment string `yaml:"environment"`
}

type Release struct {
	Version    string `yaml:"version"`
	InstallDir string `yaml:"install_dir"`
	DataRoot   string `yaml:"data_root"`
	Timezone   string `yaml:"timezone"`
}

type Registry struct {
	Domain    string `yaml:"domain"`
	Namespace string `yaml:"namespace"`
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
}

type OS struct {
	Family  string `yaml:"family"`
	Version string `yaml:"version"`
}

type Network struct {
	UI             Endpoint `yaml:"ui"`
	GRPC           Endpoint `yaml:"grpc"`
	AdditionalSANs SANs     `yaml:"additional_sans"`
}

type Endpoint struct {
	Scheme string `yaml:"scheme"`
	Host   string `yaml:"host"`
	Port   int    `yaml:"port"`
}

type SANs struct {
	IPs []string `yaml:"ips"`
	DNS []string `yaml:"dns"`
}

type App struct {
	JWTSecret          string `yaml:"jwt_secret"`
	LogLevel           string `yaml:"log_level"`
	LogFormat          string `yaml:"log_format"`
	HeartbeatInterval  int    `yaml:"heartbeat_interval"`
	PluginsBaseURL     string `yaml:"plugins_base_url"`
	PrometheusEnabled  bool   `yaml:"prometheus_enabled"`
	PrometheusQueryURL string `yaml:"prometheus_query_url"`
	PrometheusTimeout  string `yaml:"prometheus_timeout"`
	ManagerHTTPPort    int    `yaml:"manager_http_port"`
	ACHTTPPort         int    `yaml:"ac_http_port"`
	GRPCPort           int    `yaml:"grpc_port"`
	HTTPPort           int    `yaml:"http_port"`
	HTTPSPort          int    `yaml:"https_port"`
	ExposeHTTPS        bool   `yaml:"expose_https"`
	// 插件下载并发上限（Manager 端 /api/v1/plugins/download 信号量），0 → render 默认 50
	PluginDownloadConcurrency int `yaml:"plugin_download_concurrency"`
}

type Infrastructure struct {
	MySQL      MySQL      `yaml:"mysql"`
	Redis      Redis      `yaml:"redis"`
	ClickHouse ClickHouse `yaml:"clickhouse"`
	Kafka      Kafka      `yaml:"kafka"`
}

type MySQL struct {
	RootPassword string `yaml:"root_password"`
	Database     string `yaml:"database"`
	User         string `yaml:"user"`
	Password     string `yaml:"password"`
	Host         string `yaml:"host"`
	Port         int    `yaml:"port"`
}

type Redis struct {
	Password string `yaml:"password"`
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	DB       int    `yaml:"db"`
}

type ClickHouse struct {
	Host     string `yaml:"host"`
	HTTPPort int    `yaml:"http_port"`
	TCPPort  int    `yaml:"tcp_port"`
	Database string `yaml:"database"`
	User     string `yaml:"user"`
	Password string `yaml:"password"`
}

type Kafka struct {
	Enabled     bool   `yaml:"enabled"`
	Host        string `yaml:"host"`
	BrokerPorts []int  `yaml:"broker_ports"`
	TopicPrefix string `yaml:"topic_prefix"`
}

type ControlPlane struct {
	ManagerReplicas     int `yaml:"manager_replicas"`
	AgentCenterReplicas int `yaml:"agentcenter_replicas"`
	ConsumerReplicas    int `yaml:"consumer_replicas"`
	EngineReplicas      int `yaml:"engine_replicas"`
	LLMProxyReplicas    int `yaml:"llmproxy_replicas"`
	VulnSyncReplicas    int `yaml:"vulnsync_replicas"`
}

type Node struct {
	Name       string   `yaml:"name"`
	Host       string   `yaml:"host"`
	SSHUser    string   `yaml:"ssh_user"`
	SSHPort    int      `yaml:"ssh_port"`
	SSHKeyPath string   `yaml:"ssh_key_path"`
	Roles      []string `yaml:"roles"`
	InstallDir string   `yaml:"install_dir"`
	DataRoot   string   `yaml:"data_root"`
}

type RoleAssignment struct {
	Node                Node
	Roles               []string
	ManagerReplicas     int
	AgentCenterReplicas int
	ConsumerReplicas    int
	EngineReplicas      int
	LLMProxyReplicas    int
	VulnSyncReplicas    int
}

// WithACHTTPPort 返回一个浅拷贝，将 ManagerHTTPPort 替换为 ACHTTPPort，
// 用于生成 agentcenter 独立的 server.yaml。
func (c *Config) WithACHTTPPort() *Config {
	copy := *c
	copy.App.ManagerHTTPPort = c.App.ACHTTPPort
	return &copy
}

func (c *Config) ApplyDefaults() {
	if c.APIVersion == "" {
		c.APIVersion = "mxsec.io/v1alpha1"
	}
	if c.Kind == "" {
		c.Kind = "ClusterConfig"
	}
	if c.Release.InstallDir == "" {
		c.Release.InstallDir = "/opt/mxsec-platform"
	}
	if c.Release.DataRoot == "" {
		c.Release.DataRoot = "/data/mxsec"
	}
	if c.Release.Timezone == "" {
		c.Release.Timezone = "Asia/Shanghai"
	}
	if c.OS.Family == "" {
		c.OS.Family = "ubuntu"
	}
	if c.Network.UI.Scheme == "" {
		c.Network.UI.Scheme = "http"
	}
	if c.Network.UI.Port == 0 {
		if c.Network.UI.Scheme == "https" {
			c.Network.UI.Port = 443
		} else {
			c.Network.UI.Port = 80
		}
	}
	if c.Network.GRPC.Port == 0 {
		c.Network.GRPC.Port = 6751
	}
	if c.App.LogLevel == "" {
		c.App.LogLevel = "info"
	}
	if c.App.LogFormat == "" {
		c.App.LogFormat = "json"
	}
	if c.App.HeartbeatInterval == 0 {
		c.App.HeartbeatInterval = 60
	}
	if c.App.PluginDownloadConcurrency <= 0 {
		c.App.PluginDownloadConcurrency = 50
	}
	if c.App.ManagerHTTPPort == 0 {
		c.App.ManagerHTTPPort = 8080
	}
	if c.App.ACHTTPPort == 0 {
		c.App.ACHTTPPort = 8081
	}
	if c.App.GRPCPort == 0 {
		c.App.GRPCPort = 6751
	}
	if c.App.HTTPPort == 0 {
		c.App.HTTPPort = 80
	}
	if c.App.HTTPSPort == 0 {
		c.App.HTTPSPort = 443
	}
	if c.App.PrometheusTimeout == "" {
		c.App.PrometheusTimeout = "10s"
	}
	if c.Infrastructure.MySQL.Database == "" {
		c.Infrastructure.MySQL.Database = "mxsec"
	}
	if c.Infrastructure.MySQL.User == "" {
		c.Infrastructure.MySQL.User = "mxsec_user"
	}
	if c.Infrastructure.MySQL.Port == 0 {
		c.Infrastructure.MySQL.Port = 13306
	}
	if c.Infrastructure.Redis.Port == 0 {
		c.Infrastructure.Redis.Port = 16379
	}
	if c.Infrastructure.ClickHouse.Database == "" {
		c.Infrastructure.ClickHouse.Database = "mxsec"
	}
	if c.Infrastructure.ClickHouse.User == "" {
		c.Infrastructure.ClickHouse.User = "default"
	}
	if c.Infrastructure.ClickHouse.HTTPPort == 0 {
		c.Infrastructure.ClickHouse.HTTPPort = 8123
	}
	if c.Infrastructure.ClickHouse.TCPPort == 0 {
		c.Infrastructure.ClickHouse.TCPPort = 9000
	}
	if len(c.Infrastructure.Kafka.BrokerPorts) == 0 {
		c.Infrastructure.Kafka.BrokerPorts = []int{9092, 9094, 9095}
	}

	controlCount := 0
	for i := range c.Nodes {
		if c.Nodes[i].SSHPort == 0 {
			c.Nodes[i].SSHPort = 22
		}
		if c.Nodes[i].SSHUser == "" {
			c.Nodes[i].SSHUser = "root"
		}
		if c.Nodes[i].InstallDir == "" {
			c.Nodes[i].InstallDir = c.Release.InstallDir
		}
		if c.Nodes[i].DataRoot == "" {
			c.Nodes[i].DataRoot = c.Release.DataRoot
		}
		if c.Nodes[i].HasRole(RoleControl) {
			controlCount++
		}
	}
	if controlCount == 0 {
		controlCount = 1
	}
	if c.ControlPlane.ManagerReplicas == 0 {
		c.ControlPlane.ManagerReplicas = controlCount
	}
	if c.ControlPlane.AgentCenterReplicas == 0 {
		c.ControlPlane.AgentCenterReplicas = controlCount
	}
	if c.ControlPlane.ConsumerReplicas == 0 {
		c.ControlPlane.ConsumerReplicas = controlCount
	}
	if c.ControlPlane.EngineReplicas == 0 {
		c.ControlPlane.EngineReplicas = controlCount
	}
	if c.ControlPlane.LLMProxyReplicas == 0 {
		c.ControlPlane.LLMProxyReplicas = controlCount
	}
	if c.ControlPlane.VulnSyncReplicas == 0 {
		c.ControlPlane.VulnSyncReplicas = controlCount
	}
}

func (c *Config) Validate() error {
	c.ApplyDefaults()
	if c.Metadata.Name == "" {
		return fmt.Errorf("metadata.name 不能为空")
	}
	if c.Release.Version == "" {
		return fmt.Errorf("release.version 不能为空")
	}
	if c.Network.UI.Host == "" {
		return fmt.Errorf("network.ui.host 不能为空")
	}
	if c.Network.GRPC.Host == "" {
		return fmt.Errorf("network.grpc.host 不能为空")
	}
	if c.App.JWTSecret == "" {
		return fmt.Errorf("app.jwt_secret 不能为空")
	}
	if c.Infrastructure.MySQL.RootPassword == "" || c.Infrastructure.MySQL.Password == "" {
		return fmt.Errorf("infrastructure.mysql.root_password 和 infrastructure.mysql.password 不能为空")
	}
	if len(c.Nodes) == 0 {
		return fmt.Errorf("nodes 不能为空")
	}

	nameSet := make(map[string]struct{}, len(c.Nodes))
	hostSet := make(map[string]struct{}, len(c.Nodes))
	roleCount := map[string]int{}
	for _, node := range c.Nodes {
		if node.Name == "" || node.Host == "" {
			return fmt.Errorf("所有 node 都必须配置 name 和 host")
		}
		if _, ok := nameSet[node.Name]; ok {
			return fmt.Errorf("node.name 重复: %s", node.Name)
		}
		if _, ok := hostSet[node.Host]; ok {
			return fmt.Errorf("node.host 重复: %s", node.Host)
		}
		nameSet[node.Name] = struct{}{}
		hostSet[node.Host] = struct{}{}
		if len(node.Roles) == 0 {
			return fmt.Errorf("node %s 未配置 roles", node.Name)
		}
		for _, role := range node.Roles {
			switch role {
			case RoleControl, RoleStorage, RoleKafka:
				roleCount[role]++
			default:
				return fmt.Errorf("node %s 包含不支持的 role: %s", node.Name, role)
			}
		}
	}

	controlCount := roleCount[RoleControl]
	if controlCount == 0 {
		return fmt.Errorf("至少需要一个 control 节点")
	}
	if roleCount[RoleStorage] != 1 {
		return fmt.Errorf("v1 仅支持一个 storage 节点，当前为 %d", roleCount[RoleStorage])
	}
	if roleCount[RoleKafka] != 1 {
		return fmt.Errorf("v1 仅支持一个 kafka 节点，当前为 %d", roleCount[RoleKafka])
	}
	if len(c.Infrastructure.Kafka.BrokerPorts) != 3 {
		return fmt.Errorf("infrastructure.kafka.broker_ports 必须配置 3 个端口")
	}
	if c.ControlPlane.ManagerReplicas < controlCount {
		return fmt.Errorf("control_plane.manager_replicas 不能小于 control 节点数 %d", controlCount)
	}
	if c.ControlPlane.AgentCenterReplicas < controlCount {
		return fmt.Errorf("control_plane.agentcenter_replicas 不能小于 control 节点数 %d", controlCount)
	}
	if c.ControlPlane.EngineReplicas < controlCount {
		return fmt.Errorf("control_plane.engine_replicas 不能小于 control 节点数 %d", controlCount)
	}
	if c.ControlPlane.LLMProxyReplicas < controlCount {
		return fmt.Errorf("control_plane.llmproxy_replicas 不能小于 control 节点数 %d", controlCount)
	}
	if c.ControlPlane.VulnSyncReplicas < controlCount {
		return fmt.Errorf("control_plane.vulnsync_replicas 不能小于 control 节点数 %d", controlCount)
	}
	if c.App.PrometheusEnabled {
		if _, err := c.StorageNode(); err != nil {
			return fmt.Errorf("启用 Prometheus 时必须有 storage 节点: %w", err)
		}
	}
	if _, err := c.StorageNode(); err != nil {
		return err
	}
	if _, err := c.KafkaNode(); err != nil {
		return err
	}
	return nil
}

func (c *Config) ControlNodes() []Node {
	var nodes []Node
	for _, node := range c.Nodes {
		if node.HasRole(RoleControl) {
			nodes = append(nodes, node)
		}
	}
	sort.Slice(nodes, func(i, j int) bool { return nodes[i].Name < nodes[j].Name })
	return nodes
}

func (c *Config) StorageNode() (Node, error) {
	for _, node := range c.Nodes {
		if node.HasRole(RoleStorage) {
			return node, nil
		}
	}
	return Node{}, fmt.Errorf("未找到 storage 节点")
}

func (c *Config) KafkaNode() (Node, error) {
	for _, node := range c.Nodes {
		if node.HasRole(RoleKafka) {
			return node, nil
		}
	}
	return Node{}, fmt.Errorf("未找到 kafka 节点")
}

func (n Node) HasRole(role string) bool {
	for _, item := range n.Roles {
		if item == role {
			return true
		}
	}
	return false
}

func (c *Config) ImageRef(name string) string {
	parts := make([]string, 0, 3)
	if c.Registry.Domain != "" {
		parts = append(parts, strings.TrimSuffix(c.Registry.Domain, "/"))
	}
	if c.Registry.Namespace != "" {
		parts = append(parts, strings.Trim(c.Registry.Namespace, "/"))
	}
	parts = append(parts, name)
	return strings.Join(parts, "/") + ":" + c.Release.Version
}

func (c *Config) PluginsBaseURL() string {
	if c.App.PluginsBaseURL != "" {
		return c.App.PluginsBaseURL
	}
	return fmt.Sprintf("%s://%s%s/api/v1/plugins/download", c.Network.UI.Scheme, c.Network.UI.Host, optionalPort(c.Network.UI.Scheme, c.Network.UI.Port))
}

func (c *Config) MySQLHost() string {
	if c.Infrastructure.MySQL.Host != "" {
		return c.Infrastructure.MySQL.Host
	}
	node, err := c.StorageNode()
	if err != nil {
		return ""
	}
	return node.Host
}

func (c *Config) RedisHost() string {
	if c.Infrastructure.Redis.Host != "" {
		return c.Infrastructure.Redis.Host
	}
	node, err := c.StorageNode()
	if err != nil {
		return ""
	}
	return node.Host
}

func (c *Config) ClickHouseHost() string {
	if c.Infrastructure.ClickHouse.Host != "" {
		return c.Infrastructure.ClickHouse.Host
	}
	node, err := c.StorageNode()
	if err != nil {
		return ""
	}
	return node.Host
}

func (c *Config) KafkaHost() string {
	if c.Infrastructure.Kafka.Host != "" {
		return c.Infrastructure.Kafka.Host
	}
	node, err := c.KafkaNode()
	if err != nil {
		return ""
	}
	return node.Host
}

func (c *Config) KafkaBrokerEndpoints() []string {
	host := c.KafkaHost()
	endpoints := make([]string, 0, len(c.Infrastructure.Kafka.BrokerPorts))
	for _, port := range c.Infrastructure.Kafka.BrokerPorts {
		endpoints = append(endpoints, fmt.Sprintf("%s:%d", host, port))
	}
	return endpoints
}

func (c *Config) SANValues() (ips []string, dns []string) {
	seenIP := map[string]struct{}{}
	seenDNS := map[string]struct{}{}
	appendIP := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seenIP[value]; ok {
			return
		}
		seenIP[value] = struct{}{}
		ips = append(ips, value)
	}
	appendDNS := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seenDNS[value]; ok {
			return
		}
		seenDNS[value] = struct{}{}
		dns = append(dns, value)
	}

	for _, value := range []string{c.Network.GRPC.Host, c.Network.UI.Host, "localhost", "agentcenter"} {
		if ip := net.ParseIP(value); ip != nil {
			appendIP(value)
		} else {
			appendDNS(value)
		}
	}
	for _, node := range c.ControlNodes() {
		if net.ParseIP(node.Host) != nil {
			appendIP(node.Host)
		} else {
			appendDNS(node.Host)
		}
	}
	for _, value := range c.Network.AdditionalSANs.IPs {
		appendIP(value)
	}
	for _, value := range c.Network.AdditionalSANs.DNS {
		appendDNS(value)
	}
	return ips, dns
}

func (c *Config) RoleAssignments() []RoleAssignment {
	controls := c.ControlNodes()
	assignments := make([]RoleAssignment, 0, len(c.Nodes))
	controlDistManager := distribute(c.ControlPlane.ManagerReplicas, len(controls))
	controlDistAC := distribute(c.ControlPlane.AgentCenterReplicas, len(controls))
	controlDistConsumer := distribute(c.ControlPlane.ConsumerReplicas, len(controls))
	controlDistEngine := distribute(c.ControlPlane.EngineReplicas, len(controls))
	controlDistLLMProxy := distribute(c.ControlPlane.LLMProxyReplicas, len(controls))
	controlDistVulnSync := distribute(c.ControlPlane.VulnSyncReplicas, len(controls))
	controlIndex := 0
	for _, node := range c.Nodes {
		assignment := RoleAssignment{Node: node, Roles: append([]string(nil), node.Roles...)}
		if node.HasRole(RoleControl) {
			assignment.ManagerReplicas = controlDistManager[controlIndex]
			assignment.AgentCenterReplicas = controlDistAC[controlIndex]
			assignment.ConsumerReplicas = controlDistConsumer[controlIndex]
			assignment.EngineReplicas = controlDistEngine[controlIndex]
			assignment.LLMProxyReplicas = controlDistLLMProxy[controlIndex]
			assignment.VulnSyncReplicas = controlDistVulnSync[controlIndex]
			controlIndex++
		}
		assignments = append(assignments, assignment)
	}
	return assignments
}

func distribute(total, nodes int) []int {
	if nodes <= 0 {
		return nil
	}
	result := make([]int, nodes)
	base := total / nodes
	remain := total % nodes
	for i := 0; i < nodes; i++ {
		result[i] = base
		if i < remain {
			result[i]++
		}
	}
	return result
}

func optionalPort(scheme string, port int) string {
	if port == 0 {
		return ""
	}
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		return ""
	}
	return fmt.Sprintf(":%d", port)
}
