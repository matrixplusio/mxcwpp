// Package connection 提供连接管理功能（服务发现、mTLS）
package connection

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"

	"github.com/matrixplusio/mxcwpp/internal/agent/config"
	"github.com/matrixplusio/mxcwpp/internal/common/certissue"
)

// Manager 是连接管理器
type Manager struct {
	cfg    *config.Config
	logger *zap.Logger
	conn   *grpc.ClientConn
}

// NewManager 创建新的连接管理器
func NewManager(cfg *config.Config, logger *zap.Logger) *Manager {
	return &Manager{
		cfg:    cfg,
		logger: logger,
	}
}

// GetConnection 获取 gRPC 连接（带 mTLS）
func (m *Manager) GetConnection(ctx context.Context) (*grpc.ClientConn, error) {
	// 如果已有连接且有效，直接返回
	if m.conn != nil {
		state := m.conn.GetState()
		m.logger.Debug("checking existing connection state", zap.String("state", state.String()))
		if state == connectivity.Ready || state == connectivity.Idle {
			m.logger.Debug("reusing existing connection", zap.String("state", state.String()))
			return m.conn, nil
		}
		// 连接已断开，关闭旧连接
		m.logger.Info("closing stale connection", zap.String("state", state.String()))
		m.conn.Close()
		m.conn = nil
	}

	// 获取 Server 地址（需要在加载 TLS 配置之前获取，以便设置 ServerName）
	m.logger.Info("discovering server address")
	serverAddr, err := m.discoverServer(ctx)
	if err != nil {
		m.logger.Error("failed to discover server", zap.Error(err))
		return nil, fmt.Errorf("failed to discover server: %w", err)
	}
	m.logger.Info("server address discovered", zap.String("address", serverAddr))

	// 加载 TLS 配置（包含证书验证和 ServerName）
	m.logger.Info("loading TLS configuration",
		zap.String("ca_file", m.cfg.Local.TLS.CAFile),
		zap.String("cert_file", m.cfg.Local.TLS.CertFile),
		zap.String("key_file", m.cfg.Local.TLS.KeyFile),
		zap.String("server_addr", serverAddr),
	)
	tlsConfig, err := m.loadTLSConfig(serverAddr)
	if err != nil {
		m.logger.Error("failed to load TLS config", zap.Error(err))
		return nil, fmt.Errorf("failed to load TLS config: %w", err)
	}

	// 仅首次部署（证书文件不存在）时允许 InsecureSkipVerify
	if tlsConfig.InsecureSkipVerify {
		m.logger.Warn("使用不安全模式进行首次连接（证书文件不存在）",
			zap.String("hint", "连接建立后Server会下发证书，后续连接将使用正式证书"),
		)
	} else {
		m.logger.Info("TLS configuration loaded successfully (using certificates)",
			zap.String("server_name", tlsConfig.ServerName),
		)
	}

	m.logger.Info("establishing gRPC connection",
		zap.String("server", serverAddr),
	)

	// 创建 gRPC 连接（惰性连接 + keepalive）
	conn, err := grpc.NewClient(
		"dns:///"+serverAddr,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second, // 每 30 秒发送一次 keepalive ping（降低频率避免 too_many_pings）
			Timeout:             5 * time.Second,  // keepalive ping 超时时间
			PermitWithoutStream: true,             // 即使没有活跃流也发送 keepalive
		}),
	)
	if err != nil {
		m.logger.Error("failed to create gRPC client",
			zap.String("server", serverAddr),
			zap.Error(err),
		)
		return nil, fmt.Errorf("failed to create gRPC client: %w", err)
	}

	// 等待连接就绪（最多等待 5 秒）
	readyCtx, readyCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer readyCancel()
	for {
		state := conn.GetState()
		m.logger.Debug("connection state", zap.String("state", state.String()))
		if state == connectivity.Ready {
			break
		}
		if !conn.WaitForStateChange(readyCtx, state) {
			m.logger.Warn("connection not ready within timeout",
				zap.String("final_state", conn.GetState().String()),
			)
			break
		}
	}

	m.conn = conn
	m.logger.Info("gRPC connection established successfully",
		zap.String("server", serverAddr),
		zap.String("state", conn.GetState().String()),
	)
	return conn, nil
}

// Close 关闭连接
func (m *Manager) Close() error {
	if m.conn != nil {
		return m.conn.Close()
	}
	return nil
}

// loadTLSConfig 加载 TLS 配置并验证证书
// 如果证书文件不存在（首次连接），返回不安全配置以允许首次连接获取证书
// serverAddr 用于提取主机名并设置为 ServerName（用于 SNI）
func (m *Manager) loadTLSConfig(serverAddr string) (*tls.Config, error) {
	// 从服务器地址中提取主机名（用于 SNI）
	serverName := m.extractHostname(serverAddr)
	m.logger.Debug("extracted server name from address",
		zap.String("server_addr", serverAddr),
		zap.String("server_name", serverName),
	)
	// 检查证书文件是否齐全（CA / client cert / client key）。任一缺失即为首次连接（enroll）。
	if _, err := os.Stat(m.cfg.Local.TLS.CAFile); os.IsNotExist(err) {
		return m.firstConnectTLSConfig(serverName, "CA证书文件不存在", m.cfg.Local.TLS.CAFile)
	}
	if _, err := os.Stat(m.cfg.Local.TLS.CertFile); os.IsNotExist(err) {
		return m.firstConnectTLSConfig(serverName, "客户端证书文件不存在", m.cfg.Local.TLS.CertFile)
	}
	if _, err := os.Stat(m.cfg.Local.TLS.KeyFile); os.IsNotExist(err) {
		return m.firstConnectTLSConfig(serverName, "客户端密钥文件不存在", m.cfg.Local.TLS.KeyFile)
	}

	// 证书文件存在，正常加载
	m.logger.Debug("证书文件存在，加载TLS配置",
		zap.String("ca_file", m.cfg.Local.TLS.CAFile),
		zap.String("cert_file", m.cfg.Local.TLS.CertFile),
		zap.String("key_file", m.cfg.Local.TLS.KeyFile),
	)

	// 加载 CA 证书
	m.logger.Debug("reading CA certificate", zap.String("path", m.cfg.Local.TLS.CAFile))
	caCert, err := os.ReadFile(m.cfg.Local.TLS.CAFile)
	if err != nil {
		m.logger.Error("failed to read CA cert", zap.String("path", m.cfg.Local.TLS.CAFile), zap.Error(err))
		return nil, fmt.Errorf("failed to read CA cert: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		m.logger.Error("failed to parse CA cert", zap.String("path", m.cfg.Local.TLS.CAFile))
		return nil, fmt.Errorf("failed to parse CA cert")
	}
	m.logger.Debug("CA certificate loaded successfully")

	// 解析 CA 证书用于验证
	block, _ := pem.Decode(caCert)
	if block == nil {
		m.logger.Error("failed to decode CA cert PEM")
		return nil, fmt.Errorf("failed to decode CA cert PEM")
	}
	caCertParsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		m.logger.Error("failed to parse CA cert", zap.Error(err))
		return nil, fmt.Errorf("failed to parse CA cert: %w", err)
	}
	m.logger.Info("CA certificate parsed",
		zap.String("subject", caCertParsed.Subject.String()),
		zap.String("issuer", caCertParsed.Issuer.String()),
		zap.Time("not_before", caCertParsed.NotBefore),
		zap.Time("not_after", caCertParsed.NotAfter),
	)

	// 加载客户端证书和密钥
	m.logger.Debug("loading client certificate and key",
		zap.String("cert_file", m.cfg.Local.TLS.CertFile),
		zap.String("key_file", m.cfg.Local.TLS.KeyFile),
	)
	cert, err := tls.LoadX509KeyPair(m.cfg.Local.TLS.CertFile, m.cfg.Local.TLS.KeyFile)
	if err != nil {
		m.logger.Error("failed to load client cert/key pair", zap.Error(err))
		return nil, fmt.Errorf("failed to load client cert: %w", err)
	}

	// 解析客户端证书用于验证
	clientCertData, err := os.ReadFile(m.cfg.Local.TLS.CertFile)
	if err != nil {
		m.logger.Error("failed to read client cert for verification", zap.Error(err))
		return nil, fmt.Errorf("failed to read client cert: %w", err)
	}
	block, _ = pem.Decode(clientCertData)
	if block == nil {
		m.logger.Error("failed to decode client cert PEM")
		return nil, fmt.Errorf("failed to decode client cert PEM")
	}
	clientCertParsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		m.logger.Error("failed to parse client cert", zap.Error(err))
		return nil, fmt.Errorf("failed to parse client cert: %w", err)
	}
	m.logger.Info("client certificate parsed",
		zap.String("subject", clientCertParsed.Subject.String()),
		zap.String("issuer", clientCertParsed.Issuer.String()),
		zap.Time("not_before", clientCertParsed.NotBefore),
		zap.Time("not_after", clientCertParsed.NotAfter),
	)

	// 验证客户端证书是否由 CA 签发
	m.logger.Debug("verifying client certificate is signed by CA")
	roots := x509.NewCertPool()
	roots.AddCert(caCertParsed)
	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, // 允许客户端认证用途
	}
	chains, err := clientCertParsed.Verify(opts)
	if err != nil {
		m.logger.Error("client certificate verification failed",
			zap.String("client_subject", clientCertParsed.Subject.String()),
			zap.String("ca_subject", caCertParsed.Subject.String()),
			zap.Error(err),
		)
		return nil, fmt.Errorf("client certificate is not signed by CA: %w", err)
	}
	m.logger.Info("client certificate verified successfully",
		zap.Int("chain_count", len(chains)),
		zap.String("client_subject", clientCertParsed.Subject.String()),
		zap.String("ca_subject", caCertParsed.Subject.String()),
	)

	// 创建 TLS 配置
	// 设置 ServerName 用于 SNI（Server Name Indication），确保 TLS 握手时使用正确的主机名
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            caCertPool,
		ServerName:         serverName, // 从服务器地址提取的主机名，用于 SNI
		InsecureSkipVerify: false,      // 不跳过验证，使用 CA 验证
	}

	m.logger.Debug("TLS configuration created successfully")
	return tlsConfig, nil
}

// firstConnectTLSConfig 构造首次连接（enroll）的 TLS 配置。
// 配置了 CA 指纹时用 VerifyConnection pin 住 AC 的 CA，杜绝中间人冒充 AC 下发恶意证书；
// 未配置指纹时回退到旧的 InsecureSkipVerify（仅兼容期，受控内网）。
func (m *Manager) firstConnectTLSConfig(serverName, reason, path string) (*tls.Config, error) {
	// 若本地已有 CA 文件（仅缺客户端证书），直接用 RootCAs 正常校验 AC，无需 pin/insecure。
	if caBytes, err := os.ReadFile(m.cfg.Local.TLS.CAFile); err == nil {
		pool := x509.NewCertPool()
		if pool.AppendCertsFromPEM(caBytes) {
			m.logger.Info("首次连接(enroll)：本地已有 CA，使用 RootCAs 校验 AC（无客户端证书）",
				zap.String("reason", reason),
			)
			return &tls.Config{
				ServerName: serverName,
				RootCAs:    pool,
			}, nil
		}
	}

	fp := m.cfg.Local.TLS.CAFingerprint
	if fp != "" {
		m.logger.Warn("首次连接(enroll)：本地证书不完整，使用 CA 指纹 pin 校验 AC 身份",
			zap.String("reason", reason),
			zap.String("path", path),
		)
		return &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, // 关闭默认链校验，改由 VerifyConnection 做 CA pin
			VerifyConnection: func(cs tls.ConnectionState) error {
				raw := make([][]byte, 0, len(cs.PeerCertificates))
				for _, c := range cs.PeerCertificates {
					raw = append(raw, c.Raw)
				}
				if err := certissue.VerifyChainPinnedCA(raw, fp); err != nil {
					m.logger.Error("AC CA 指纹 pin 校验失败，疑似中间人，拒绝连接", zap.Error(err))
					return err
				}
				return nil
			},
		}, nil
	}
	m.logger.Warn("首次连接：未配置 CA 指纹，回退不安全模式（仅兼容期，受控内网）",
		zap.String("reason", reason),
		zap.String("path", path),
		zap.String("hint", "建议安装包下发 ca_fingerprint，pin 住 AC 杜绝中间人"),
	)
	return &tls.Config{InsecureSkipVerify: true}, nil
}

// acInstanceInfo 是 Manager SD 返回的 AC 实例信息（仅解析需要的字段）
type acInstanceInfo struct {
	GRPCAddr  string `json:"grpc_addr"`
	ConnCount int64  `json:"conn_count"`
	Healthy   bool   `json:"healthy"`
}

// discoverServer 通过服务发现获取 Server 地址，优先级：
// 1. Manager SD HTTP 接口（动态发现，power-of-two-choices 负载均衡）
// 2. 静态地址列表 Addresses（轮转）
// 3. PrivateHost / PublicHost（向后兼容）
func (m *Manager) discoverServer(ctx context.Context) (string, error) {
	// 1. 尝试 Manager SD 服务发现
	if url := m.cfg.Local.Server.ServiceDiscovery.URL; url != "" {
		if addr, err := m.fetchFromSD(ctx, url); err == nil {
			m.logger.Info("通过 Manager SD 发现 AC 地址", zap.String("address", addr))
			return addr, nil
		} else {
			m.logger.Warn("Manager SD 发现失败，降级到静态地址", zap.Error(err))
		}
	}

	// 2. 静态地址列表轮转
	if addrs := m.cfg.Local.Server.AgentCenter.Addresses; len(addrs) > 0 {
		addr := addrs[rand.Intn(len(addrs))]
		m.logger.Info("使用静态地址列表", zap.String("address", addr))
		return addr, nil
	}

	// 3. 兼容旧配置
	addr := m.cfg.Local.Server.AgentCenter.PrivateHost
	if addr == "" {
		addr = m.cfg.Local.Server.AgentCenter.PublicHost
	}
	if addr == "" {
		return "", fmt.Errorf("no server address configured")
	}
	return addr, nil
}

// fetchFromSD 调用 Manager SD 接口获取健康 AC 列表，用 power-of-two-choices 选择
func (m *Manager) fetchFromSD(ctx context.Context, sdURL string) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, sdURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("SD 返回 %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Instances []acInstanceInfo `json:"instances"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("解析 SD 响应失败: %w", err)
	}

	// 过滤健康实例
	healthy := make([]acInstanceInfo, 0, len(result.Data.Instances))
	for _, inst := range result.Data.Instances {
		if inst.Healthy && inst.GRPCAddr != "" {
			healthy = append(healthy, inst)
		}
	}
	if len(healthy) == 0 {
		return "", fmt.Errorf("SD 返回 0 个健康实例")
	}

	return selectByPowerOfTwo(healthy), nil
}

// selectByPowerOfTwo 随机选两个候选，返回连接数更少的那个（防止新 AC 上线时雪崩）
func selectByPowerOfTwo(instances []acInstanceInfo) string {
	if len(instances) == 1 {
		return instances[0].GRPCAddr
	}
	i := rand.Intn(len(instances))
	j := rand.Intn(len(instances) - 1)
	if j >= i {
		j++ // 确保 j != i，避免选中同一实例
	}
	if instances[j].ConnCount < instances[i].ConnCount {
		return instances[j].GRPCAddr
	}
	return instances[i].GRPCAddr
}

// extractHostname 从服务器地址中提取主机名（去掉端口）
// 支持 IPv4、IPv6 和域名格式：
//
//	agentcenter:6751 -> agentcenter
//	192.168.1.1:6751 -> 192.168.1.1
//	[::1]:6751       -> ::1
func (m *Manager) extractHostname(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// 没有端口号或格式不匹配，直接返回原始地址
		return addr
	}
	return host
}

// Startup 启动连接管理（保持连接活跃）
func Startup(ctx context.Context, wg interface{}, cfg *config.Config, logger *zap.Logger) {
	// 此函数用于在主程序中启动连接管理
	// 实际连接在 transport 模块中按需获取
	// 这里可以添加连接健康检查逻辑
}
