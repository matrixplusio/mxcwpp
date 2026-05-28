<template>
  <a-spin :spinning="loading" :style="loading ? { minHeight: '300px', display: 'flex', justifyContent: 'center', alignItems: 'center' } : {}">
    <div v-if="host" class="host-overview">
      <!-- 主内容区域 -->
      <div class="main-content">
        <!-- 基础信息 -->
        <div class="content-section">
            <a-card title="主机基本信息" :bordered="false" class="host-info-card">
              <div class="host-info-container">
                <!-- 左侧列 -->
                <div class="info-column">
                  <div class="info-group">
                    <div class="info-item">
                      <span class="info-label">主机名称</span>
                      <span class="info-value">
                        <a-tooltip v-if="host.hostname" :title="host.hostname" placement="topLeft">
                          <span class="copyable-text" @click="copyText(host.hostname, '主机名称')">
                            {{ host.hostname }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">主机ID</span>
                      <span class="info-value">
                        <a-tooltip v-if="host.host_id" :title="host.host_id" placement="topLeft">
                          <span class="copyable-text" @click="copyText(host.host_id, '主机ID')">
                            {{ host.host_id }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">操作系统</span>
                      <span class="info-value">
                        <a-tooltip 
                          v-if="host.os_family || host.os_version"
                          :title="(host.os_family || '未知') + (host.os_family && host.os_version ? ' ' : '') + (host.os_version || '')"
                          placement="topLeft"
                        >
                          <span 
                            class="copyable-text"
                            @click="copyText((host.os_family || '未知') + (host.os_family && host.os_version ? ' ' : '') + (host.os_version || ''), '操作系统')"
                          >
                            {{ host.os_family || '未知' }}{{ host.os_family && host.os_version ? ' ' : '' }}{{ host.os_version || '' }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">主机标签</span>
                      <span class="info-value">
                        <a-tag v-if="host.tags && host.tags.length > 0" v-for="tag in host.tags" :key="tag" color="blue" style="margin-right: 4px">
                          {{ tag }}
                        </a-tag>
                        <span v-else class="empty-value">未设置</span>
                        <a-button 
                          type="link" 
                          size="small" 
                          style="padding: 0; margin-left: 8px; height: auto;"
                          @click="showTagModal = true"
                        >
                          {{ host.tags && host.tags.length > 0 ? '编辑' : '设置' }}
                        </a-button>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">设备型号</span>
                      <span class="info-value">
                        <template v-if="getFieldStatus(host.device_model, 'hardware') === 'has_value'">
                          <a-tooltip :title="host.device_model" placement="topLeft">
                            <span class="copyable-text" @click="copyText(host.device_model, '设备型号')">
                              {{ host.device_model }}
                            </span>
                          </a-tooltip>
                        </template>
                        <a-tooltip v-else :title="getFieldStatusText(host.device_model, 'hardware').tooltip" placement="topLeft">
                          <span class="empty-value" :class="{ 'status-no-data': getFieldStatus(host.device_model, 'hardware') === 'no_data' }">
                            {{ getFieldStatusText(host.device_model, 'hardware').text }}
                          </span>
                        </a-tooltip>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">生产商</span>
                      <span class="info-value">
                        <template v-if="getFieldStatus(host.manufacturer, 'hardware') === 'has_value'">
                          <a-tooltip :title="host.manufacturer" placement="topLeft">
                            <span class="copyable-text" @click="copyText(host.manufacturer, '生产商')">
                              {{ host.manufacturer }}
                            </span>
                          </a-tooltip>
                        </template>
                        <a-tooltip v-else :title="getFieldStatusText(host.manufacturer, 'hardware').tooltip" placement="topLeft">
                          <span class="empty-value" :class="{ 'status-no-data': getFieldStatus(host.manufacturer, 'hardware') === 'no_data' }">
                            {{ getFieldStatusText(host.manufacturer, 'hardware').text }}
                          </span>
                        </a-tooltip>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">系统负载</span>
                      <span class="info-value">
                        <a-tooltip v-if="host.system_load" :title="host.system_load" placement="topLeft">
                          <span class="copyable-text" @click="copyText(host.system_load, '系统负载')">
                            {{ host.system_load }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                  </div>
                </div>

                <!-- 中间列 -->
                <div class="info-column">
                  <div class="info-group">
                    <div class="info-item">
                      <span class="info-label">公网IPv4</span>
                      <span class="info-value">
                        <template v-if="getArrayFieldStatus(host.public_ipv4) === 'has_value'">
                          <a-tooltip :title="host.public_ipv4!.join(', ')" placement="topLeft">
                            <span class="copyable-text" @click="copyText(host.public_ipv4!.join(', '), '公网IPv4')">
                              {{ host.public_ipv4![0] }}
                            </span>
                          </a-tooltip>
                          <a-tag v-if="host.public_ipv4!.length > 1" color="blue" size="small" style="margin-left: 6px">
                            +{{ host.public_ipv4!.length - 1 }}
                          </a-tag>
                        </template>
                        <a-tooltip v-else :title="getArrayFieldStatusText(host.public_ipv4, '公网IPv4').tooltip" placement="topLeft">
                          <span class="empty-value" :class="{ 'status-no-data': getArrayFieldStatus(host.public_ipv4) === 'no_data' }">
                            {{ getArrayFieldStatusText(host.public_ipv4, '公网IPv4').text }}
                          </span>
                        </a-tooltip>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">公网IPv6</span>
                      <span class="info-value">
                        <template v-if="getArrayFieldStatus(host.public_ipv6) === 'has_value'">
                          <a-tooltip :title="host.public_ipv6!.join(', ')" placement="topLeft">
                            <span class="copyable-text" @click="copyText(host.public_ipv6!.join(', '), '公网IPv6')">
                              {{ host.public_ipv6![0] }}
                            </span>
                          </a-tooltip>
                          <a-tag v-if="host.public_ipv6!.length > 1" color="blue" size="small" style="margin-left: 6px">
                            +{{ host.public_ipv6!.length - 1 }}
                          </a-tag>
                        </template>
                        <a-tooltip v-else :title="getArrayFieldStatusText(host.public_ipv6, '公网IPv6').tooltip" placement="topLeft">
                          <span class="empty-value" :class="{ 'status-no-data': getArrayFieldStatus(host.public_ipv6) === 'no_data' }">
                            {{ getArrayFieldStatusText(host.public_ipv6, '公网IPv6').text }}
                          </span>
                        </a-tooltip>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">私网IPv4</span>
                      <span class="info-value">
                        <template v-if="getArrayFieldStatus(host.ipv4) === 'has_value'">
                          <a-tooltip :title="host.ipv4!.join(', ')" placement="topLeft">
                            <span class="copyable-text" @click="copyText(host.ipv4!.join(', '), '私网IPv4')">
                              {{ host.ipv4![0] }}
                            </span>
                          </a-tooltip>
                          <a-tag v-if="host.ipv4!.length > 1" color="blue" size="small" style="margin-left: 6px">
                            +{{ host.ipv4!.length - 1 }}
                          </a-tag>
                        </template>
                        <a-tooltip v-else :title="getArrayFieldStatusText(host.ipv4, '私网IPv4').tooltip" placement="topLeft">
                          <span class="empty-value" :class="{ 'status-no-data': getArrayFieldStatus(host.ipv4) === 'no_data' }">
                            {{ getArrayFieldStatusText(host.ipv4, '私网IPv4').text }}
                          </span>
                        </a-tooltip>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">私网IPv6</span>
                      <span class="info-value">
                        <template v-if="getArrayFieldStatus(host.ipv6) === 'has_value'">
                          <a-tooltip :title="host.ipv6!.join(', ')" placement="topLeft">
                            <span class="copyable-text" @click="copyText(host.ipv6!.join(', '), '私网IPv6')">
                              {{ host.ipv6![0] }}
                            </span>
                          </a-tooltip>
                          <a-tag v-if="host.ipv6!.length > 1" color="blue" size="small" style="margin-left: 6px">
                            +{{ host.ipv6!.length - 1 }}
                          </a-tag>
                        </template>
                        <a-tooltip v-else :title="getArrayFieldStatusText(host.ipv6, '私网IPv6').tooltip" placement="topLeft">
                          <span class="empty-value" :class="{ 'status-no-data': getArrayFieldStatus(host.ipv6) === 'no_data' }">
                            {{ getArrayFieldStatusText(host.ipv6, '私网IPv6').text }}
                          </span>
                        </a-tooltip>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">CPU信息</span>
                      <span class="info-value">
                        <a-tooltip v-if="host.cpu_info" :title="host.cpu_info" placement="topLeft">
                          <span class="copyable-text" @click="copyText(host.cpu_info, 'CPU信息')">
                            {{ host.cpu_info }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">内存大小</span>
                      <span class="info-value">
                        <a-tooltip v-if="host.memory_size" :title="host.memory_size" placement="topLeft">
                          <span class="copyable-text" @click="copyText(host.memory_size, '内存大小')">
                            {{ host.memory_size }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">默认网关</span>
                      <span class="info-value">
                        <a-tooltip v-if="host.default_gateway" :title="host.default_gateway" placement="topLeft">
                          <span class="copyable-text" @click="copyText(host.default_gateway, '默认网关')">
                            {{ host.default_gateway }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                  </div>
                </div>

                <!-- 右侧列 -->
                <div class="info-column">
                  <div class="info-group">
                    <div class="info-item">
                      <span class="info-label">业务线</span>
                      <span class="info-value">
                        <template v-if="host.business_line">
                          <a-tooltip :title="host.business_line" placement="topLeft">
                            <span class="copyable-text" @click="copyText(host.business_line, '业务线')">
                              {{ host.business_line }}
                            </span>
                          </a-tooltip>
                        </template>
                        <span v-else class="empty-value">未设置</span>
                        <a-button 
                          type="link" 
                          size="small" 
                          style="padding: 0; margin-left: 8px; height: auto;"
                          @click="showBusinessLineModal = true"
                        >
                          {{ host.business_line ? '编辑' : '设置' }}
                        </a-button>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">内核版本</span>
                      <span class="info-value">
                        <a-tooltip v-if="host.kernel_version" :title="host.kernel_version" placement="topLeft">
                          <span class="copyable-text" @click="copyText(host.kernel_version, '内核版本')">
                            {{ host.kernel_version }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">网络模式</span>
                      <span class="info-value">
                        <a-tooltip v-if="host.network_mode" :title="host.network_mode" placement="topLeft">
                          <span class="copyable-text" @click="copyText(host.network_mode, '网络模式')">
                            {{ host.network_mode }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">客户端状态</span>
                      <span class="info-value">
                        <a-tag :color="host.status === 'online' ? 'success' : 'error'" class="status-tag">
                          <span class="status-dot" :class="host.status === 'online' ? 'online' : 'offline'"></span>
                          {{ host.status === 'online' ? '运行中' : '离线' }}
                        </a-tag>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">CPU使用率</span>
                      <span class="info-value">
                        <a-tooltip v-if="host.cpu_usage" :title="host.cpu_usage" placement="topLeft">
                          <span class="copyable-text" @click="copyText(host.cpu_usage, 'CPU使用率')">
                            {{ host.cpu_usage }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">内存使用率</span>
                      <span class="info-value">
                        <a-tooltip v-if="host.memory_usage" :title="host.memory_usage" placement="topLeft">
                          <span class="copyable-text" @click="copyText(host.memory_usage, '内存使用率')">
                            {{ host.memory_usage }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">DNS服务器</span>
                      <span class="info-value">
                        <template v-if="host.dns_servers && host.dns_servers.length > 0">
                          <a-tooltip :title="host.dns_servers.join(', ')" placement="topLeft">
                            <span class="copyable-text" @click="copyText(host.dns_servers.join(', '), 'DNS服务器')">
                              {{ host.dns_servers[0] }}
                            </span>
                          </a-tooltip>
                          <a-tag v-if="host.dns_servers.length > 1" color="blue" size="small" style="margin-left: 6px">
                            +{{ host.dns_servers.length - 1 }}
                          </a-tag>
                        </template>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                  </div>
                </div>

                <!-- 最右侧时间信息列 -->
                <div class="info-column">
                  <div class="info-group">
                    <div class="info-item">
                      <span class="info-label">系统启动时间</span>
                      <span class="info-value">
                        <template v-if="getFieldStatus(host.system_boot_time) === 'has_value'">
                          <a-tooltip 
                            :title="formatDateTime(host.system_boot_time)" 
                            placement="topLeft"
                          >
                            <span 
                              class="copyable-text" 
                              @click="copyText(formatDateTime(host.system_boot_time), '系统启动时间')"
                            >
                              {{ formatDateTime(host.system_boot_time) }}
                            </span>
                          </a-tooltip>
                        </template>
                        <a-tooltip v-else :title="getFieldStatusText(host.system_boot_time).tooltip" placement="topLeft">
                          <span class="empty-value" :class="{ 'status-no-data': getFieldStatus(host.system_boot_time) === 'no_data' }">
                            {{ getFieldStatusText(host.system_boot_time).text }}
                          </span>
                        </a-tooltip>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">最近活跃时间</span>
                      <span class="info-value">
                        <a-tooltip 
                          v-if="host.last_active_time" 
                          :title="formatDateTime(host.last_active_time)" 
                          placement="topLeft"
                        >
                          <span 
                            class="copyable-text" 
                            @click="copyText(formatDateTime(host.last_active_time), '最近活跃时间')"
                          >
                            {{ formatDateTime(host.last_active_time) }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">客户端安装时间</span>
                      <span class="info-value">
                        <a-tooltip 
                          v-if="host.created_at" 
                          :title="formatDateTime(host.created_at)" 
                          placement="topLeft"
                        >
                          <span 
                            class="copyable-text" 
                            @click="copyText(formatDateTime(host.created_at), '客户端安装时间')"
                          >
                            {{ formatDateTime(host.created_at) }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">客户端启动时间</span>
                      <span class="info-value">
                        <template v-if="getFieldStatus(host.agent_start_time) === 'has_value'">
                          <a-tooltip 
                            :title="formatDateTime(host.agent_start_time)" 
                            placement="topLeft"
                          >
                            <span 
                              class="copyable-text" 
                              @click="copyText(formatDateTime(host.agent_start_time), '客户端启动时间')"
                            >
                              {{ formatDateTime(host.agent_start_time) }}
                            </span>
                          </a-tooltip>
                        </template>
                        <a-tooltip v-else :title="getFieldStatusText(host.agent_start_time).tooltip" placement="topLeft">
                          <span class="empty-value" :class="{ 'status-no-data': getFieldStatus(host.agent_start_time) === 'no_data' }">
                            {{ getFieldStatusText(host.agent_start_time).text }}
                          </span>
                        </a-tooltip>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">设备序列号</span>
                      <span class="info-value">
                        <template v-if="getFieldStatus(host.device_serial, 'hardware') === 'has_value'">
                          <a-tooltip :title="host.device_serial" placement="topLeft">
                            <span class="copyable-text" @click="copyText(host.device_serial, '设备序列号')">
                              {{ host.device_serial }}
                            </span>
                          </a-tooltip>
                        </template>
                        <a-tooltip v-else :title="getFieldStatusText(host.device_serial, 'hardware').tooltip" placement="topLeft">
                          <span class="empty-value" :class="{ 'status-no-data': getFieldStatus(host.device_serial, 'hardware') === 'no_data' }">
                            {{ getFieldStatusText(host.device_serial, 'hardware').text }}
                          </span>
                        </a-tooltip>
                      </span>
                    </div>
                    <div class="info-item">
                      <span class="info-label">设备ID</span>
                      <span class="info-value">
                        <a-tooltip v-if="host.device_id" :title="host.device_id" placement="topLeft">
                          <span class="copyable-text" @click="copyText(host.device_id, '设备ID')">
                            {{ host.device_id }}
                          </span>
                        </a-tooltip>
                        <span v-else class="empty-value">未采集</span>
                      </span>
                    </div>
                  </div>
                </div>
              </div>
            </a-card>
          </div>

          <!-- 风险概览 -->
          <div class="content-section">
            <!-- 安全态势概览 -->
            <div class="risk-overview-container">
              <!-- 第一行：3个卡片 -->
              <div class="risk-overview-row first-row">
                <div class="risk-card">
                  <div class="risk-card-header">
                    <span class="risk-card-title">主机和容器安全告警</span>
                    <a-button type="link" size="small" class="risk-card-link" @click="$emit('view-detail', 'alerts')">详情</a-button>
                  </div>
                  <div class="risk-card-content">
                    <div class="risk-left-section">
                      <div class="risk-unprocessed">
                        <span class="risk-unprocessed-label">未处理</span>
                        <span class="risk-unprocessed-value">{{ alertCount }}</span>
                      </div>
                      <div class="risk-ring-wrapper">
                        <div class="risk-ring" :class="{ 'has-risk': alertCount > 0 }"></div>
                      </div>
                    </div>
                    <div class="risk-stats">
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot critical"></span>
                        <span class="risk-stat-label">严重</span>
                        <span class="risk-stat-value">{{ alertStats.critical || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot medium"></span>
                        <span class="risk-stat-label">中危</span>
                        <span class="risk-stat-value">{{ alertStats.medium || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot high"></span>
                        <span class="risk-stat-label">高危</span>
                        <span class="risk-stat-value">{{ alertStats.high || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot low"></span>
                        <span class="risk-stat-label">低危</span>
                        <span class="risk-stat-value">{{ alertStats.low || 0 }}</span>
                      </div>
                    </div>
                  </div>
                </div>
                <div class="risk-card">
                  <div class="risk-card-header">
                    <span class="risk-card-title">漏洞风险</span>
                    <a-button type="link" size="small" class="risk-card-link" @click="$emit('view-detail', 'vulnerabilities')">详情</a-button>
                  </div>
                  <div class="risk-card-content">
                    <div class="risk-left-section">
                      <div class="risk-unprocessed">
                        <span class="risk-unprocessed-label">未处理</span>
                        <span class="risk-unprocessed-value">{{ vulnerabilityCount }}</span>
                      </div>
                      <div class="risk-ring-wrapper">
                        <div class="risk-ring" :class="{ 'has-risk': vulnerabilityCount > 0 }"></div>
                      </div>
                    </div>
                    <div class="risk-stats">
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot critical"></span>
                        <span class="risk-stat-label">严重</span>
                        <span class="risk-stat-value">{{ vulnStats.critical || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot medium"></span>
                        <span class="risk-stat-label">中危</span>
                        <span class="risk-stat-value">{{ vulnStats.medium || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot high"></span>
                        <span class="risk-stat-label">高危</span>
                        <span class="risk-stat-value">{{ vulnStats.high || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot low"></span>
                        <span class="risk-stat-label">低危</span>
                        <span class="risk-stat-value">{{ vulnStats.low || 0 }}</span>
                      </div>
                    </div>
                  </div>
                </div>
                <div class="risk-card">
                  <div class="risk-card-header">
                    <div class="risk-card-title-with-tags">
                      <span class="risk-card-title">基线风险</span>
                      <div class="baseline-tags" v-if="weakPasswordStatus">
                        <a-tag size="small" style="font-size: 11px; margin-right: 4px;">弱口令</a-tag>
                        <a-tag :color="weakPasswordStatus === '无风险' ? 'success' : 'error'" size="small" style="font-size: 11px;">
                          {{ weakPasswordStatus }}
                        </a-tag>
                      </div>
                    </div>
                    <a-button type="link" size="small" class="risk-card-link" @click="$emit('view-detail', 'baseline')">详情</a-button>
                  </div>
                  <div class="risk-card-content">
                    <div class="risk-left-section">
                      <div class="risk-unprocessed">
                        <span class="risk-unprocessed-label">未处理</span>
                        <span class="risk-unprocessed-value">{{ baselineCount }}</span>
                      </div>
                      <div class="risk-ring-wrapper">
                        <div class="risk-ring" :class="{ 'has-risk': baselineCount > 0 }"></div>
                      </div>
                    </div>
                    <div class="risk-stats">
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot high"></span>
                        <span class="risk-stat-label">高危</span>
                        <span class="risk-stat-value">{{ baselineStats.high || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot medium"></span>
                        <span class="risk-stat-label">中危</span>
                        <span class="risk-stat-value">{{ baselineStats.medium || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot low"></span>
                        <span class="risk-stat-label">低危</span>
                        <span class="risk-stat-value">{{ baselineStats.low || 0 }}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              <!-- 第二行：2个卡片 -->
              <div class="risk-overview-row second-row">
                <div class="risk-card">
                  <div class="risk-card-header">
                    <span class="risk-card-title">检测告警</span>
                    <a-button type="link" size="small" class="risk-card-link" @click="$emit('view-detail', 'detection')">详情</a-button>
                  </div>
                  <div class="risk-card-content">
                    <div class="risk-left-section">
                      <div class="risk-unprocessed">
                        <span class="risk-unprocessed-label">未处理</span>
                        <span class="risk-unprocessed-value">{{ runtimeCount }}</span>
                      </div>
                      <div class="risk-ring-wrapper">
                        <div class="risk-ring" :class="{ 'has-risk': runtimeCount > 0 }"></div>
                      </div>
                    </div>
                    <div class="risk-stats">
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot critical"></span>
                        <span class="risk-stat-label">严重</span>
                        <span class="risk-stat-value">{{ runtimeStats.critical || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot medium"></span>
                        <span class="risk-stat-label">中危</span>
                        <span class="risk-stat-value">{{ runtimeStats.medium || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot high"></span>
                        <span class="risk-stat-label">高危</span>
                        <span class="risk-stat-value">{{ runtimeStats.high || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot low"></span>
                        <span class="risk-stat-label">低危</span>
                        <span class="risk-stat-value">{{ runtimeStats.low || 0 }}</span>
                      </div>
                    </div>
                  </div>
                </div>
                <div class="risk-card">
                  <div class="risk-card-header">
                    <span class="risk-card-title">病毒扫描</span>
                    <a-button type="link" size="small" class="risk-card-link" @click="$emit('view-detail', 'antivirus')">详情</a-button>
                  </div>
                  <div class="risk-card-content">
                    <div class="risk-left-section">
                      <div class="risk-unprocessed">
                        <span class="risk-unprocessed-label">未处理</span>
                        <span class="risk-unprocessed-value">{{ antivirusCount }}</span>
                      </div>
                      <div class="risk-ring-wrapper">
                        <div class="risk-ring" :class="{ 'has-risk': antivirusCount > 0 }"></div>
                      </div>
                    </div>
                    <div class="risk-stats">
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot critical"></span>
                        <span class="risk-stat-label">严重</span>
                        <span class="risk-stat-value">{{ antivirusStats.critical || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot medium"></span>
                        <span class="risk-stat-label">中危</span>
                        <span class="risk-stat-value">{{ antivirusStats.medium || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot high"></span>
                        <span class="risk-stat-label">高危</span>
                        <span class="risk-stat-value">{{ antivirusStats.high || 0 }}</span>
                      </div>
                      <div class="risk-stat-item">
                        <span class="risk-stat-dot low"></span>
                        <span class="risk-stat-label">低危</span>
                        <span class="risk-stat-value">{{ antivirusStats.low || 0 }}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>

          <!-- 资产指纹 -->
          <div class="content-section">
            <div class="fingerprint-section">
              <div class="fingerprint-header">
                <span class="fingerprint-title">资产指纹</span>
                <a-button type="link" size="small" class="fingerprint-link" @click="$emit('view-detail', 'fingerprint')">详情</a-button>
              </div>
              <div class="fingerprint-grid">
                <div class="fingerprint-item" v-for="item in fingerprintItems" :key="item.key">
                  <div class="fingerprint-value">{{ item.value }}</div>
                  <div class="fingerprint-label">{{ item.label }}</div>
                </div>
              </div>
            </div>
          </div>

          <!-- 磁盘信息 -->
          <div class="content-section">
            <a-card title="磁盘信息" :bordered="false">
              <div v-if="parsedDiskInfo && parsedDiskInfo.length > 0">
                <a-table
                  :columns="diskColumns"
                  :data-source="parsedDiskInfo"
                  :pagination="false"
                  size="small"
                  :scroll="{ x: 'max-content' }"
                >
                  <template #bodyCell="{ column, record }">
                    <template v-if="column.key === 'device'">
                      <span class="copyable-text" @click="copyText(record.device, '设备路径')">
                        {{ record.device }}
                      </span>
                    </template>
                    <template v-else-if="column.key === 'mount_point'">
                      <span class="copyable-text" @click="copyText(record.mount_point, '挂载点')">
                        {{ record.mount_point }}
                      </span>
                    </template>
                    <template v-else-if="column.key === 'file_system'">
                      {{ record.file_system }}
                    </template>
                    <template v-else-if="column.key === 'total_size'">
                      {{ formatBytes(record.total_size) }}
                    </template>
                    <template v-else-if="column.key === 'used_size'">
                      {{ formatBytes(record.used_size) }}
                    </template>
                    <template v-else-if="column.key === 'available_size'">
                      {{ formatBytes(record.available_size) }}
                    </template>
                    <template v-else-if="column.key === 'usage_percent'">
                      <a-progress
                        :percent="record.usage_percent"
                        :status="record.usage_percent > 90 ? 'exception' : record.usage_percent > 80 ? 'active' : 'success'"
                        :stroke-width="8"
                        :format="(percent: number) => `${percent?.toFixed(1)}%`"
                      />
                    </template>
                  </template>
                </a-table>
              </div>
              <a-empty v-else-if="getFieldStatus(host?.disk_info) === 'no_data'" description="Agent 已连接，但未采集到磁盘信息" />
              <a-empty v-else description="磁盘信息未采集，请确保 Agent 已连接并已部署最新版本" />
            </a-card>
          </div>
          <!-- 网卡信息 -->
          <div class="content-section">
            <a-card title="网卡信息" :bordered="false">
              <div v-if="parsedNetworkInterfaces && parsedNetworkInterfaces.length > 0">
                <a-table
                  :columns="networkColumns"
                  :data-source="parsedNetworkInterfaces"
                  :pagination="false"
                  size="small"
                  :scroll="{ x: 'max-content' }"
                >
                  <template #bodyCell="{ column, record }">
                    <template v-if="column.key === 'interface_name'">
                      <span class="copyable-text" @click="copyText(record.interface_name, '接口名称')">
                        {{ record.interface_name }}
                      </span>
                    </template>
                    <template v-else-if="column.key === 'mac_address'">
                      <span v-if="record.mac_address" class="copyable-text" @click="copyText(record.mac_address, 'MAC地址')">
                        {{ record.mac_address }}
                      </span>
                      <span v-else class="empty-value">-</span>
                    </template>
                    <template v-else-if="column.key === 'ipv4_addresses'">
                      <div v-if="record.ipv4_addresses && record.ipv4_addresses.length > 0">
                        <a-tag v-for="(ip, index) in record.ipv4_addresses" :key="index" color="blue" style="margin-right: 4px; margin-bottom: 4px;">
                          <span class="copyable-text" @click.stop="copyText(ip, 'IPv4地址')">
                            {{ ip }}
                          </span>
                        </a-tag>
                      </div>
                      <span v-else class="empty-value">-</span>
                    </template>
                    <template v-else-if="column.key === 'ipv6_addresses'">
                      <div v-if="record.ipv6_addresses && record.ipv6_addresses.length > 0">
                        <a-tag v-for="(ip, index) in record.ipv6_addresses" :key="index" color="green" style="margin-right: 4px; margin-bottom: 4px;">
                          <span class="copyable-text" @click.stop="copyText(ip, 'IPv6地址')">
                            {{ ip }}
                          </span>
                        </a-tag>
                      </div>
                      <span v-else class="empty-value">-</span>
                    </template>
                    <template v-else-if="column.key === 'mtu'">
                      <span v-if="record.mtu">{{ record.mtu }}</span>
                      <span v-else class="empty-value">-</span>
                    </template>
                    <template v-else-if="column.key === 'state'">
                      <a-tag :color="record.state === 'up' ? 'success' : 'default'">
                        {{ record.state === 'up' ? '启用' : '禁用' }}
                      </a-tag>
                    </template>
                  </template>
                </a-table>
              </div>
              <a-empty v-else-if="getFieldStatus(host?.network_interfaces) === 'no_data'" description="Agent 已连接，但未采集到网卡信息" />
              <a-empty v-else description="网卡信息未采集，请确保 Agent 已连接并已部署最新版本" />
            </a-card>
          </div>
          <div class="content-section">
            <a-card title="组件列表" :bordered="false">
              <a-spin :spinning="componentsLoading">
                <a-table
                  v-if="components.length > 0"
                  :columns="componentColumns"
                  :data-source="components"
                  :pagination="false"
                  row-key="name"
                  size="small"
                >
                  <template #bodyCell="{ column, record }">
                    <template v-if="column.key === 'name'">
                      <a-tag :color="record.name === 'agent' ? 'blue' : 'green'" style="margin-right: 8px;">
                        {{ record.name === 'agent' ? 'Agent' : 'Plugin' }}
                      </a-tag>
                      <span style="font-weight: 500;">{{ record.name }}</span>
                    </template>
                    <template v-else-if="column.key === 'version'">
                      <span :style="{ color: record.need_update && !(host?.is_container && record.status === 'not_installed') ? '#F59E0B' : 'inherit' }">
                        {{ record.version || '-' }}
                        <template v-if="record.need_update && !(host?.is_container && record.status === 'not_installed')">
                          <a-tooltip v-if="host?.is_container" title="容器环境请通过重建镜像更新，不支持在线推送">
                            <a-tag color="default" style="margin-left: 8px; font-size: 11px; cursor: help;">
                              请重建镜像
                            </a-tag>
                          </a-tooltip>
                          <a-tag v-else color="orange" style="margin-left: 8px; font-size: 11px;">
                            可更新
                          </a-tag>
                        </template>
                      </span>
                    </template>
                    <template v-else-if="column.key === 'latest_version'">
                      {{ record.latest_version || '-' }}
                    </template>
                    <template v-else-if="column.key === 'status'">
                      <a-tooltip v-if="host?.is_container && record.status === 'not_installed'" title="容器环境中插件随镜像部署，无需单独安装">
                        <a-tag color="default" style="cursor: help;">容器环境无需安装</a-tag>
                      </a-tooltip>
                      <a-tag v-else :color="componentStatusMap[record.status]?.color || 'default'">
                        {{ componentStatusMap[record.status]?.text || record.status }}
                      </a-tag>
                    </template>
                    <template v-else-if="column.key === 'start_time'">
                      {{ record.start_time ? formatDateTime(record.start_time) : '-' }}
                    </template>
                    <template v-else-if="column.key === 'updated_at'">
                      {{ record.updated_at ? formatDateTime(record.updated_at) : '-' }}
                    </template>
                    <template v-else-if="column.key === 'action'">
                      <span style="color: #bfbfbf">-</span>
                    </template>
                  </template>
                </a-table>
                <a-empty v-else description="暂无组件信息" />
              </a-spin>
            </a-card>
          </div>
      </div>

      <!-- 标签编辑模态框 -->
      <a-modal
        v-model:open="showTagModal"
        title="编辑主机标签"
        @ok="handleSaveTags"
        @cancel="handleCancelTags"
      >
        <div style="margin-bottom: 16px;">
          <div style="margin-bottom: 8px; font-weight: 500;">标签</div>
          <a-select
            v-model:value="editingTags"
            mode="tags"
            placeholder="输入标签后按回车添加"
            style="width: 100%"
            :max-tag-count="10"
          >
          </a-select>
          <div style="margin-top: 8px; color: #86909C; font-size: 12px;">
            提示：输入标签后按回车键添加，最多可添加10个标签，每个标签最多50个字符
          </div>
        </div>
      </a-modal>

      <!-- 业务线编辑模态框 -->
      <a-modal
        v-model:open="showBusinessLineModal"
        title="编辑业务线"
        @ok="handleSaveBusinessLine"
        @cancel="handleCancelBusinessLine"
      >
        <div style="margin-bottom: 16px;">
          <div style="margin-bottom: 8px; font-weight: 500;">业务线</div>
          <a-select
            v-model:value="editingBusinessLine"
            placeholder="请选择业务线"
            style="width: 100%"
            show-search
            allow-clear
            :filter-option="filterBusinessLineOption"
          >
            <a-select-option v-for="bl in businessLines" :key="bl.code" :value="bl.code">
              {{ bl.name }}
            </a-select-option>
          </a-select>
          <div style="margin-top: 8px; color: #86909C; font-size: 12px;">
            提示：选择业务线后，该主机将归属于所选业务线。留空表示取消业务线绑定。
          </div>
        </div>
      </a-modal>
    </div>
    <div v-else-if="!loading" class="host-overview-empty">
      <a-empty description="暂无主机数据" />
    </div>
  </a-spin>
</template>

<script setup lang="ts">
import { ref, onMounted, watch, computed } from 'vue'
import { message } from 'ant-design-vue'
import { hostsApi, type HostRiskStatistics } from '@/api/hosts'
import { businessLinesApi, type BusinessLine } from '@/api/business-lines'
import { componentsApi } from '@/api/components'
import type { HostDetail, BaselineScore, DiskInfo, NetworkInterfaceInfo } from '@/api/types'
import { formatDateTime } from '@/utils/date'

const props = defineProps<{
  host: HostDetail | null
  loading: boolean
  scoreData?: BaselineScore | null
}>()

const emit = defineEmits<{
  (e: 'update:host', host: HostDetail): void
  (e: 'view-detail', tab: string): void
}>()

const score = ref<BaselineScore | null>(null)

const alertCount = ref(0)
const alertStats = ref({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
})

const vulnerabilityCount = ref(0)
const vulnStats = ref({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
})

const baselineCount = ref(0)
const baselineStats = ref({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
})

const runtimeCount = ref(0)
const runtimeStats = ref({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
})

const antivirusCount = ref(0)
const antivirusStats = ref({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
})

const weakPasswordStatus = ref('无风险') // 弱口令状态：无风险/有风险

const fingerprintItems = ref([
  { key: 'containers', label: '容器', value: 0 },
  { key: 'ports', label: '开放端口', value: 0 },
  { key: 'processes', label: '运行进程', value: 0 },
  { key: 'users', label: '系统用户', value: 0 },
  { key: 'cron', label: '定时任务', value: 0 },
  { key: 'services', label: '系统服务', value: 0 },
  { key: 'packages', label: '系统软件', value: 0 },
  { key: 'integrity', label: '系统完整性校验', value: 0 },
])

// 组件列表（包含 Agent 和插件）
interface ComponentInfo {
  name: string
  version: string
  latest_version: string
  status: string
  start_time?: string
  updated_at?: string
  need_update: boolean
}

const components = ref<ComponentInfo[]>([])
const componentsLoading = ref(false)

// 组件状态标签映射
const componentStatusMap: Record<string, { text: string; color: string }> = {
  running: { text: '运行中', color: 'green' },
  stopped: { text: '已停止', color: 'default' },
  error: { text: '错误', color: 'red' },
  not_installed: { text: '未安装', color: 'orange' },
  updating: { text: '更新中', color: 'blue' },
  dormant: { text: '休眠', color: 'purple' },
}

// 组件表格列定义
const componentColumns = [
  { title: '组件名称', dataIndex: 'name', key: 'name' },
  { title: '当前版本', dataIndex: 'version', key: 'version' },
  { title: '最新版本', dataIndex: 'latest_version', key: 'latest_version' },
  { title: '状态', dataIndex: 'status', key: 'status' },
  { title: '启动时间', dataIndex: 'start_time', key: 'start_time' },
  { title: '更新时间', dataIndex: 'updated_at', key: 'updated_at' },
  { title: '操作', key: 'action', width: 120, align: 'center' as const },
]

// 加载组件列表（包含 Agent 和插件）
const loadComponents = async () => {
  if (!props.host) return
  
  componentsLoading.value = true
  try {
    // 1. 加载插件列表
    const pluginsResponse = await hostsApi.getPlugins(props.host.host_id)
    
    // 2. 加载所有组件的最新版本
    const allComponents = await componentsApi.list()
    const latestVersions = new Map<string, string>()
    allComponents.forEach(c => {
      if (c.latest_version) {
        latestVersions.set(c.name, c.latest_version)
      }
    })
    
    // 3. 构建组件列表（先添加 Agent）
    const componentList: ComponentInfo[] = []
    
    // 添加 Agent
    const agentLatestVersion = latestVersions.get('agent') || ''
    const agentCurrentVersion = props.host.agent_version || ''
    componentList.push({
      name: 'agent',
      version: agentCurrentVersion || '-',
      latest_version: agentLatestVersion,
      status: agentCurrentVersion ? 'running' : 'not_installed',
      start_time: props.host.agent_start_time,
      updated_at: props.host.updated_at,
      need_update: !!(agentLatestVersion && agentCurrentVersion && agentCurrentVersion !== agentLatestVersion),
    })
    
    // 添加插件
    pluginsResponse.forEach(plugin => {
      componentList.push({
        name: plugin.name,
        version: plugin.version,
        latest_version: plugin.latest_version,
        status: plugin.status,
        start_time: plugin.start_time,
        updated_at: plugin.updated_at,
        need_update: plugin.need_update,
      })
    })
    
    components.value = componentList
  } catch (error) {
    console.error('加载组件列表失败:', error)
  } finally {
    componentsLoading.value = false
  }
}


// 监听 host 变化，重新加载组件列表
watch(() => props.host?.host_id, (newHostId) => {
  if (newHostId) {
    loadComponents()
  }
})

const showTagModal = ref(false)
const editingTags = ref<string[]>([])

// 监听标签编辑模态框打开，初始化编辑标签
watch(showTagModal, (open) => {
  if (open && props.host) {
    editingTags.value = props.host.tags ? [...props.host.tags] : []
  }
})

// 业务线编辑
const showBusinessLineModal = ref(false)
const editingBusinessLine = ref<string>('')
const businessLines = ref<BusinessLine[]>([])

// 监听业务线编辑模态框打开，初始化编辑业务线
watch(showBusinessLineModal, async (open) => {
  if (open && props.host) {
    editingBusinessLine.value = props.host.business_line || ''
    // 加载业务线列表
    try {
      const response = await businessLinesApi.list({ enabled: 'true', page_size: 1000 })
      businessLines.value = response.items
    } catch (error) {
      console.error('加载业务线列表失败:', error)
    }
  }
})

// 业务线筛选选项过滤
const filterBusinessLineOption = (input: string, option: any) => {
  return option.children[0].children.toLowerCase().indexOf(input.toLowerCase()) >= 0
}

// 保存业务线
const handleSaveBusinessLine = async () => {
  if (!props.host) return
  
  try {
    // 调用API更新业务线
    await hostsApi.updateBusinessLine(props.host.host_id, editingBusinessLine.value || '')
    
    // 通过 emit 通知父组件更新
    emit('update:host', {
      ...props.host,
      business_line: editingBusinessLine.value || undefined
    })
    
    message.success('业务线保存成功')
    showBusinessLineModal.value = false
  } catch (error: any) {
    console.error('保存业务线失败:', error)
    message.error(error?.message || '保存业务线失败，请重试')
  }
}

// 取消业务线编辑
const handleCancelBusinessLine = () => {
  showBusinessLineModal.value = false
  editingBusinessLine.value = ''
}


const riskStatistics = ref<HostRiskStatistics | null>(null)

const loadOverviewData = async () => {
  if (!props.host) return

  try {
    // 使用父组件传入的 scoreData（避免重复 API 调用）
    if (props.scoreData) {
      score.value = props.scoreData
      baselineCount.value = props.scoreData.fail_count
    } else {
      // 兜底：如果父组件没有传入，自行加载
      const fetchedScore = await hostsApi.getScore(props.host.host_id).catch(() => null)
      if (fetchedScore) {
        score.value = fetchedScore
        baselineCount.value = fetchedScore.fail_count
      }
    }

    // 加载风险统计数据
    const riskStats = await hostsApi.getRiskStatistics(props.host.host_id).catch(() => null)
    if (riskStats) {
      riskStatistics.value = riskStats
      // 更新告警统计
      alertCount.value = riskStats.alerts.total
      alertStats.value = {
        critical: riskStats.alerts.critical,
        high: riskStats.alerts.high,
        medium: riskStats.alerts.medium,
        low: riskStats.alerts.low,
      }
      // 更新漏洞统计
      vulnerabilityCount.value = riskStats.vulnerabilities.total
      vulnStats.value = {
        critical: riskStats.vulnerabilities.critical,
        high: riskStats.vulnerabilities.high,
        medium: riskStats.vulnerabilities.medium,
        low: riskStats.vulnerabilities.low,
      }
      // 更新基线统计
      baselineCount.value = riskStats.baseline.total
      baselineStats.value = {
        critical: riskStats.baseline.critical,
        high: riskStats.baseline.high,
        medium: riskStats.baseline.medium,
        low: riskStats.baseline.low,
      }
      // TODO: 从API获取运行时告警和病毒扫描统计数据
      // TODO: 从API获取弱口令状态
    }

    // TODO: 加载资产指纹数据
  } catch (error) {
    console.error('加载概览数据失败:', error)
  }
}

// formatDateTime 已从 @/utils/date 导入，使用统一的格式化函数

// 判断字段状态：返回 'has_value' | 'not_collected' | 'no_data'
// has_value: 有值
// not_collected: 未采集（Agent 未连接或代码未更新）
// no_data: 无数据（Agent 已连接但采集不到数据，如容器环境）
const getFieldStatus = (fieldValue: any, _fieldType: 'hardware' | 'normal' | 'ip' = 'normal'): 'has_value' | 'not_collected' | 'no_data' => {
  // 如果有值，返回有值
  if (fieldValue !== null && fieldValue !== undefined && fieldValue !== '') {
    return 'has_value'
  }
  
  // 检查 Agent 是否已连接（通过 last_heartbeat 判断）
  const hasRecentHeartbeat = props.host?.last_heartbeat && 
    (new Date().getTime() - new Date(props.host.last_heartbeat).getTime()) < 5 * 60 * 1000 // 5分钟内有心跳
  
  if (hasRecentHeartbeat) {
    // Agent 已连接，但字段为空，说明采集了但没有数据
    return 'no_data'
  } else {
    // Agent 未连接或很久没心跳，说明未采集
    return 'not_collected'
  }
}

// 获取字段状态的显示文本和提示
const getFieldStatusText = (fieldValue: any, fieldType: 'hardware' | 'normal' | 'ip' = 'normal'): { text: string, tooltip: string } => {
  const status = getFieldStatus(fieldValue, fieldType as 'hardware' | 'normal' | 'ip')
  
  if (status === 'has_value') {
    return { text: String(fieldValue), tooltip: String(fieldValue) }
  }
  
  if (status === 'no_data') {
    if (fieldType === 'hardware') {
      return { 
        text: '无数据（容器环境）', 
        tooltip: '容器环境中无法访问 DMI（Desktop Management Interface）信息，这是正常现象。物理机/虚拟机通常可以正常采集。' 
      }
    } else if (fieldType === 'ip') {
      return { 
        text: '无数据', 
        tooltip: 'Agent 已连接并尝试采集，但未能获取到 IP 地址。可能是系统未配置该类型的 IP 地址（如未启用 IPv6 或没有公网 IP）。' 
      }
    } else {
      return { 
        text: '无数据', 
        tooltip: 'Agent 已连接并尝试采集，但未能获取到数据。' 
      }
    }
  }
  
  // not_collected
  return { 
    text: '未采集', 
    tooltip: 'Agent 未连接或代码未更新，请检查 Agent 状态并确保已部署最新版本。' 
  }
}

// 判断数组字段（IP地址）的状态
const getArrayFieldStatus = (fieldValue: any[] | null | undefined): 'has_value' | 'not_collected' | 'no_data' => {
  // 如果有值且数组不为空，返回有值
  if (fieldValue && Array.isArray(fieldValue) && fieldValue.length > 0) {
    return 'has_value'
  }
  
  // 检查 Agent 是否已连接（通过 last_heartbeat 判断）
  const hasRecentHeartbeat = props.host?.last_heartbeat && 
    (new Date().getTime() - new Date(props.host.last_heartbeat).getTime()) < 5 * 60 * 1000 // 5分钟内有心跳
  
  if (hasRecentHeartbeat) {
    // Agent 已连接，但字段为空，说明采集了但没有数据
    return 'no_data'
  } else {
    // Agent 未连接或很久没心跳，说明未采集
    return 'not_collected'
  }
}

// 获取数组字段状态的显示文本和提示
const getArrayFieldStatusText = (fieldValue: any[] | null | undefined, fieldLabel: string): { text: string, tooltip: string } => {
  const status = getArrayFieldStatus(fieldValue)
  
  if (status === 'has_value') {
    const ipList = fieldValue!.join(', ')
    return { text: fieldValue![0], tooltip: ipList }
  }
  
  if (status === 'no_data') {
    // 根据字段类型提供不同的提示
    if (fieldLabel.includes('公网')) {
      return { 
        text: '无数据', 
        tooltip: `Agent 已连接并尝试采集，但未能获取到${fieldLabel}。很多服务器没有公网 IP 地址是正常现象（仅配置内网 IP）。` 
      }
    } else if (fieldLabel.includes('IPv6')) {
      return { 
        text: '无数据', 
        tooltip: `Agent 已连接并尝试采集，但未能获取到${fieldLabel}。可能是系统未启用 IPv6 或网络接口未配置 IPv6 地址。` 
      }
    } else {
      return { 
        text: '无数据', 
        tooltip: `Agent 已连接并尝试采集，但未能获取到${fieldLabel}。` 
      }
    }
  }
  
  // not_collected
  return { 
    text: '未采集', 
    tooltip: 'Agent 未连接或代码未更新，请检查 Agent 状态并确保已部署最新版本。' 
  }
}

const handleSaveTags = async () => {
  if (!props.host?.host_id) return

  try {
    // 调用API更新标签
    await hostsApi.updateTags(props.host.host_id, editingTags.value)
    
    // 通过 emit 通知父组件更新
    emit('update:host', {
      ...props.host,
      tags: editingTags.value
    })
    
    message.success('标签保存成功')
    showTagModal.value = false
  } catch (error: any) {
    console.error('保存标签失败:', error)
    message.error(error?.message || '保存标签失败，请重试')
  }
}

const handleCancelTags = () => {
  showTagModal.value = false
  editingTags.value = []
}

// 通用的复制文本方法
const copyText = async (text: string | undefined, label: string = '内容') => {
  if (!text) return
  
  try {
    await navigator.clipboard.writeText(text)
    message.success(`${label}已复制到剪贴板`)
  } catch (err) {
    // 降级方案：使用传统方法
    const textArea = document.createElement('textarea')
    textArea.value = text
    textArea.style.position = 'fixed'
    textArea.style.opacity = '0'
    document.body.appendChild(textArea)
    textArea.select()
    try {
      document.execCommand('copy')
      message.success(`${label}已复制到剪贴板`)
    } catch {
      message.error('复制失败，请手动复制')
    }
    document.body.removeChild(textArea)
  }
}

// 格式化字节大小
const formatBytes = (bytes: number): string => {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  const value = bytes / Math.pow(k, i)
  return `${value.toFixed(2)} ${sizes[i]}`
}

// 解析磁盘信息
const parsedDiskInfo = computed<DiskInfo[]>(() => {
  if (!props.host?.disk_info) {
    return []
  }
  
  try {
    const diskInfo = JSON.parse(props.host.disk_info) as DiskInfo[]
    return Array.isArray(diskInfo) ? diskInfo : []
  } catch (error) {
    console.error('解析磁盘信息失败:', error)
    return []
  }
})

// 解析网卡信息
const parsedNetworkInterfaces = computed<NetworkInterfaceInfo[]>(() => {
  if (!props.host?.network_interfaces) {
    return []
  }
  
  try {
    const networkInterfaces = JSON.parse(props.host.network_interfaces) as NetworkInterfaceInfo[]
    return Array.isArray(networkInterfaces) ? networkInterfaces : []
  } catch (error) {
    console.error('解析网卡信息失败:', error)
    return []
  }
})

// 磁盘信息表格列定义
const diskColumns = [
  {
    title: '设备路径',
    key: 'device',
    dataIndex: 'device',
    width: 150,
  },
  {
    title: '挂载点',
    key: 'mount_point',
    dataIndex: 'mount_point',
    width: 150,
  },
  {
    title: '文件系统',
    key: 'file_system',
    dataIndex: 'file_system',
    width: 100,
  },
  {
    title: '总大小',
    key: 'total_size',
    dataIndex: 'total_size',
    width: 120,
  },
  {
    title: '已用',
    key: 'used_size',
    dataIndex: 'used_size',
    width: 120,
  },
  {
    title: '可用',
    key: 'available_size',
    dataIndex: 'available_size',
    width: 120,
  },
  {
    title: '使用率',
    key: 'usage_percent',
    dataIndex: 'usage_percent',
    width: 200,
  },
]

// 网卡信息表格列定义
const networkColumns = [
  {
    title: '接口名称',
    key: 'interface_name',
    dataIndex: 'interface_name',
    width: 120,
  },
  {
    title: 'MAC地址',
    key: 'mac_address',
    dataIndex: 'mac_address',
    width: 150,
  },
  {
    title: 'IPv4地址',
    key: 'ipv4_addresses',
    dataIndex: 'ipv4_addresses',
    width: 200,
  },
  {
    title: 'IPv6地址',
    key: 'ipv6_addresses',
    dataIndex: 'ipv6_addresses',
    width: 250,
  },
  {
    title: 'MTU',
    key: 'mtu',
    dataIndex: 'mtu',
    width: 80,
  },
  {
    title: '状态',
    key: 'state',
    dataIndex: 'state',
    width: 100,
  },
]


onMounted(() => {
  loadOverviewData()
  loadComponents()
})
</script>

<style scoped lang="less">
.host-overview {
  width: 100%;
}

.main-content {
  width: 100%;
}

.content-section {
  width: 100%;
}

.host-info-card {
  margin-bottom: 16px;
  border-radius: 8px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03),
    0 2px 4px rgba(0, 0, 0, 0.04),
    0 4px 8px rgba(0, 0, 0, 0.04);
  border: none;
}

.host-info-card :deep(.ant-card-head) {
  border-bottom: 1px solid var(--mxsec-border);
  padding: 16px 16px;
}

.host-info-card :deep(.ant-card-head-title) {
  font-size: 16px;
  font-weight: 600;
  color: var(--mxsec-text-1);
}

.host-info-card :deep(.ant-card-body) {
  padding: 20px 16px;
}

.host-info-container {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 24px 16px;
  width: 100%;
}

.info-column {
  display: flex;
  flex-direction: column;
  min-width: 0;
}

.info-group {
  display: flex;
  flex-direction: column;
  gap: 0;
}

.info-item {
  display: grid;
  grid-template-columns: 100px 1fr;
  align-items: center;
  padding: 12px 0;
  border-bottom: 1px solid var(--mxsec-border-light);
  min-height: 44px;
  gap: 8px;
}

.info-item:last-child {
  border-bottom: none;
}

.info-label {
  font-size: 14px;
  font-weight: 500;
  color: var(--mxsec-text-1);
  text-align: left;
  line-height: 20px;
  white-space: nowrap;
  flex-shrink: 0;
}

.info-value {
  font-size: 14px;
  color: var(--mxsec-text-2);
  line-height: 20px;
  word-break: break-word;
  min-width: 0;
  overflow: hidden;
}

.info-value.empty-value {
  color: rgba(0, 0, 0, 0.25);
  font-style: normal;
}

/* 无数据状态（Agent 已连接但采集不到数据，如容器环境） */
.info-value.empty-value.status-no-data {
  color: var(--mxsec-text-3);
  font-style: italic;
}

/* 可复制文本通用样式 */
.copyable-text {
  display: inline-block;
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  line-height: 1.5;
  cursor: pointer;
  user-select: none;
  transition: color 0.2s;
  vertical-align: middle;
}

.copyable-text:hover {
  color: var(--mxsec-primary);
  text-decoration: underline;
}

.cpu-info-text:hover {
  color: var(--mxsec-primary);
}


.status-tag {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 8px;
  border: none;
  font-weight: 500;
}

.status-dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  display: inline-block;
  flex-shrink: 0;
}

.status-dot.online {
  background-color: #22C55E;
  box-shadow: 0 0 0 2px rgba(82, 196, 26, 0.2);
}

.status-dot.offline {
  background-color: #EF4444;
  box-shadow: 0 0 0 2px rgba(255, 77, 79, 0.2);
}

/* 安全态势概览 */
.risk-overview-container {
  display: flex;
  flex-direction: column;
  gap: 16px;
  margin-bottom: 16px;
}

.risk-overview-row {
  display: grid;
  gap: 16px;
}

.risk-overview-row.first-row {
  grid-template-columns: repeat(3, 1fr);
}

.risk-overview-row.second-row {
  grid-template-columns: repeat(2, 1fr);
}

.risk-card {
  flex: 1;
  background: var(--mxsec-card-bg);
  border: none;
  border-radius: 8px;
  padding: 16px;
  display: flex;
  flex-direction: column;
  position: relative;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03),
    0 2px 4px rgba(0, 0, 0, 0.04),
    0 4px 8px rgba(0, 0, 0, 0.04);
  transition: all 0.3s ease;

  &:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08),
      0 8px 24px rgba(0, 0, 0, 0.06);
  }
}

.risk-card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  padding-bottom: 12px;
  border-bottom: 1px solid var(--mxsec-border-light);
}

.risk-card-title {
  font-size: 14px;
  font-weight: 500;
  color: var(--mxsec-text-1);
}

.risk-card-title-with-tags {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.risk-card-link {
  padding: 0;
  height: auto;
  font-size: 12px;
  color: var(--mxsec-primary);
}

.risk-card-content {
  flex: 1;
  display: flex;
  flex-direction: row;
  align-items: center;
  gap: 20px;
  padding: 8px 0;
  min-height: 0;
}

.risk-left-section {
  display: flex;
  flex-direction: row;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}

.risk-unprocessed {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 4px;
}

.risk-unprocessed-label {
  font-size: 12px;
  color: var(--mxsec-text-2);
  line-height: 1.2;
}

.risk-unprocessed-value {
  font-size: 28px;
  font-weight: 600;
  color: var(--mxsec-text-1);
  line-height: 1;
}

.risk-ring-wrapper {
  width: 70px;
  height: 70px;
  display: flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.risk-ring {
  width: 70px;
  height: 70px;
  border: 3px solid #e8e8e8;
  border-radius: 50%;
  background: var(--mxsec-fill-1);
  transition: all 0.3s;
}

.risk-ring.has-risk {
  border-color: #ff7a45;
  background: linear-gradient(135deg, #fff2e8 0%, #fff7e6 100%);
  box-shadow: 0 0 0 4px rgba(255, 122, 69, 0.08);
}

.risk-stats {
  flex: 1;
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  grid-template-rows: repeat(2, 1fr);
  gap: 6px 16px;
  align-content: center;
  justify-items: start;
}

.risk-stat-item {
  display: flex;
  align-items: center;
  gap: 6px;
  padding: 0;
  height: 22px;
  line-height: 22px;
  width: 100%;
}

.risk-stat-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  flex-shrink: 0;
}

.risk-stat-dot.critical {
  background-color: #EF4444;
  box-shadow: 0 0 0 2px rgba(255, 77, 79, 0.15);
}

.risk-stat-dot.high {
  background-color: #ff7a45;
  box-shadow: 0 0 0 2px rgba(255, 122, 69, 0.15);
}

.risk-stat-dot.medium {
  background-color: #F59E0B;
  box-shadow: 0 0 0 2px rgba(250, 173, 20, 0.15);
}

.risk-stat-dot.low {
  background-color: var(--mxsec-primary);
  box-shadow: 0 0 0 2px rgba(24, 144, 255, 0.15);
}

.risk-stat-label {
  font-size: 12px;
  color: var(--mxsec-text-2);
  white-space: nowrap;
}

.risk-stat-value {
  font-size: 12px;
  font-weight: 500;
  color: var(--mxsec-text-1);
  margin-left: auto;
}

.baseline-tags {
  display: flex;
  align-items: center;
  gap: 4px;
}


/* 资产指纹 */
.fingerprint-section {
  background: var(--mxsec-card-bg);
  border: none;
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03),
    0 2px 4px rgba(0, 0, 0, 0.04),
    0 4px 8px rgba(0, 0, 0, 0.04);
}

.fingerprint-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 20px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--mxsec-border);
}

.fingerprint-title {
  font-size: 16px;
  font-weight: 600;
  color: var(--mxsec-text-1);
}

.fingerprint-link {
  padding: 0;
  height: auto;
  font-size: 14px;
}

.fingerprint-grid {
  display: grid;
  grid-template-columns: repeat(8, 1fr);
  gap: 12px;
}

.fingerprint-item {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 20px;
  background: var(--mxsec-fill-1);
  border: 1px solid var(--mxsec-border);
  border-radius: 8px;
  transition: all 0.3s ease;
  cursor: pointer;
}

.fingerprint-item:hover {
  background: var(--mxsec-primary-bg);
  border-color: #91d5ff;
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(24, 144, 255, 0.12);
}

.fingerprint-value {
  font-size: 28px;
  font-weight: 600;
  color: var(--mxsec-text-1);
  margin-bottom: 8px;
  line-height: 1;
}

.fingerprint-label {
  font-size: 14px;
  color: var(--mxsec-text-2);
  text-align: center;
}

/* 磁盘/网卡/组件 Card 优化 */
.content-section :deep(.ant-card) {
  border-radius: 8px;
  border: none;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.03),
    0 2px 4px rgba(0, 0, 0, 0.04),
    0 4px 8px rgba(0, 0, 0, 0.04);
  margin-bottom: 16px;
}

.content-section :deep(.ant-card .ant-card-head) {
  border-bottom: 1px solid var(--mxsec-border);
}

.content-section :deep(.ant-card .ant-card-head-title) {
  font-size: 16px;
  font-weight: 600;
}

/* 响应式设计 */
@media (max-width: 1400px) {
  .host-info-container {
    gap: 20px 12px;
  }
  
  .info-item {
    grid-template-columns: 95px 1fr;
  }
  
  .info-label {
    font-size: 13px;
  }
  
  .info-value {
    font-size: 13px;
  }
  
  .fingerprint-grid {
    grid-template-columns: repeat(8, 1fr);
    gap: 10px;
  }
  
  .fingerprint-item {
    padding: 16px 12px;
  }
  
  .fingerprint-value {
    font-size: 24px;
  }
  
  .fingerprint-label {
    font-size: 13px;
  }
}

@media (max-width: 1200px) {
  .host-info-container {
    grid-template-columns: repeat(2, 1fr);
    gap: 0;
  }
  
  .info-item {
    grid-template-columns: 100px 1fr;
    border-bottom: 1px solid var(--mxsec-border-light);
  }
  
  .info-item:last-child {
    border-bottom: 1px solid var(--mxsec-border-light);
  }
  
  .info-group:last-child .info-item:last-child {
    border-bottom: none;
  }
  
  .risk-overview-row.first-row {
    grid-template-columns: repeat(2, 1fr);
  }
  
  .risk-overview-row.second-row {
    grid-template-columns: 1fr;
  }
  
  .fingerprint-grid {
    grid-template-columns: repeat(4, 1fr);
    gap: 12px;
  }
}

@media (max-width: 768px) {
  .host-info-container {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 768px) {
  .fingerprint-grid {
    grid-template-columns: repeat(4, 1fr);
    gap: 8px;
  }
  
  .fingerprint-item {
    padding: 12px 8px;
  }
  
  .fingerprint-value {
    font-size: 20px;
  }
  
  .fingerprint-label {
    font-size: 12px;
  }
  
  .risk-overview-row.first-row,
  .risk-overview-row.second-row {
    grid-template-columns: 1fr;
  }
  
  .risk-card-content {
    flex-direction: column;
    align-items: center;
    gap: 16px;
  }
  
  .risk-left-section {
    width: 100%;
    justify-content: center;
  }
  
  .risk-stats {
    width: 100%;
  }
}

.host-overview-empty {
  display: flex;
  justify-content: center;
  align-items: center;
  min-height: 300px;
}
</style>
