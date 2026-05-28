<template>
  <div class="linux-install-guide">
    <!-- 支持的操作系统 -->
    <div class="section">
      <h3>支持的操作系统类型及版本</h3>
      <div class="os-list">
        <div class="os-item">
          <span class="os-badge">CentOS</span>
          <span>CentOS 7/8/9</span>
        </div>
        <div class="os-item">
          <span class="os-badge">RHEL</span>
          <span>Red Hat 7/8/9</span>
        </div>
        <div class="os-item">
          <span class="os-badge">Rocky</span>
          <span>Rocky Linux 8/9</span>
        </div>
        <div class="os-item">
          <span class="os-badge">Debian</span>
          <span>Debian 10/11/12</span>
        </div>
        <div class="os-item">
          <span class="os-badge">Ubuntu</span>
          <span>Ubuntu 18.04/20.04/22.04</span>
        </div>
      </div>
    </div>

    <!-- 前置要求 -->
    <div class="section">
      <h3>前置要求</h3>
      <a-alert type="info" show-icon class="prereq-alert">
        <template #message>
          <div>
            <p><strong>1. 组件包上传</strong>：请先在 <router-link to="/system/components">系统管理 &gt; 组件列表</router-link> 中上传 Agent 安装包（RPM/DEB）。</p>
            <p><strong>2. 服务器地址配置</strong>：请配置正确的服务器地址，确保目标主机可以访问。</p>
          </div>
        </template>
      </a-alert>
    </div>

    <!-- 服务器地址配置 -->
    <div class="section">
      <h3>服务器地址配置</h3>
      <a-card :bordered="false" class="config-card">
        <a-form layout="inline">
          <a-form-item label="HTTP 服务器地址">
            <a-input
              v-model:value="httpServerAddress"
              placeholder="例如: 192.168.1.100:8080"
              style="width: 250px"
            />
            <a-tooltip title="后端 Manager HTTP API 地址（端口 8080），用于下载安装包。curl 命令会自动使用前端地址（3000）下载安装脚本。">
              <QuestionCircleOutlined style="margin-left: 8px; color: #999" />
            </a-tooltip>
          </a-form-item>
          <a-form-item label="gRPC 服务器地址">
            <a-input
              v-model:value="grpcServerAddress"
              placeholder="例如: 192.168.1.100:6751"
              style="width: 250px"
            />
            <a-tooltip title="AgentCenter gRPC 地址（端口 6751），Agent 连接此地址上报数据">
              <QuestionCircleOutlined style="margin-left: 8px; color: #999" />
            </a-tooltip>
          </a-form-item>
        </a-form>
        <div v-if="isLocalhost" class="warning-tip">
          <WarningOutlined style="color: #F59E0B" />
          <span>检测到您正在使用 localhost 访问，请输入服务器的实际 IP 地址。</span>
        </div>
      </a-card>
    </div>

    <!-- 安装步骤 -->
    <div class="section">
      <h3>安装步骤</h3>

      <!-- 步骤1：复制客户端安装命令 -->
      <div class="step">
        <h4>步骤1：复制客户端安装命令</h4>

        <a-tabs v-model:activeKey="installMethod" type="card">
          <!-- 一键安装 -->
          <a-tab-pane key="auto" tab="一键安装">
            <p class="method-desc">使用一键安装脚本自动检测系统并安装对应版本：</p>
            <div class="command-box">
              <code class="command">{{ autoInstallCommand }}</code>
              <a-button type="link" @click="copyCommand(autoInstallCommand)" class="copy-btn">
                <template #icon><CopyOutlined /></template>
                复制命令
              </a-button>
            </div>
          </a-tab-pane>

          <!-- 手动安装 -->
          <a-tab-pane key="manual" tab="手动安装">
            <p class="method-desc">根据操作系统选择对应的包管理器安装：</p>

            <div class="manual-install-options">
              <a-radio-group v-model:value="manualPkgType" button-style="solid">
                <a-radio-button value="rpm">RPM (CentOS/RHEL/Rocky)</a-radio-button>
                <a-radio-button value="deb">DEB (Debian/Ubuntu)</a-radio-button>
              </a-radio-group>
            </div>

            <div class="command-box">
              <code class="command">{{ manualInstallCommand }}</code>
              <a-button type="link" @click="copyCommand(manualInstallCommand)" class="copy-btn">
                <template #icon><CopyOutlined /></template>
                复制命令
              </a-button>
            </div>
          </a-tab-pane>
        </a-tabs>

        <!-- 高级选项 -->
        <a-collapse :bordered="false" class="advanced-options">
          <a-collapse-panel key="1" header="高级选项">
            <div class="form-item">
              <label>选择业务线（可选）：</label>
              <a-select
                v-model:value="selectedBusinessLine"
                placeholder="请选择业务线（不选择则不绑定）"
                allow-clear
                show-search
                :filter-option="filterBusinessLineOption"
                style="width: 300px"
              >
                <a-select-option v-for="bl in businessLines" :key="bl.code" :value="bl.code">
                  {{ bl.name }} ({{ bl.code }})
                </a-select-option>
              </a-select>
            </div>
            <p v-if="selectedBusinessLine" class="tip" style="margin-top: 8px">
              <InfoCircleOutlined /> 已选择业务线，上方安装命令已自动包含业务线配置
            </p>
          </a-collapse-panel>
        </a-collapse>
      </div>

      <!-- 步骤2：在目标主机上以管理员权限执行安装命令 -->
      <div class="step">
        <h4>步骤2：在目标主机上以管理员权限执行安装命令</h4>
        <p class="tip">
          <InfoCircleOutlined /> Linux 系统的管理员一般是 <code>root</code> 用户，请确保以管理员权限执行安装命令。
        </p>
      </div>

      <!-- 步骤3：检查安装是否成功 -->
      <div class="step">
        <h4>步骤3：检查安装是否成功</h4>

        <!-- 3.1 检查Agent运行状态 -->
        <div class="sub-step">
          <h5>3.1 检查 Agent 运行状态</h5>
          <p>执行以下命令检查 Agent 是否正常运行：</p>
          <div class="command-box">
            <code class="command">{{ statusCommand }}</code>
            <a-button type="link" @click="copyCommand(statusCommand)" class="copy-btn">
              <template #icon><CopyOutlined /></template>
              复制命令
            </a-button>
          </div>
          <p class="tip">
            如果输出结果中显示 <code>Active: active (running)</code> 字样，则表示安装启动成功。
          </p>
        </div>

        <!-- 3.2 检查Agent网络连通性 -->
        <div class="sub-step">
          <h5>3.2 检查 Agent 网络连通性</h5>
          <p>在确认 Agent 运行正常后，执行以下命令检查网络连通性：</p>
          <div class="command-box">
            <code class="command">{{ logCommand }}</code>
            <a-button type="link" @click="copyCommand(logCommand)" class="copy-btn">
              <template #icon><CopyOutlined /></template>
              复制命令
            </a-button>
          </div>
          <p class="tip">
            如果日志中显示 <code>connected to server</code> 或类似的连接成功信息，则视为网络畅通。
          </p>
        </div>

        <!-- 3.3 总结 -->
        <div class="sub-step">
          <h5>3.3 总结</h5>
          <p class="tip success">
            如果"步骤一"和"步骤二"都显示预期结果，则表示 Agent 安装成功。约 1-2 分钟后，主机将出现在 <router-link to="/hosts">主机列表</router-link> 中。
          </p>
        </div>
      </div>
    </div>

    <!-- 卸载方法 -->
    <div class="section">
      <h3>卸载方法</h3>

      <a-tabs type="card">
        <a-tab-pane key="auto" tab="一键卸载">
          <div class="command-box">
            <code class="command">{{ uninstallCommand }}</code>
            <a-button type="link" @click="copyCommand(uninstallCommand)" class="copy-btn">
              <template #icon><CopyOutlined /></template>
              复制命令
            </a-button>
          </div>
        </a-tab-pane>
        <a-tab-pane key="manual" tab="手动卸载">
          <div class="manual-install-options">
            <a-radio-group v-model:value="uninstallPkgType" button-style="solid">
              <a-radio-button value="rpm">RPM (CentOS/RHEL/Rocky)</a-radio-button>
              <a-radio-button value="deb">DEB (Debian/Ubuntu)</a-radio-button>
            </a-radio-group>
          </div>
          <div class="command-box">
            <code class="command">{{ manualUninstallCommand }}</code>
            <a-button type="link" @click="copyCommand(manualUninstallCommand)" class="copy-btn">
              <template #icon><CopyOutlined /></template>
              复制命令
            </a-button>
          </div>
        </a-tab-pane>
      </a-tabs>
    </div>

    <!-- 常见问题 -->
    <div class="section">
      <h3>常见问题</h3>
      <a-collapse :bordered="false">
        <a-collapse-panel key="1" header="Agent 无法连接到服务器">
          <ul>
            <li>检查防火墙是否开放 gRPC 端口（默认 6751）</li>
            <li>确认服务器地址配置正确（不能是 localhost 或 127.0.0.1）</li>
            <li>检查 AgentCenter 服务是否正常运行</li>
          </ul>
        </a-collapse-panel>
        <a-collapse-panel key="2" header="下载安装包失败">
          <ul>
            <li>确认已在组件列表中上传对应架构的安装包</li>
            <li>检查 HTTP 服务器端口（默认 8080）是否可访问</li>
            <li>检查目标主机的网络连通性</li>
          </ul>
        </a-collapse-panel>
        <a-collapse-panel key="3" header="Agent 启动后无法上报数据">
          <ul>
            <li>检查 Agent 日志：<code>journalctl -u mxsec-agent -f</code></li>
            <li>确认 mTLS 证书配置正确（如果启用）</li>
            <li>检查 SELinux 或 AppArmor 是否阻止了通信</li>
          </ul>
        </a-collapse-panel>
      </a-collapse>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import {
  CopyOutlined,
  InfoCircleOutlined,
  QuestionCircleOutlined,
  WarningOutlined,
} from '@ant-design/icons-vue'
import { businessLinesApi, type BusinessLine } from '@/api/business-lines'

// 服务器地址配置
const httpServerAddress = ref('')
const grpcServerAddress = ref('')

// 检测是否使用 localhost
const isLocalhost = computed(() => {
  const host = window.location.hostname
  return host === 'localhost' || host === '127.0.0.1' || host === '::1'
})

// 初始化服务器地址
const initServerAddresses = () => {
  const hostname = window.location.hostname

  // 如果是 localhost，提示用户输入实际地址
  if (isLocalhost.value) {
    httpServerAddress.value = ''
    grpcServerAddress.value = ''
  } else {
    // HTTP 服务器地址：后端 Manager API 端口 8080（用于下载安装包）
    httpServerAddress.value = `${hostname}:8080`
    // gRPC 地址：AgentCenter 端口 6751
    grpcServerAddress.value = `${hostname}:6751`
  }
}

// 安装方式
const installMethod = ref<'auto' | 'manual'>('auto')
const manualPkgType = ref<'rpm' | 'deb'>('rpm')
const uninstallPkgType = ref<'rpm' | 'deb'>('rpm')

// 业务线
const selectedBusinessLine = ref<string>('')
const businessLines = ref<BusinessLine[]>([])

// 安装命令
const autoInstallCommand = computed(() => {
  const httpAddr = httpServerAddress.value || 'YOUR_HTTP_SERVER:8080'
  const grpcAddr = grpcServerAddress.value || 'YOUR_GRPC_SERVER:6751'
  // curl 通过当前访问地址获取脚本（nginx 代理 /agent 路径）
  // MXSEC_HTTP_SERVER 使用后端地址（8080），因为脚本内部需要下载安装包
  const hostname = window.location.hostname
  const port = window.location.port
  // 开发环境（3000）或生产环境（80/空）都通过当前地址访问
  const curlAddr = port && port !== '80' && port !== '443' ? `${hostname}:${port}` : hostname
  let envVars = `MXSEC_HTTP_SERVER=${httpAddr} MXSEC_AGENT_SERVER=${grpcAddr}`
  // 如果选择了业务线，添加到环境变量
  if (selectedBusinessLine.value) {
    envVars += ` MXSEC_BUSINESS_LINE=${selectedBusinessLine.value}`
  }
  return `${envVars} bash -c "$(curl -fsSL http://${curlAddr}/agent/install.sh)"`
})

const manualInstallCommand = computed(() => {
  const httpAddr = httpServerAddress.value || 'YOUR_HTTP_SERVER:8080'
  const arch = 'amd64' // 可以根据需要扩展

  if (manualPkgType.value === 'rpm') {
    return `curl -fsSL -o mxsec-agent.rpm http://${httpAddr}/api/v1/agent/download/rpm/${arch} && yum install -y ./mxsec-agent.rpm && rm -f mxsec-agent.rpm`
  } else {
    return `curl -fsSL -o mxsec-agent.deb http://${httpAddr}/api/v1/agent/download/deb/${arch} && apt-get install -y ./mxsec-agent.deb && rm -f mxsec-agent.deb`
  }
})

const statusCommand = 'systemctl status mxsec-agent'
const logCommand = 'journalctl -u mxsec-agent -n 50 --no-pager | grep -i connect'

const uninstallCommand = computed(() => {
  // curl 通过当前访问地址获取脚本（nginx 代理 /agent 路径）
  const hostname = window.location.hostname
  const port = window.location.port
  // 开发环境（3000）或生产环境（80/空）都通过当前地址访问
  const curlAddr = port && port !== '80' && port !== '443' ? `${hostname}:${port}` : hostname
  return `bash -c "$(curl -fsSL http://${curlAddr}/agent/uninstall.sh)"`
})

const manualUninstallCommand = computed(() => {
  if (uninstallPkgType.value === 'rpm') {
    return 'systemctl stop mxsec-agent && yum remove -y mxsec-agent'
  } else {
    return 'systemctl stop mxsec-agent && apt-get remove -y mxsec-agent'
  }
})

// 加载业务线列表
const loadBusinessLines = async () => {
  try {
    const response = await businessLinesApi.list({ enabled: 'true', page_size: 1000 })
    businessLines.value = response.items || []
  } catch (error) {
    console.error('加载业务线列表失败:', error)
  }
}

// 业务线筛选选项过滤
const filterBusinessLineOption = (input: string, option: any) => {
  const text = option.children?.[0]?.children || ''
  return text.toLowerCase().indexOf(input.toLowerCase()) >= 0
}

// 复制命令
const copyCommand = async (command: string) => {
  try {
    await navigator.clipboard.writeText(command)
    message.success('命令已复制到剪贴板')
  } catch (err) {
    const textArea = document.createElement('textarea')
    textArea.value = command
    textArea.style.position = 'fixed'
    textArea.style.opacity = '0'
    document.body.appendChild(textArea)
    textArea.select()
    try {
      document.execCommand('copy')
      message.success('命令已复制到剪贴板')
    } catch (e) {
      message.error('复制失败，请手动复制')
    }
    document.body.removeChild(textArea)
  }
}

onMounted(() => {
  initServerAddresses()
  loadBusinessLines()
})
</script>

<style scoped>
.linux-install-guide {
  padding: 16px 0;
}

.section {
  margin-bottom: 32px;
}

.section h3 {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 16px;
  color: var(--mxsec-text-1);
}

.prereq-alert {
  margin-bottom: 16px;
}

.prereq-alert p {
  margin: 4px 0;
}

.config-card {
  background: var(--mxsec-fill-1);
}

.warning-tip {
  margin-top: 12px;
  padding: 8px 12px;
  background: var(--mxsec-card-bg)be6;
  border: 1px solid #ffe58f;
  border-radius: 4px;
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  color: #614700;
}

.step {
  margin-bottom: 24px;
  padding-left: 24px;
  border-left: 2px solid #e8e8e8;
}

.step h4 {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 12px;
  color: #595959;
}

.sub-step {
  margin-bottom: 16px;
  padding-left: 16px;
}

.sub-step h5 {
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 8px;
  color: var(--mxsec-text-3);
}

.os-list {
  display: flex;
  flex-wrap: wrap;
  gap: 24px;
  margin-bottom: 16px;
}

.os-item {
  display: flex;
  align-items: center;
  gap: 8px;
}

.os-badge {
  display: inline-block;
  padding: 4px 12px;
  background: var(--mxsec-fill-3);
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  color: #595959;
  min-width: 70px;
  text-align: center;
}

.method-desc {
  margin-bottom: 12px;
  color: #595959;
}

.manual-install-options {
  margin-bottom: 12px;
}

.command-box {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  padding: 12px;
  background: var(--mxsec-fill-2);
  border-radius: 4px;
  margin: 12px 0;
  position: relative;
}

.command {
  flex: 1;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', 'source-code-pro', monospace;
  font-size: 13px;
  color: var(--mxsec-text-1);
  word-break: break-all;
  white-space: pre-wrap;
  line-height: 1.6;
}

.copy-btn {
  flex-shrink: 0;
}

.advanced-options {
  margin-top: 12px;
  background: transparent;
}

.form-item {
  margin-bottom: 12px;
}

.form-item label {
  display: block;
  margin-bottom: 8px;
  color: #595959;
  font-size: 13px;
  font-weight: 500;
}

.tip {
  margin: 8px 0;
  padding: 8px 12px;
  background: var(--mxsec-primary-bg);
  border-left: 3px solid #3B82F6;
  border-radius: 2px;
  color: #595959;
  font-size: 13px;
}

.tip.success {
  background: var(--mxsec-success-bg);
  border-left-color: #22C55E;
}

.tip code {
  background: var(--mxsec-card-bg);
  padding: 2px 6px;
  border-radius: 2px;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', 'source-code-pro', monospace;
  font-size: 12px;
  color: var(--mxsec-primary);
}

p {
  margin: 8px 0;
  color: #595959;
  font-size: 13px;
  line-height: 1.6;
}

:deep(.ant-collapse-header) {
  font-weight: 500;
}

:deep(.ant-collapse-content-box) {
  padding-left: 24px;
}

:deep(.ant-collapse-content-box ul) {
  margin: 0;
  padding-left: 20px;
}

:deep(.ant-collapse-content-box li) {
  margin-bottom: 8px;
  color: #595959;
}

:deep(.ant-collapse-content-box code) {
  background: var(--mxsec-fill-2);
  padding: 2px 6px;
  border-radius: 2px;
  font-family: monospace;
  font-size: 12px;
}
</style>
