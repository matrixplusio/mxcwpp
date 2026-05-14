<template>
  <div class="kubernetes-install-guide">
    <!-- 支持的操作系统 -->
    <div class="section">
      <h3>支持的操作系统类型及版本</h3>
      <div class="os-list">
        <div class="os-item">
          <span class="os-badge">Kubernetes</span>
          <span>Kubernetes 1.20 及以上版本</span>
        </div>
      </div>
    </div>

    <!-- Agent 部署指引 -->
    <div class="section">
      <h3>在 Kubernetes 上部署 Agent 操作指引</h3>
      
      <div class="config-form">
        <div class="form-item">
          <label>仓库镜像地址：</label>
          <a-input
            v-model:value="imageRepository"
            placeholder="请输入镜像仓库地址"
            style="width: 400px;"
            :disabled="configLoading"
          />
        </div>
        
        <div class="form-item">
          <label>请选择版本号：</label>
          <a-select
            v-model:value="selectedVersion"
            placeholder="请选择版本号"
            style="width: 200px;"
            :loading="configLoading"
          >
            <a-select-option v-for="version in versions" :key="version" :value="version">
              {{ version }}
            </a-select-option>
          </a-select>
        </div>
        
        <div class="form-item">
          <a-button type="primary" @click="generateManifest" :loading="generating" :disabled="!imageRepository || !selectedVersion">
            生成镜像和操作指引
          </a-button>
        </div>
      </div>

      <!-- 业务线选择（可选） -->
      <div class="form-item" style="margin-top: 16px;">
        <label>选择业务线（可选）：</label>
        <a-select
          v-model:value="selectedBusinessLine"
          placeholder="请选择业务线（不选择则不绑定）"
          allow-clear
          show-search
          :filter-option="filterBusinessLineOption"
          style="width: 300px;"
        >
          <a-select-option v-for="bl in businessLines" :key="bl.code" :value="bl.code">
            {{ bl.name }} ({{ bl.code }})
          </a-select-option>
        </a-select>
      </div>

      <!-- 生成的配置和指引 -->
      <div v-if="generatedManifest" class="generated-content">
        <a-tabs v-model:activeKey="manifestTab" type="card">
          <!-- 步骤1：镜像下载 -->
          <a-tab-pane key="step1" tab="步骤1：镜像下载">
            <div class="step-content">
              <h4>镜像下载链接：</h4>
              <div class="command-box">
                <code class="command">{{ imageDownloadUrl }}</code>
                <a-button type="link" @click="copyCommand(imageDownloadUrl)" class="copy-btn">
                  <template #icon><CopyOutlined /></template>
                  复制命令
                </a-button>
              </div>
              <p class="tip">
                请下载镜像文件到本地，然后按照步骤2推送到您的镜像仓库。
              </p>
            </div>
          </a-tab-pane>

          <!-- 步骤2：推送镜像 -->
          <a-tab-pane key="step2" tab="步骤2：推送镜像">
            <div class="step-content">
              <h4>将下载的镜像通过下面命令推送到镜像仓库，并确定集群能访问到制作好的镜像所在的镜像仓库：</h4>
              <div class="command-box">
                <code class="command">{{ dockerLoadCommand }}</code>
                <a-button type="link" @click="copyCommand(dockerLoadCommand)" class="copy-btn">
                  <template #icon><CopyOutlined /></template>
                  复制命令
                </a-button>
              </div>
              <div class="command-box">
                <code class="command">{{ dockerPushCommand }}</code>
                <a-button type="link" @click="copyCommand(dockerPushCommand)" class="copy-btn">
                  <template #icon><CopyOutlined /></template>
                  复制命令
                </a-button>
              </div>
            </div>
          </a-tab-pane>

          <!-- 步骤3：创建 Namespace -->
          <a-tab-pane key="step3" tab="步骤3：创建 Namespace">
            <div class="step-content">
              <h4>在集群中创建一个名字为 mxsec 的 namespace：</h4>
              <div class="command-box">
                <code class="command">{{ namespaceCommand }}</code>
                <a-button type="link" @click="copyCommand(namespaceCommand)" class="copy-btn">
                  <template #icon><CopyOutlined /></template>
                  复制命令
                </a-button>
              </div>
            </div>
          </a-tab-pane>

          <!-- 步骤4：应用配置 -->
          <a-tab-pane key="step4" tab="步骤4：应用配置">
            <div class="step-content">
              <h4>使用 kubectl apply -f 应用以下 yaml 文件：</h4>
              
              <!-- ConfigMap 配置 -->
              <div class="code-block">
                <div class="code-header">
                  <span>ConfigMap 配置</span>
                  <a-button type="link" size="small" @click="copyToClipboard(configMapYaml)">
                    <template #icon><CopyOutlined /></template>
                    复制配置
                  </a-button>
                </div>
                <pre><code>{{ configMapYaml }}</code></pre>
              </div>

              <!-- DaemonSet 配置 -->
              <div class="code-block" style="margin-top: 16px;">
                <div class="code-header">
                  <span>DaemonSet 配置</span>
                  <a-button type="link" size="small" @click="copyToClipboard(daemonsetYaml)">
                    <template #icon><CopyOutlined /></template>
                    复制配置
                  </a-button>
                </div>
                <pre><code>{{ daemonsetYaml }}</code></pre>
              </div>
            </div>
          </a-tab-pane>
        </a-tabs>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { CopyOutlined } from '@ant-design/icons-vue'
import { businessLinesApi, type BusinessLine } from '@/api/business-lines'
import { systemConfigApi } from '@/api/system-config'

// 获取当前页面的基础 URL（用于构建 Server 地址）
const getBaseUrl = () => {
  const protocol = window.location.protocol
  const host = window.location.host
  return `${protocol}//${host}`
}

const baseUrl = getBaseUrl()
const httpServer = baseUrl.replace(/^https?:\/\//, '')

// 表单数据
const imageRepository = ref('')
const selectedVersion = ref('')
const versions = ref<string[]>([])
const configLoading = ref(false)

// 业务线
const selectedBusinessLine = ref<string>('')
const businessLines = ref<BusinessLine[]>([])

// 生成状态
const generating = ref(false)
const generatedManifest = ref(false)
const manifestTab = ref('step1')

// 加载配置
const loadKubernetesConfig = async () => {
  configLoading.value = true
  try {
    const config = await systemConfigApi.getKubernetesImageConfig()
    // API 客户端已经处理了响应，直接返回数据
    imageRepository.value = config.repository || 'mxsec-platform/mxsec-agent'
    versions.value = config.versions || ['latest', 'v1.0.0']
    selectedVersion.value = config.default_version || 'latest'
  } catch (error) {
    console.error('加载 Kubernetes 镜像配置失败:', error)
    // 使用默认值
    imageRepository.value = 'mxsec-platform/mxsec-agent'
    versions.value = ['latest', 'v1.0.0']
    selectedVersion.value = 'latest'
  } finally {
    configLoading.value = false
  }
}

// 镜像下载 URL
const imageDownloadUrl = computed(() => {
  const imageName = imageRepository.value.replace(/\//g, '_')
  const version = selectedVersion.value
  return `${baseUrl}/api/v1/agent/download/image/${imageName}_${version}.tar`
})

// Docker 命令
const dockerLoadCommand = computed(() => {
  const imageName = imageRepository.value.replace(/\//g, '_')
  const version = selectedVersion.value
  return `docker load -i ${imageName}_${version}.tar`
})

const dockerPushCommand = computed(() => {
  const fullImage = selectedVersion.value === 'latest'
    ? `${imageRepository.value}:latest`
    : `${imageRepository.value}:${selectedVersion.value}`
  return `docker push ${fullImage}`
})

// 生成的 YAML 配置
const configMapYaml = computed(() => {
  const serverName = httpServer.split(':')[0]
  return `apiVersion: v1
kind: ConfigMap
metadata:
  name: mxsec-agent-config
  namespace: mxsec
data:
  cert: ""
  svr_name: "${serverName}"`
})

const daemonsetYaml = computed(() => {
  const image = selectedVersion.value === 'latest' 
    ? `${imageRepository.value}:latest`
    : `${imageRepository.value}:${selectedVersion.value}`
  
  const serverHost = httpServer.split(':')[0] + ':6751' // 假设 gRPC 端口是 6751
  
  let envVars = `
        - name: MXSEC_AGENT_SERVER
          value: "${serverHost}"`
  
  if (selectedBusinessLine.value) {
    envVars += `
        - name: MXSEC_BUSINESS_LINE
          value: "${selectedBusinessLine.value}"`
  }
  
  return `apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: mxsec-agent
  namespace: mxsec
  labels:
    app: mxsec-agent
spec:
  selector:
    matchLabels:
      app: mxsec-agent
  template:
    metadata:
      labels:
        app: mxsec-agent
    spec:
      containers:
      - name: mxsec-agent
        image: ${image}
        imagePullPolicy: IfNotPresent
        securityContext:
          privileged: true
        env:${envVars}
        resources:
          requests:
            cpu: 100m
            memory: 128Mi
          limits:
            cpu: 1000m
            memory: 512Mi
        volumeMounts:
        - name: host-root
          mountPath: /host
          readOnly: true
        - name: host-var-lib
          mountPath: /var/lib/mxsec-agent
        - name: host-var-log
          mountPath: /var/log/mxsec-agent
        - name: host-proc
          mountPath: /host/proc
          readOnly: true
        - name: host-sys
          mountPath: /host/sys
          readOnly: true
        - name: host-dev
          mountPath: /host/dev
          readOnly: true
      volumes:
      - name: host-root
        hostPath:
          path: /
      - name: host-var-lib
        hostPath:
          path: /var/lib/mxsec-agent
          type: DirectoryOrCreate
      - name: host-var-log
        hostPath:
          path: /var/log/mxsec-agent
          type: DirectoryOrCreate
      - name: host-proc
        hostPath:
          path: /proc
      - name: host-sys
        hostPath:
          path: /sys
      - name: host-dev
        hostPath:
          path: /dev
      hostNetwork: true
      hostPID: true
      tolerations:
      - key: node-role.kubernetes.io/master
        effect: NoSchedule
      - key: node-role.kubernetes.io/control-plane
        effect: NoSchedule`
})

// 部署命令
const namespaceCommand = 'kubectl create namespace mxsec'

// 生成配置
const generateManifest = () => {
  if (!imageRepository.value) {
    message.warning('请输入镜像仓库地址')
    return
  }
  
  if (!selectedVersion.value) {
    message.warning('请选择版本号')
    return
  }
  
  generating.value = true
  setTimeout(() => {
    generatedManifest.value = true
    generating.value = false
    message.success('配置生成成功')
    manifestTab.value = 'step1'
  }, 500)
}

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
  const text = option.children[0].children || ''
  return text.toLowerCase().indexOf(input.toLowerCase()) >= 0
}

// 复制到剪贴板
const copyToClipboard = async (text: string) => {
  try {
    await navigator.clipboard.writeText(text)
    message.success('已复制到剪贴板')
  } catch (err) {
    const textArea = document.createElement('textarea')
    textArea.value = text
    textArea.style.position = 'fixed'
    textArea.style.opacity = '0'
    document.body.appendChild(textArea)
    textArea.select()
    try {
      document.execCommand('copy')
      message.success('已复制到剪贴板')
    } catch (e) {
      message.error('复制失败，请手动复制')
    }
    document.body.removeChild(textArea)
  }
}

const copyCommand = async (command: string) => {
  await copyToClipboard(command)
}

onMounted(() => {
  loadKubernetesConfig()
  loadBusinessLines()
})
</script>

<style scoped>
.kubernetes-install-guide {
  padding: 16px 0;
}

.section {
  margin-bottom: 32px;
}

.section h3 {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 16px;
  color: #262626;
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
  background: #f0f0f0;
  border-radius: 4px;
  font-size: 12px;
  font-weight: 600;
  color: #595959;
  min-width: 60px;
  text-align: center;
}

.config-form {
  display: flex;
  flex-wrap: wrap;
  align-items: flex-end;
  gap: 16px;
  margin-bottom: 16px;
}

.form-item {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.form-item label {
  color: #595959;
  font-size: 13px;
  font-weight: 500;
}

.form-hint {
  margin-left: 8px;
  color: #86909C;
  font-size: 12px;
}

.generated-content {
  margin-top: 24px;
  padding: 16px;
  background: #F7F8FA;
  border-radius: 4px;
}

.step-content {
  padding: 16px 0;
}

.step-content h4 {
  font-size: 14px;
  font-weight: 600;
  margin-bottom: 16px;
  color: #262626;
}

.code-block {
  background: #fff;
  border: 1px solid #e8e8e8;
  border-radius: 4px;
  overflow: hidden;
  margin-top: 12px;
}

.code-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 8px 12px;
  background: #F2F3F5;
  border-bottom: 1px solid #e8e8e8;
  font-size: 13px;
  font-weight: 500;
  color: #595959;
}

.code-block pre {
  margin: 0;
  padding: 16px;
  background: #f8f8f8;
  overflow-x: auto;
  max-height: 500px;
  overflow-y: auto;
}

.code-block code {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', 'source-code-pro', monospace;
  font-size: 12px;
  line-height: 1.6;
  color: #262626;
}

.command-box {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 12px;
  background: #F2F3F5;
  border-radius: 4px;
  margin: 12px 0;
}

.command {
  flex: 1;
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', 'source-code-pro', monospace;
  font-size: 13px;
  color: #262626;
  word-break: break-all;
  white-space: pre-wrap;
}

.copy-btn {
  flex-shrink: 0;
}

.tip {
  margin: 8px 0;
  padding: 8px 12px;
  background: #E8F3FF;
  border-left: 3px solid #165DFF;
  border-radius: 2px;
  color: #595959;
  font-size: 13px;
}

p {
  margin: 8px 0;
  color: #595959;
  font-size: 13px;
  line-height: 1.6;
}
</style>
