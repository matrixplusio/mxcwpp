<template>
  <div class="notification-page">
    <!-- 页面标题和描述 -->
    <div class="page-header">
      <h2 class="page-title">通知管理</h2>
      <p class="page-description">通过飞书、钉钉、企业微信等方式第一时间接收告警信息</p>
    </div>

    <!-- 搜索和操作 -->
    <div class="toolbar">
      <a-input
        v-model:value="filters.keyword"
        placeholder="搜索通知名称"
        class="search-input"
        allow-clear
        @press-enter="handleSearch"
      >
        <template #prefix>
          <SearchOutlined />
        </template>
      </a-input>
      <a-select
        v-model:value="filters.enabled"
        placeholder="状态"
        class="status-select"
        allow-clear
        @change="handleSearch"
      >
        <a-select-option value="true">启用</a-select-option>
        <a-select-option value="false">禁用</a-select-option>
      </a-select>
      <a-button @click="handleSearch">搜索</a-button>
      <a-button @click="loadNotifications">刷新</a-button>
      <a-button type="primary" @click="handleCreate">
        <template #icon>
          <PlusOutlined />
        </template>
        新建通知
      </a-button>
    </div>

    <!-- 通知列表 -->
    <a-table
      :columns="columns"
      :data-source="notifications"
      :loading="loading"
      :pagination="pagination"
      :scroll="{ x: 910 }"
      row-key="id"
      @change="handleTableChange"
    >
      <template #bodyCell="{ column, record }">
        <template v-if="column.key === 'notify_category'">
          <a-tag :color="NOTIFY_CATEGORY_COLOR_MAP[record.notify_category] || 'default'">
            {{ NOTIFY_CATEGORY_TEXT_MAP[record.notify_category] || record.notify_category }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'enabled'">
          <a-switch
            v-model:checked="record.enabled"
            size="small"
            @change="handleToggleEnabled(record)"
          />
        </template>
        <template v-else-if="column.key === 'severities'">
          <template v-if="record.severities?.length">
            <a-space size="small">
              <a-tag v-if="record.severities.includes('critical')" color="red" size="small">严重</a-tag>
              <a-tag v-if="record.severities.includes('high')" color="orange" size="small">高危</a-tag>
              <a-tag v-if="record.severities.includes('medium')" color="blue" size="small">中危</a-tag>
              <a-tag v-if="record.severities.includes('low')" color="default" size="small">低危</a-tag>
            </a-space>
          </template>
          <template v-else>
            <span style="color: #999;">-</span>
          </template>
        </template>
        <template v-else-if="column.key === 'scope'">
          {{ getScopeText(record.scope) }}
        </template>
        <template v-else-if="column.key === 'config'">
          <a-tag :color="record.type === 'lark' ? 'blue' : 'cyan'">
            {{ getTypeText(record.type) }}
          </a-tag>
        </template>
        <template v-else-if="column.key === 'actions'">
          <a-space>
            <a-button type="link" size="small" @click="handleViewDetail(record)">详情</a-button>
            <a-button type="link" size="small" @click="handleEdit(record)">编辑</a-button>
            <a-popconfirm
              title="确定要删除这个通知吗？"
              ok-text="确定"
              cancel-text="取消"
              @confirm="handleDelete(record)"
            >
              <a-button type="link" size="small" danger>删除</a-button>
            </a-popconfirm>
          </a-space>
        </template>
      </template>
    </a-table>

    <!-- 创建/编辑通知对话框 -->
    <a-modal
      v-model:open="modalVisible"
      :title="modalTitle"
      :width="900"
      :confirm-loading="submitting"
      @ok="handleSubmit"
      @cancel="handleCancel"
    >
      <a-form
        ref="formRef"
        :model="formData"
        :rules="formRules"
        :label-col="{ span: 5 }"
        :wrapper-col="{ span: 19 }"
      >
        <a-form-item label="通知类别" name="notify_category" required>
          <a-select v-model:value="formData.notify_category" @change="handleNotifyCategoryChange" placeholder="请选择通知类别">
            <a-select-option v-for="opt in notifyCategoryOptions" :key="opt.value" :value="opt.value">
              {{ opt.label }}
            </a-select-option>
          </a-select>
          <div class="form-tip">
            {{ notifyCategoryOptions.find(o => o.value === formData.notify_category)?.description }}
          </div>
        </a-form-item>

        <a-form-item label="通知名称" name="name" required>
          <a-input
            v-model:value="formData.name"
            placeholder="请输入通知名称，如：生产环境基线告警"
            allow-clear
          />
        </a-form-item>

        <!-- 带等级过滤的通知类别显示等级选择器 -->
        <a-form-item v-if="currentCategoryHasSeverity" label="通知等级" name="severities" required>
          <div class="severity-section">
            <a-checkbox-group v-model:value="formData.severities" class="severity-checkbox-group">
              <a-checkbox value="critical">严重</a-checkbox>
              <a-checkbox value="high">高危</a-checkbox>
              <a-checkbox value="medium">中危</a-checkbox>
              <a-checkbox value="low">低危</a-checkbox>
            </a-checkbox-group>
            <div class="form-tip">
              选择需要通知的告警等级
            </div>
          </div>
        </a-form-item>

        <!-- Agent 离线通知的说明 -->
        <a-form-item v-if="formData.notify_category === 'agent_offline'" label="通知说明">
          <a-alert
            type="info"
            show-icon
            message="Agent 离线通知"
            description="当 Agent 断开连接时，将自动发送离线通知到配置的通知渠道。"
          />
        </a-form-item>

        <!-- K8s 告警通知的说明 -->
        <a-form-item v-if="formData.notify_category === 'kube_alert'" label="通知说明">
          <a-alert
            type="info"
            show-icon
            message="K8s 安全告警"
            description="当 K8s 审计检测引擎触发安全告警时发送通知。主机范围配置对此类通知无效，始终按全局范围匹配。"
          />
        </a-form-item>

        <!-- 漏洞通报通知的说明 -->
        <a-form-item v-if="formData.notify_category === 'vuln_bulletin'" label="通知说明">
          <a-alert
            type="info"
            show-icon
            message="漏洞通报通知"
            description="漏洞通报创建时自动发送到此渠道。通报的优先级过滤在「漏洞管理 → 漏洞通报 → 通报配置」中管理，此处仅配置通知渠道。"
          />
        </a-form-item>

        <a-form-item v-if="formData.notify_category !== 'vuln_bulletin'" label="主机范围" name="scope" required>
          <a-radio-group
            v-model:value="formData.scope"
            @change="handleScopeChange"
            class="scope-radio-group"
          >
            <a-radio value="global">全局</a-radio>
            <a-radio value="host_tags">主机标签</a-radio>
            <a-radio value="business_line">业务线</a-radio>
            <a-radio value="specified">指定主机</a-radio>
          </a-radio-group>
          <div v-if="formData.scope === 'host_tags'" class="scope-input-wrapper">
            <a-select
              v-model:value="formData.scope_value.tags"
              mode="tags"
              placeholder="请输入或选择主机标签，按回车或逗号分隔"
              style="width: 100%"
              :token-separators="[',']"
              allow-clear
            />
          </div>
          <div v-else-if="formData.scope === 'business_line'" class="scope-input-wrapper">
            <a-select
              v-model:value="formData.scope_value.business_lines"
              mode="multiple"
              placeholder="请选择业务线"
              style="width: 100%"
              :filter-option="(input: string, option: any) => filterBusinessLineOption(input, { label: option.label || option.children })"
              allow-clear
              show-search
            >
              <a-select-option v-for="bl in businessLines" :key="bl.code" :value="bl.code" :label="bl.name">
                {{ bl.name }}
              </a-select-option>
            </a-select>
          </div>
          <div v-else-if="formData.scope === 'specified'" class="scope-input-wrapper">
            <a-select
              v-model:value="formData.scope_value.host_ids"
              mode="multiple"
              placeholder="请选择主机"
              style="width: 100%"
              show-search
              :filter-option="(input: string, option: any) => filterHostOption(input, { label: option.label || option.children })"
              allow-clear
            >
              <a-select-option
                v-for="host in hosts"
                :key="host.host_id"
                :value="host.host_id"
                :label="host.hostname || host.host_id"
              >
                {{ host.hostname || host.host_id }}
              </a-select-option>
            </a-select>
          </div>
        </a-form-item>

        <a-form-item label="前端地址" name="frontend_url" required>
          <a-input
            v-model:value="formData.frontend_url"
            placeholder="请输入前端地址（告警带上告警uri，点击告警跳到具体的告警信息去）"
            allow-clear
          />
        </a-form-item>

        <a-form-item label="通知配置" name="type" required>
          <a-tabs v-model:activeKey="formData.type" type="card" class="config-tabs">
            <a-tab-pane key="lark" tab="飞书">
              <div class="config-form-wrapper">
                <a-form-item label="* WebHookURL" class="config-form-item">
                  <a-input
                    v-model:value="formData.config.webhook_url"
                    placeholder="请输入飞书 Webhook URL"
                    allow-clear
                  />
                </a-form-item>
                <a-form-item label="Secret" class="config-form-item">
                  <a-input-password
                    v-model:value="formData.config.secret"
                    placeholder="请输入飞书 Secret（可选，用于签名验证）"
                    allow-clear
                  />
                </a-form-item>
                <a-form-item label="用户备注" class="config-form-item">
                  <a-input
                    v-model:value="formData.config.user_notes"
                    placeholder="请输入用户昵称,仅做为备注使用"
                    allow-clear
                  />
                </a-form-item>
              </div>
            </a-tab-pane>
            <a-tab-pane key="webhook" tab="Webhook">
              <div class="config-form-wrapper">
                <a-form-item label="* WebHookURL" class="config-form-item">
                  <a-input
                    v-model:value="formData.config.webhook_url"
                    placeholder="请输入 Webhook URL"
                    allow-clear
                  />
                </a-form-item>
                <a-form-item label="用户备注" class="config-form-item">
                  <a-input
                    v-model:value="formData.config.user_notes"
                    placeholder="请输入用户昵称,仅做为备注使用"
                    allow-clear
                  />
                </a-form-item>
              </div>
            </a-tab-pane>
          </a-tabs>
        </a-form-item>

        <a-form-item :label-col="{ span: 5 }" :wrapper-col="{ span: 19 }">
          <div class="test-section">
            <span class="test-tip">1. 确保上方必填信息完整</span>
            <a-button type="link" :loading="testing" @click="handleTestNotification" class="test-button">
              测试连接状态
            </a-button>
          </div>
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 自定义告警选择对话框 -->
    <a-modal
      v-model:open="showCustomAlertModal"
      title="选择通知告警"
      :width="600"
      @ok="handleCustomAlertOk"
      @cancel="showCustomAlertModal = false"
    >
      <div class="custom-alert-modal">
        <p>自定义告警功能暂未实现</p>
      </div>
    </a-modal>

    <!-- 通知详情弹窗 -->
    <a-modal
      v-model:open="detailModalVisible"
      title="通知详情"
      :width="600"
      :footer="null"
    >
      <a-descriptions :column="1" bordered v-if="viewingNotification">
        <a-descriptions-item label="通知类型">
          {{ viewingNotification.name }}
        </a-descriptions-item>
        <a-descriptions-item label="通知状态">
          <a-tag :color="viewingNotification.enabled ? 'success' : 'default'">
            {{ viewingNotification.enabled ? '启用' : '禁用' }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="关注等级">
          <a-space size="small">
            <a-tag v-if="viewingNotification.severities?.includes('critical')" color="red">严重</a-tag>
            <a-tag v-if="viewingNotification.severities?.includes('high')" color="orange">高危</a-tag>
            <a-tag v-if="viewingNotification.severities?.includes('medium')" color="blue">中危</a-tag>
            <a-tag v-if="viewingNotification.severities?.includes('low')" color="default">低危</a-tag>
          </a-space>
        </a-descriptions-item>
        <a-descriptions-item label="主机范围">
          {{ getScopeText(viewingNotification.scope) }}
        </a-descriptions-item>
        <a-descriptions-item label="通知方式">
          <a-tag :color="viewingNotification.type === 'lark' ? 'blue' : 'cyan'">
            {{ getTypeText(viewingNotification.type) }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="Webhook URL">
          <div class="detail-url">
            {{ viewingNotification.config?.webhook_url || '-' }}
          </div>
        </a-descriptions-item>
        <a-descriptions-item label="用户备注">
          {{ viewingNotification.config?.user_notes || '-' }}
        </a-descriptions-item>
        <a-descriptions-item label="前端地址">
          {{ viewingNotification.frontend_url || '-' }}
        </a-descriptions-item>
      </a-descriptions>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed } from 'vue'
import { message } from 'ant-design-vue'
import { SearchOutlined, PlusOutlined } from '@ant-design/icons-vue'
import {
  notificationsApi,
  type Notification,
  type CreateNotificationRequest,
  type UpdateNotificationRequest,
  type ScopeValueData,
  type NotifyCategory,
} from '@/api/notifications'
import { businessLinesApi, type BusinessLine } from '@/api/business-lines'
import { hostsApi, type Host } from '@/api/hosts'

// 通知类别选项
const notifyCategoryOptions = [
  { value: 'baseline_alert', label: '基线安全告警', description: '基线检测发现安全问题时发送通知', hasSeverity: true },
  { value: 'agent_offline', label: 'Agent 离线通知', description: 'Agent 断开连接时发送通知', hasSeverity: false },
  { value: 'virus_alert', label: '病毒查杀告警', description: '检测到病毒或恶意文件时发送通知', hasSeverity: true },
  { value: 'fim_alert', label: '文件完整性告警', description: '关键文件被篡改、新增或删除时发送通知', hasSeverity: true },
  { value: 'detection', label: '检测告警', description: 'CEL 检测规则触发告警时发送通知', hasSeverity: true },
  { value: 'kube_alert', label: 'K8s 安全告警', description: 'K8s 审计检测规则触发告警时发送通知', hasSeverity: true },
  { value: 'vuln_bulletin', label: '漏洞通报', description: '漏洞通报创建时发送通知，通报等级在漏洞通报配置中管理', hasSeverity: false },
]

// 通知类别文本映射
const NOTIFY_CATEGORY_TEXT_MAP: Record<string, string> = {
  baseline_alert: '基线安全告警',
  agent_offline: 'Agent 离线通知',
  vuln_bulletin: '漏洞通报',
  virus_alert: '病毒查杀告警',
  fim_alert: '文件完整性告警',
  detection: '检测告警',
  kube_alert: 'K8s 安全告警',
}

// 通知类别颜色映射
const NOTIFY_CATEGORY_COLOR_MAP: Record<string, string> = {
  baseline_alert: 'green',
  agent_offline: 'orange',
  vuln_bulletin: 'magenta',
  virus_alert: 'volcano',
  fim_alert: 'gold',
  detection: 'purple',
  kube_alert: 'blue',
}

const SCOPE_TEXT_MAP: Record<string, string> = {
  global: '全局',
  host_tags: '主机标签',
  business_line: '业务线',
  specified: '指定主机',
}

const TYPE_TEXT_MAP: Record<string, string> = {
  lark: '飞书',
  webhook: 'Webhook',
}

const loading = ref(false)
const submitting = ref(false)
const testing = ref(false)
const notifications = ref<Notification[]>([])
const businessLines = ref<BusinessLine[]>([])
const hosts = ref<Host[]>([])
const modalVisible = ref(false)
const detailModalVisible = ref(false)
const viewingNotification = ref<Notification | null>(null)
const isEdit = ref(false)
const editingId = ref<number | null>(null)
const formRef = ref()
const showCustomAlertModal = ref(false)
const customAlerts = ref<string[]>([])

const filters = reactive({
  keyword: '',
  enabled: undefined as string | undefined,
})

const pagination = reactive({
  current: 1,
  pageSize: 20,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
})

const formData = reactive<CreateNotificationRequest>({
  name: '',
  description: '',
  notify_category: 'baseline_alert', // 默认基线告警
  enabled: true,
  type: 'lark',
  severities: [],
  scope: 'global',
  scope_value: {
    tags: [],
    business_lines: [],
    host_ids: [],
  },
  frontend_url: '',
  config: {
    webhook_url: '',
    secret: '',
    user_notes: '',
  },
})

// 当前类别是否需要等级选择
const currentCategoryHasSeverity = computed(() => {
  const opt = notifyCategoryOptions.find(o => o.value === formData.notify_category)
  return opt?.hasSeverity ?? false
})

const formRules = {
  name: [{ required: true, message: '请输入通知名称', trigger: 'blur' }],
  notify_category: [{ required: true, message: '请选择通知类别', trigger: 'change' }],
  severities: [{
    validator: (_rule: any, value: string[]) => {
      // 带等级过滤的类别才需要验证 severities
      if (currentCategoryHasSeverity.value && (!value || value.length === 0)) {
        return Promise.reject('请选择至少一个通知等级')
      }
      return Promise.resolve()
    },
    trigger: 'change',
  }],
  scope: [{
    validator: () => {
      // 漏洞通报不需要主机范围
      if (formData.notify_category === 'vuln_bulletin') {
        return Promise.resolve()
      }
      if (!formData.scope) {
        return Promise.reject('请选择主机范围')
      }
      return Promise.resolve()
    },
    trigger: 'change',
  }],
  type: [{ required: true, message: '请选择通知方式', trigger: 'change' }],
  frontend_url: [{ required: true, message: '请输入前端地址', trigger: 'blur' }],
}

const columns = [
  {
    title: '通知名称',
    dataIndex: 'name',
    key: 'name',
    width: 150,
    ellipsis: true,
  },
  {
    title: '通知类别',
    key: 'notify_category',
    width: 130,
  },
  {
    title: '通知状态',
    key: 'enabled',
    width: 100,
    align: 'center' as const,
  },
  {
    title: '关注等级',
    key: 'severities',
    width: 200,
  },
  {
    title: '主机范围',
    key: 'scope',
    width: 100,
  },
  {
    title: '通知方式',
    key: 'config',
    width: 80,
  },
  {
    title: '操作',
    key: 'actions',
    width: 180,
    align: 'center' as const,
    fixed: 'right' as const,
  },
]

const modalTitle = computed(() => (isEdit.value ? '编辑通知' : '新建通知'))

const getScopeText = (scope: string) => SCOPE_TEXT_MAP[scope] || scope
const getTypeText = (type: string) => TYPE_TEXT_MAP[type] || type


const filterBusinessLineOption = (input: string, option: any) => {
  if (!input) return true
  const text = option.label || option.children || ''
  return String(text).toLowerCase().indexOf(input.toLowerCase()) >= 0
}

const filterHostOption = (input: string, option: any) => {
  if (!input) return true
  const text = option.label || option.children || ''
  return String(text).toLowerCase().indexOf(input.toLowerCase()) >= 0
}

const loadNotifications = async () => {
  loading.value = true
  try {
    const params: any = {
      page: pagination.current,
      page_size: pagination.pageSize,
    }
    if (filters.keyword) {
      params.keyword = filters.keyword
    }
    if (filters.enabled !== undefined) {
      params.enabled = filters.enabled
    }
    const response = await notificationsApi.list(params)
    notifications.value = response.items
    pagination.total = response.total
  } catch (error: any) {
    message.error(error?.message || '加载通知列表失败')
  } finally {
    loading.value = false
  }
}

const loadBusinessLines = async () => {
  try {
    const response = await businessLinesApi.list({ enabled: 'true', page_size: 1000 })
    businessLines.value = response.items
  } catch (error) {
    console.error('加载业务线列表失败:', error)
  }
}

const loadHosts = async () => {
  try {
    const response = await hostsApi.list({ page_size: 1000 })
    hosts.value = response.items
  } catch (error) {
    console.error('加载主机列表失败:', error)
  }
}

const handleSearch = () => {
  pagination.current = 1
  loadNotifications()
}

const handleTableChange = (pag: any) => {
  pagination.current = pag.current
  pagination.pageSize = pag.pageSize
  loadNotifications()
}

const handleToggleEnabled = async (record: Notification) => {
  try {
    await notificationsApi.update(record.id, { enabled: record.enabled })
    message.success('更新成功')
  } catch (error: any) {
    message.error(error?.message || '更新通知状态失败')
    record.enabled = !record.enabled
  }
}

const handleViewDetail = async (record: Notification) => {
  try {
    const detail = await notificationsApi.get(record.id)
    viewingNotification.value = detail
    detailModalVisible.value = true
  } catch (error: any) {
    message.error(error?.message || '加载通知详情失败')
  }
}

const handleCreate = () => {
  isEdit.value = false
  editingId.value = null
  resetForm()
  modalVisible.value = true
  loadBusinessLines()
  loadHosts()
}

const handleEdit = async (record: Notification) => {
  isEdit.value = true
  editingId.value = record.id
  try {
    const detail = await notificationsApi.get(record.id)
    Object.assign(formData, {
      name: detail.name,
      description: detail.description || '',
      notify_category: detail.notify_category || 'baseline_alert',
      enabled: detail.enabled,
      type: detail.type,
      severities: detail.severities || [],
      scope: detail.scope,
      frontend_url: detail.frontend_url || '',
      config: detail.config,
    })

    if (detail.scope_value) {
      try {
        const scopeValue = JSON.parse(detail.scope_value) as ScopeValueData
        formData.scope_value = {
          tags: scopeValue.tags || [],
          business_lines: scopeValue.business_lines || [],
          host_ids: scopeValue.host_ids || [],
        }
      } catch (e) {
        formData.scope_value = { tags: [], business_lines: [], host_ids: [] }
      }
    } else {
      formData.scope_value = { tags: [], business_lines: [], host_ids: [] }
    }

    modalVisible.value = true
    loadBusinessLines()
    loadHosts()
  } catch (error: any) {
    message.error(error?.message || '加载通知详情失败')
  }
}

const handleDelete = async (record: Notification) => {
  try {
    await notificationsApi.delete(record.id)
    message.success('删除成功')
    loadNotifications()
  } catch (error: any) {
    message.error(error?.message || '删除通知失败')
  }
}

const handleSubmit = async () => {
  try {
    await formRef.value.validate()
  } catch (error) {
    return
  }

  if (!formData.config.webhook_url) {
    message.warning('请输入 WebHookURL')
    return
  }

  submitting.value = true
  try {
    const scopeValue: ScopeValueData = {
      tags: [],
      business_lines: [],
      host_ids: [],
    }
    if (formData.scope === 'host_tags') {
      scopeValue.tags = formData.scope_value.tags || []
    } else if (formData.scope === 'business_line') {
      scopeValue.business_lines = formData.scope_value.business_lines || []
    } else if (formData.scope === 'specified') {
      scopeValue.host_ids = formData.scope_value.host_ids || []
    }

    if (isEdit.value && editingId.value) {
      const updateData: UpdateNotificationRequest = {
        name: formData.name,
        description: formData.description,
        enabled: formData.enabled,
        type: formData.type,
        severities: formData.severities,
        scope: formData.scope,
        scope_value: scopeValue,
        frontend_url: formData.frontend_url,
        config: formData.config,
      }
      await notificationsApi.update(editingId.value, updateData)
      message.success('更新成功')
    } else {
      const createData: CreateNotificationRequest = {
        ...formData,
        scope_value: scopeValue,
      }
      await notificationsApi.create(createData)
      message.success('创建成功')
    }
    modalVisible.value = false
    loadNotifications()
  } catch (error: any) {
    message.error(error?.message || '保存通知失败')
  } finally {
    submitting.value = false
  }
}

const handleTestNotification = async () => {
  if (!formData.config.webhook_url) {
    message.warning('请先填写 WebHookURL')
    return
  }

  testing.value = true
  try {
    const testData: any = {
      type: formData.type,
      config: formData.config,
    }
    
    // 如果提供了前端URL，传递它用于测试跳转链接
    if (formData.frontend_url) {
      testData.frontend_url = formData.frontend_url
    }
    
    // 如果是在编辑模式下，传递通知ID（用于获取通知名称等信息）
    if (isEdit.value && editingId.value) {
      testData.notification_id = editingId.value
    }

    // 传递通知类别，让后端使用对应类别的模拟数据
    testData.notify_category = formData.notify_category

    await notificationsApi.test(testData)
    message.success('测试通知发送成功')
  } catch (error: any) {
    message.error(error?.message || '测试通知失败')
  } finally {
    testing.value = false
  }
}

const handleCancel = () => {
  resetForm()
  modalVisible.value = false
}

const handleScopeChange = () => {
  formData.scope_value = { tags: [], business_lines: [], host_ids: [] }
}

const handleNotifyCategoryChange = () => {
  // 切换通知类别时，清空 severities
  formData.severities = []
  // 漏洞通报是 CVE 维度，不需要主机范围，自动设为全局
  if (formData.notify_category === 'vuln_bulletin') {
    formData.scope = 'global'
  }
  // 根据类别设置默认名称
  const defaultNames: Record<string, string> = {
    baseline_alert: '基线安全告警',
    agent_offline: 'Agent 离线通知',
    vuln_bulletin: '漏洞通报通知',
    virus_alert: '病毒查杀告警',
    fim_alert: '文件完整性告警',
    detection: '检测告警',
    kube_alert: 'K8s 安全告警',
  }
  formData.name = formData.name || defaultNames[formData.notify_category] || ''
}

const handleCustomAlertOk = () => {
  showCustomAlertModal.value = false
}

const resetForm = () => {
  Object.assign(formData, {
    name: '',
    description: '',
    notify_category: 'baseline_alert' as NotifyCategory,
    enabled: true,
    type: 'lark',
    severities: [],
    scope: 'global',
    scope_value: { tags: [], business_lines: [], host_ids: [] },
    frontend_url: '',
    config: { webhook_url: '', secret: '', user_notes: '' },
  })
  customAlerts.value = []
  formRef.value?.resetFields()
}

onMounted(() => {
  loadNotifications()
})
</script>

<style scoped lang="less">
.notification-page {
  width: 100%;
}

.page-header {
  margin-bottom: 24px;

  .page-title {
    margin: 0 0 8px 0;
    font-size: 20px;
    font-weight: 600;
    color: var(--mxsec-text-1);
  }

  .page-description {
    margin: 0;
    font-size: 14px;
    color: var(--mxsec-text-3);
  }
}

.toolbar {
  display: flex;
  gap: 12px;
  align-items: center;
  margin-bottom: 16px;
  padding: 12px 16px;
  background: var(--mxsec-fill-1);
  border-radius: 6px;
  border: 1px solid var(--mxsec-border);

  .search-input {
    width: 280px;
  }

  .status-select {
    width: 120px;
  }
}

.config-url {
  font-size: 12px;
  color: var(--mxsec-text-3);
  word-break: break-all;
}

.detail-url {
  word-break: break-all;
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 13px;
  background: #f5f7fa;
  padding: 10px 12px;
  border-radius: 6px;
  border: 1px solid #e8e8e8;
}

.severity-section {
  width: 100%;

  .severity-checkbox-group {
    width: 100%;
    margin-bottom: 8px;

    :deep(.ant-checkbox-wrapper) {
      margin-right: 16px;
      margin-bottom: 8px;
    }
  }

  .custom-alert-section {
    margin: 8px 0;
  }
}

.form-tip {
  margin-top: 8px;
  font-size: 12px;
  color: var(--mxsec-text-3);
  line-height: 1.5;
}

.scope-radio-group {
  width: 100%;
  margin-bottom: 0;

  :deep(.ant-radio-wrapper) {
    margin-right: 16px;
    margin-bottom: 8px;
  }
}

.scope-input-wrapper {
  margin-top: 12px;
}

.config-tabs {
  :deep(.ant-tabs-content-holder) {
    padding-top: 16px;
  }

  :deep(.ant-tabs-tab) {
    padding: 8px 16px;
  }
}

.config-form-wrapper {
  .config-form-item {
    margin-bottom: 16px;

    :deep(.ant-form-item-label) {
      padding-bottom: 4px;
      width: 120px;
    }

    :deep(.ant-form-item-control) {
      flex: 1;
    }
  }
}

.test-section {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0;

  .test-tip {
    font-size: 14px;
    color: #595959;
    margin: 0;
  }

  .test-button {
    padding: 0;
    height: auto;
  }
}

:deep(.ant-form-item) {
  margin-bottom: 20px;
}

:deep(.ant-form-item-label > label) {
  font-weight: 500;
}

:deep(.ant-modal-body) {
  padding: 24px;
}

:deep(.ant-input),
:deep(.ant-select-selector),
:deep(.ant-input-password) {
  border-radius: 4px;
}
</style>
