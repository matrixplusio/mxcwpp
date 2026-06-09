<template>
  <div class="policy-groups-page">
    <!-- 策略组列表视图 -->
    <template v-if="!currentGroup">
      <div class="page-header">
        <h2>策略组管理</h2>
        <a-button type="primary" @click="handleCreateGroup">
          <template #icon>
            <PlusOutlined />
          </template>
          新建策略组
        </a-button>
      </div>

      <!-- 策略组列表 -->
      <a-spin :spinning="loading">
        <div class="groups-grid">
          <a-card
            v-for="group in policyGroups"
            :key="group.id"
            class="group-card"
            :class="{ disabled: !group.enabled }"
            hoverable
          >
            <template #title>
              <div class="card-title">
                <span
                  class="group-icon"
                  :style="{ backgroundColor: group.color || '#3B82F6' }"
                >
                  {{ group.icon || group.name.charAt(0) }}
                </span>
                <span class="group-name">{{ group.name }}</span>
                <a-tag v-if="!group.enabled" color="default">已禁用</a-tag>
              </div>
            </template>
            <template #extra>
              <a-dropdown>
                <a-button type="text" size="small">
                  <MoreOutlined />
                </a-button>
                <template #overlay>
                  <a-menu @click="({ key }: { key: string }) => handleMenuClick(key, group)">
                    <a-menu-item key="edit">
                      <EditOutlined /> 编辑策略组
                    </a-menu-item>
                    <a-menu-item key="toggle">
                      <template v-if="group.enabled">
                        <StopOutlined /> 禁用
                      </template>
                      <template v-else>
                        <CheckOutlined /> 启用
                      </template>
                    </a-menu-item>
                    <a-menu-divider />
                    <a-menu-item key="delete" danger>
                      <DeleteOutlined /> 删除策略组
                    </a-menu-item>
                  </a-menu>
                </template>
              </a-dropdown>
            </template>

            <p class="group-description">{{ group.description || '暂无描述' }}</p>

            <div class="group-stats">
              <a-row :gutter="16">
                <a-col :span="8">
                  <a-statistic title="策略数" :value="group.policy_count || 0" />
                </a-col>
                <a-col :span="8">
                  <a-statistic title="检查项" :value="group.rule_count || 0" />
                </a-col>
                <a-col :span="8">
                  <a-statistic
                    title="通过率"
                    :value="Math.floor(group.pass_rate || 0)"
                    :precision="0"
                    suffix="%"
                    :value-style="{ color: getPassRateColor(group.pass_rate || 0) }"
                  />
                </a-col>
              </a-row>
            </div>

            <div class="group-footer">
              <span class="host-count">
                <DesktopOutlined /> 检查主机: {{ group.host_count || 0 }}
              </span>
              <a-button type="primary" size="small" @click="handleEnterGroup(group)">
                管理策略 <RightOutlined />
              </a-button>
            </div>
          </a-card>

          <!-- 空状态 -->
          <a-empty
            v-if="policyGroups.length === 0 && !loading"
            description="暂无策略组"
            class="empty-state"
          >
            <a-button type="primary" @click="handleCreateGroup">创建策略组</a-button>
          </a-empty>
        </div>
      </a-spin>
    </template>

    <!-- 策略管理视图（进入某个策略组后） -->
    <template v-else>
      <div class="page-header">
        <div class="breadcrumb-header">
          <a-button type="text" @click="handleBackToGroups">
            <LeftOutlined /> 返回策略组列表
          </a-button>
          <a-divider type="vertical" />
          <span
            class="group-icon small"
            :style="{ backgroundColor: currentGroup.color || '#3B82F6' }"
          >
            {{ currentGroup.icon || currentGroup.name.charAt(0) }}
          </span>
          <h2 style="margin: 0; margin-left: 8px;">{{ currentGroup.name }}</h2>
          <a-tag v-if="!currentGroup.enabled" color="default" style="margin-left: 8px;">已禁用</a-tag>
        </div>
        <a-space>
          <a-button @click="handleEditGroup(currentGroup)">
            <template #icon>
              <EditOutlined />
            </template>
            编辑策略组
          </a-button>
          <a-button type="primary" @click="handleCreatePolicy">
            <template #icon>
              <PlusOutlined />
            </template>
            新建策略
          </a-button>
        </a-space>
      </div>

      <!-- 策略组描述 -->
      <a-card :bordered="false" class="group-info-card" v-if="currentGroup.description">
        <p style="margin: 0; color: #666;">{{ currentGroup.description }}</p>
      </a-card>

      <!-- 策略列表 -->
      <a-card title="策略列表" :bordered="false">
        <template #extra>
          <a-space>
            <!-- 批量操作按钮 -->
            <template v-if="selectedPolicyIds.length > 0">
              <span style="color: #666;">已选 {{ selectedPolicyIds.length }} 项</span>
              <a-button @click="handleBatchEnable(true)">批量启用</a-button>
              <a-button @click="handleBatchEnable(false)">批量禁用</a-button>
              <a-button @click="handleBatchExport">批量导出</a-button>
              <a-popconfirm
                title="确定要删除选中的策略吗？"
                ok-text="删除"
                cancel-text="取消"
                @confirm="handleBatchDelete"
              >
                <a-button danger>批量删除</a-button>
              </a-popconfirm>
              <a-divider type="vertical" />
            </template>
            <a-dropdown>
              <a-button>
                <template #icon>
                  <DownloadOutlined />
                </template>
                导出
              </a-button>
              <template #overlay>
                <a-menu @click="handleExportMenuClick">
                  <a-menu-item key="export-all">
                    <ExportOutlined /> 导出所有策略
                  </a-menu-item>
                  <a-menu-item key="export-group">
                    <FileTextOutlined /> 导出当前策略组
                  </a-menu-item>
                </a-menu>
              </template>
            </a-dropdown>
            <a-upload
              :show-upload-list="false"
              :before-upload="handleImportFile"
              accept=".json"
            >
              <a-button>
                <template #icon>
                  <UploadOutlined />
                </template>
                导入
              </a-button>
            </a-upload>
            <a-input-search
              v-model:value="policySearchKeyword"
              placeholder="搜索策略名称"
              style="width: 200px"
              @search="handleSearchPolicies"
            />
            <a-button @click="loadGroupPolicies">
              <template #icon>
                <ReloadOutlined />
              </template>
            </a-button>
          </a-space>
        </template>

        <a-table
          :columns="policyColumns"
          :data-source="filteredPolicies"
          :loading="policiesLoading"
          row-key="id"
          :scroll="{ x: 900 }"
          :pagination="policyPagination"
          :row-selection="{
            selectedRowKeys: selectedPolicyIds,
            onChange: (keys: string[]) => { selectedPolicyIds = keys },
          }"
          @change="handlePolicyTableChange"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'name'">
              <div>
                <span style="font-weight: 500;">{{ record.name }}</span>
                <a-tag v-if="!record.enabled" color="default" style="margin-left: 8px;">已禁用</a-tag>
              </div>
              <div style="font-size: 12px; color: #999;">{{ record.id }}</div>
            </template>
            <template v-else-if="column.key === 'os_family'">
              <a-tag v-for="os in record.os_family" :key="os" style="margin-right: 4px;">
                {{ getOSLabel(os) }}
              </a-tag>
              <span v-if="!record.os_family || record.os_family.length === 0">-</span>
            </template>
            <template v-else-if="column.key === 'enabled'">
              <a-switch
                :checked="record.enabled"
                @change="(checked: boolean) => handleTogglePolicy(record, checked)"
                size="small"
              />
            </template>
            <template v-else-if="column.key === 'action'">
              <a-space>
                <a-button type="link" size="small" @click="handleEnterPolicy(record)">
                  管理规则
                </a-button>
                <a-button type="link" size="small" @click="handleEditPolicy(record)">
                  编辑
                </a-button>
                <a-popconfirm
                  title="确定要删除此策略吗？"
                  ok-text="删除"
                  cancel-text="取消"
                  @confirm="handleDeletePolicy(record)"
                >
                  <a-button type="link" size="small" danger>删除</a-button>
                </a-popconfirm>
              </a-space>
            </template>
          </template>

          <template #emptyText>
            <a-empty description="暂无策略">
              <a-button type="primary" @click="handleCreatePolicy">创建策略</a-button>
            </a-empty>
          </template>
        </a-table>
      </a-card>
    </template>

    <!-- 创建/编辑策略组对话框 -->
    <a-modal
      v-model:open="groupModalVisible"
      :title="editingGroup ? '编辑策略组' : '新建策略组'"
      @ok="handleGroupModalOk"
      @cancel="handleGroupModalCancel"
      :confirm-loading="groupModalLoading"
    >
      <a-form
        ref="groupFormRef"
        :model="groupFormState"
        :rules="groupFormRules"
        :label-col="{ span: 6 }"
        :wrapper-col="{ span: 18 }"
      >
        <a-form-item label="策略组ID" name="id" v-if="!editingGroup">
          <a-input
            v-model:value="groupFormState.id"
            placeholder="留空自动生成"
          />
        </a-form-item>
        <a-form-item label="策略组名称" name="name">
          <a-input
            v-model:value="groupFormState.name"
            placeholder="例如：系统基线组、应用基线组"
          />
        </a-form-item>
        <a-form-item label="描述" name="description">
          <a-textarea
            v-model:value="groupFormState.description"
            placeholder="策略组描述"
            :rows="3"
          />
        </a-form-item>
        <a-form-item label="图标" name="icon">
          <a-input
            v-model:value="groupFormState.icon"
            placeholder="单个字符或 emoji"
            :maxlength="2"
            style="width: 100px"
          />
        </a-form-item>
        <a-form-item label="颜色" name="color">
          <a-input
            v-model:value="groupFormState.color"
            type="color"
            style="width: 100px; padding: 0"
          />
        </a-form-item>
        <a-form-item label="排序" name="sort_order">
          <a-input-number
            v-model:value="groupFormState.sort_order"
            :min="0"
            :max="999"
          />
        </a-form-item>
        <a-form-item label="启用状态" name="enabled">
          <a-switch v-model:checked="groupFormState.enabled" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 创建/编辑策略对话框 -->
    <PolicyModal
      v-model:open="policyModalVisible"
      :policy="editingPolicy"
      :default-group-id="currentGroup?.id"
      @success="handlePolicyModalSuccess"
    />
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { message, Modal } from 'ant-design-vue'
import {
  PlusOutlined,
  EditOutlined,
  DeleteOutlined,
  MoreOutlined,
  RightOutlined,
  LeftOutlined,
  DesktopOutlined,
  StopOutlined,
  CheckOutlined,
  ReloadOutlined,
  DownloadOutlined,
  UploadOutlined,
  ExportOutlined,
  FileTextOutlined,
} from '@ant-design/icons-vue'
import { policyGroupsApi } from '@/api/policy-groups'
import { policiesApi } from '@/api/policies'
import type { PolicyGroup, Policy } from '@/api/types'
import type { FormInstance } from 'ant-design-vue'
import PolicyModal from '@/views/Policies/components/PolicyModal.vue'

const router = useRouter()
const route = useRoute()

const loading = ref(false)
const policyGroups = ref<PolicyGroup[]>([])
const currentGroup = ref<PolicyGroup | null>(null)
const groupModalVisible = ref(false)
const groupModalLoading = ref(false)
const editingGroup = ref<PolicyGroup | null>(null)
const groupFormRef = ref<FormInstance>()

// 策略相关
const policiesLoading = ref(false)
const groupPolicies = ref<Policy[]>([])
const policySearchKeyword = ref('')
const policyModalVisible = ref(false)
const editingPolicy = ref<Policy | null>(null)
const selectedPolicyIds = ref<string[]>([])

// 分页配置
const policyPagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
  showSizeChanger: true,
  showTotal: (total: number) => `共 ${total} 条`,
  pageSizeOptions: ['10', '20', '50', '100'],
})

const groupFormState = reactive({
  id: '',
  name: '',
  description: '',
  icon: '',
  color: '#3B82F6',
  sort_order: 0,
  enabled: true,
})

const groupFormRules = {
  name: [{ required: true, message: '请输入策略组名称', trigger: 'blur' }],
}

const policyColumns = [
  {
    title: '策略名称',
    key: 'name',
    width: 280,
    ellipsis: true,
  },
  {
    title: '版本',
    dataIndex: 'version',
    key: 'version',
    width: 80,
  },
  {
    title: '适用系统',
    key: 'os_family',
    width: 180,
  },
  {
    title: '检查项',
    dataIndex: 'rule_count',
    key: 'rule_count',
    width: 80,
    align: 'center' as const,
  },
  {
    title: '启用',
    key: 'enabled',
    width: 70,
    align: 'center' as const,
  },
  {
    title: '操作',
    key: 'action',
    width: 200,
    fixed: 'right' as const,
  },
]

const filteredPolicies = computed(() => {
  let result = groupPolicies.value
  if (policySearchKeyword.value) {
    result = result.filter(p =>
      p.name.toLowerCase().includes(policySearchKeyword.value.toLowerCase()) ||
      p.id.toLowerCase().includes(policySearchKeyword.value.toLowerCase())
    )
  }
  // 更新分页总数
  policyPagination.total = result.length
  return result
})

// 表格分页变化处理
const handlePolicyTableChange = (pag: any) => {
  policyPagination.current = pag.current
  policyPagination.pageSize = pag.pageSize
}

// 获取 OS 标签
const getOSLabel = (os: string) => {
  const osMap: Record<string, string> = {
    rocky: 'Rocky',
    centos: 'CentOS',
    oracle: 'Oracle',
    debian: 'Debian',
    ubuntu: 'Ubuntu',
    openeuler: 'openEuler',
    alibaba: 'Alibaba',
  }
  return osMap[os] || os
}

// 加载策略组列表
const loadPolicyGroups = async () => {
  loading.value = true
  try {
    const response = await policyGroupsApi.list() as any
    policyGroups.value = response.data?.items || response.items || []
  } catch (error) {
    console.error('加载策略组失败:', error)
    message.error('加载策略组失败')
  } finally {
    loading.value = false
  }
}

// 加载策略组下的策略
const loadGroupPolicies = async () => {
  if (!currentGroup.value) return

  policiesLoading.value = true
  try {
    const response = await policiesApi.list({ group_id: currentGroup.value.id }) as any
    groupPolicies.value = response.items || []
  } catch (error) {
    console.error('加载策略列表失败:', error)
    message.error('加载策略列表失败')
  } finally {
    policiesLoading.value = false
  }
}

// 获取通过率颜色
const getPassRateColor = (rate: number) => {
  if (rate >= 80) return '#22C55E'
  if (rate >= 60) return '#F59E0B'
  return '#f5222d'
}

// 进入策略组管理
const handleEnterGroup = (group: PolicyGroup) => {
  currentGroup.value = group
  // 更新 URL 参数
  router.replace({ query: { group_id: group.id } })
  loadGroupPolicies()
}

// 返回策略组列表
const handleBackToGroups = () => {
  currentGroup.value = null
  policySearchKeyword.value = ''
  groupPolicies.value = []
  // 清除 URL 参数
  router.replace({ query: {} })
  loadPolicyGroups()
}

// 搜索策略
const handleSearchPolicies = () => {
  // 搜索时重置页码
  policyPagination.current = 1
}

// 创建策略组
const handleCreateGroup = () => {
  editingGroup.value = null
  resetGroupForm()
  groupModalVisible.value = true
}

// 编辑策略组
const handleEditGroup = (group: PolicyGroup) => {
  editingGroup.value = group
  groupFormState.id = group.id
  groupFormState.name = group.name
  groupFormState.description = group.description || ''
  groupFormState.icon = group.icon || ''
  groupFormState.color = group.color || '#3B82F6'
  groupFormState.sort_order = group.sort_order || 0
  groupFormState.enabled = group.enabled
  groupModalVisible.value = true
}

// 菜单点击
const handleMenuClick = async (key: string, group: PolicyGroup) => {
  if (key === 'edit') {
    handleEditGroup(group)
  } else if (key === 'toggle') {
    await handleToggleGroup(group)
  } else if (key === 'delete') {
    handleDeleteGroup(group)
  }
}

// 切换策略组启用状态
const handleToggleGroup = async (group: PolicyGroup) => {
  try {
    await policyGroupsApi.update(group.id, { enabled: !group.enabled })
    message.success(group.enabled ? '已禁用策略组' : '已启用策略组')
    loadPolicyGroups()
  } catch (error) {
    console.error('更新策略组失败:', error)
    message.error('更新策略组失败')
  }
}

// 删除策略组
const handleDeleteGroup = (group: PolicyGroup) => {
  Modal.confirm({
    title: '确认删除',
    content: `确定要删除策略组「${group.name}」吗？删除后无法恢复。`,
    okText: '删除',
    okType: 'danger',
    cancelText: '取消',
    async onOk() {
      try {
        await policyGroupsApi.delete(group.id)
        message.success('删除成功')
        loadPolicyGroups()
      } catch (error: any) {
        console.error('删除策略组失败:', error)
        if (error.response?.status === 409) {
          message.error('策略组下存在策略，无法删除')
        } else {
          message.error('删除策略组失败')
        }
      }
    },
  })
}

// 提交策略组表单
const handleGroupModalOk = async () => {
  try {
    await groupFormRef.value?.validate()
    groupModalLoading.value = true

    if (editingGroup.value) {
      await policyGroupsApi.update(editingGroup.value.id, {
        name: groupFormState.name,
        description: groupFormState.description,
        icon: groupFormState.icon,
        color: groupFormState.color,
        sort_order: groupFormState.sort_order,
        enabled: groupFormState.enabled,
      })
      message.success('更新成功')
      // 如果当前在策略组详情页，更新当前组信息
      if (currentGroup.value && currentGroup.value.id === editingGroup.value.id) {
        currentGroup.value = {
          ...currentGroup.value,
          name: groupFormState.name,
          description: groupFormState.description,
          icon: groupFormState.icon,
          color: groupFormState.color,
          sort_order: groupFormState.sort_order,
          enabled: groupFormState.enabled,
        }
      }
    } else {
      await policyGroupsApi.create({
        id: groupFormState.id || undefined,
        name: groupFormState.name,
        description: groupFormState.description,
        icon: groupFormState.icon,
        color: groupFormState.color,
        sort_order: groupFormState.sort_order,
        enabled: groupFormState.enabled,
      })
      message.success('创建成功')
    }

    groupModalVisible.value = false
    loadPolicyGroups()
  } catch (error: any) {
    if (error?.errorFields) {
      return
    }
    console.error('保存策略组失败:', error)
    if (error.response?.status === 409) {
      message.error('策略组 ID 已存在')
    } else {
      message.error('保存策略组失败')
    }
  } finally {
    groupModalLoading.value = false
  }
}

// 取消策略组表单
const handleGroupModalCancel = () => {
  groupModalVisible.value = false
  resetGroupForm()
}

// 重置策略组表单
const resetGroupForm = () => {
  groupFormState.id = ''
  groupFormState.name = ''
  groupFormState.description = ''
  groupFormState.icon = ''
  groupFormState.color = '#3B82F6'
  groupFormState.sort_order = 0
  groupFormState.enabled = true
  groupFormRef.value?.resetFields()
}

// === 策略管理 ===

// 进入策略规则管理页面
const handleEnterPolicy = (policy: Policy) => {
  router.push(`/policy-groups/policies/${policy.id}/rules`)
}

// 创建策略
const handleCreatePolicy = () => {
  editingPolicy.value = null
  policyModalVisible.value = true
}

// 编辑策略
const handleEditPolicy = (policy: Policy) => {
  editingPolicy.value = policy
  policyModalVisible.value = true
}

// 切换策略启用状态
const handleTogglePolicy = async (policy: Policy, checked: boolean) => {
  try {
    await policiesApi.update(policy.id, { enabled: checked })
    message.success(checked ? '已启用策略' : '已禁用策略')
    loadGroupPolicies()
  } catch (error) {
    console.error('更新策略失败:', error)
    message.error('更新策略失败')
  }
}

// 删除策略
const handleDeletePolicy = async (policy: Policy) => {
  try {
    await policiesApi.delete(policy.id)
    message.success('删除成功')
    loadGroupPolicies()
  } catch (error) {
    console.error('删除策略失败:', error)
    message.error('删除策略失败')
  }
}

// 策略保存成功
const handlePolicyModalSuccess = () => {
  policyModalVisible.value = false
  loadGroupPolicies()
  // 同时刷新策略组列表以更新统计数据
  loadPolicyGroups()
}

// === 批量操作 ===

// 批量启用/禁用
const handleBatchEnable = async (enabled: boolean) => {
  try {
    await policiesApi.batchEnableDisable(selectedPolicyIds.value, enabled)
    message.success(`已${enabled ? '启用' : '禁用'} ${selectedPolicyIds.value.length} 个策略`)
    selectedPolicyIds.value = []
    loadGroupPolicies()
  } catch (error) {
    console.error('批量操作失败:', error)
    message.error('批量操作失败')
  }
}

// 批量删除
const handleBatchDelete = async () => {
  try {
    await policiesApi.batchDelete(selectedPolicyIds.value)
    message.success(`已删除 ${selectedPolicyIds.value.length} 个策略`)
    selectedPolicyIds.value = []
    loadGroupPolicies()
  } catch (error) {
    console.error('批量删除失败:', error)
    message.error('批量删除失败')
  }
}

// 批量导出
const handleBatchExport = async () => {
  try {
    const response = await policiesApi.batchExport(selectedPolicyIds.value)
    downloadJSON(response, `policies-batch-${Date.now()}.json`)
    message.success(`已导出 ${selectedPolicyIds.value.length} 个策略`)
  } catch (error) {
    console.error('批量导出失败:', error)
    message.error('批量导出失败')
  }
}

// === 导入/导出功能 ===

// 导出菜单点击
const handleExportMenuClick = async ({ key }: { key: string }) => {
  try {
    if (key === 'export-all') {
      // 导出所有策略
      const response = await policiesApi.exportAll()
      downloadJSON(response, 'policies-all.json')
      message.success('导出成功')
    } else if (key === 'export-group' && currentGroup.value) {
      // 导出当前策略组的所有策略
      const policies = groupPolicies.value
      if (policies.length === 0) {
        message.warning('当前策略组没有策略')
        return
      }

      // 导出每个策略的详细信息
      const exportData = []
      for (const policy of policies) {
        const detail = await policiesApi.export(policy.id)
        exportData.push(detail)
      }

      downloadJSON(exportData, `policies-${currentGroup.value.id}.json`)
      message.success(`已导出 ${exportData.length} 个策略`)
    }
  } catch (error) {
    console.error('导出失败:', error)
    message.error('导出失败')
  }
}

// 导入文件
const handleImportFile = async (file: File) => {
  if (!currentGroup.value) {
    message.error('请先选择一个策略组')
    return false
  }

  try {
    // 读取文件内容
    const text = await file.text()
    const data = JSON.parse(text)

    // 显示导入确认对话框
    Modal.confirm({
      title: '确认导入',
      content: `即将导入 ${Array.isArray(data) ? data.length : 1} 个策略到「${currentGroup.value.name}」策略组，导入模式为"更新"（保留未在文件中的规则）。是否继续？`,
      okText: '导入',
      cancelText: '取消',
      onOk: async () => {
        try {
          const formData = new FormData()
          formData.append('file', file)
          formData.append('group_id', currentGroup.value!.id)

          const result = await policiesApi.import(formData)

          message.success(
            `导入完成：新增 ${result.imported} 个，更新 ${result.updated} 个，跳过 ${result.skipped} 个`
          )

          if (result.errors && result.errors.length > 0) {
            Modal.warning({
              title: '部分导入失败',
              content: result.errors.join('\n'),
            })
          }

          // 刷新列表
          if (currentGroup.value) {
            loadGroupPolicies()
          }
          loadPolicyGroups()
        } catch (error: any) {
          console.error('导入失败:', error)
          message.error(error.response?.data?.message || '导入失败')
        }
      },
    })
  } catch (error) {
    console.error('读取文件失败:', error)
    message.error('文件格式错误，请上传有效的 JSON 文件')
  }

  // 返回 false 阻止自动上传
  return false
}

// 下载 JSON 文件
const downloadJSON = (data: any, filename: string) => {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

// 从 URL 参数恢复状态
const restoreStateFromUrl = async () => {
  const groupId = route.query.group_id as string
  if (groupId && policyGroups.value.length > 0) {
    const group = policyGroups.value.find(g => g.id === groupId)
    if (group) {
      currentGroup.value = group
      await loadGroupPolicies()
    }
  }
}

onMounted(async () => {
  await loadPolicyGroups()
  // 加载完策略组后，检查 URL 参数恢复状态
  await restoreStateFromUrl()
})

// 监听路由参数变化
watch(
  () => route.query.group_id,
  async (newGroupId) => {
    if (newGroupId) {
      // 有 group_id 参数，尝试进入该策略组
      if (policyGroups.value.length > 0) {
        const group = policyGroups.value.find(g => g.id === newGroupId)
        if (group && currentGroup.value?.id !== group.id) {
          currentGroup.value = group
          await loadGroupPolicies()
        }
      }
    } else {
      // 没有 group_id 参数，返回列表
      if (currentGroup.value) {
        currentGroup.value = null
        policySearchKeyword.value = ''
        groupPolicies.value = []
      }
    }
  }
)
</script>

<style scoped>
.policy-groups-page {
  width: 100%;
}

.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 24px;
}

.page-header h2 {
  margin: 0;
}

.breadcrumb-header {
  display: flex;
  align-items: center;
}

.groups-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
  gap: 16px;
}

.group-card {
  transition: all 0.3s ease;
}

.group-card.disabled {
  opacity: 0.6;
}

.group-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08),
    0 8px 24px rgba(0, 0, 0, 0.06);
}

.card-title {
  display: flex;
  align-items: center;
  gap: 8px;
}

.group-icon {
  width: 32px;
  height: 32px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--mxsec-card-bg);
  font-weight: bold;
  font-size: 16px;
}

.group-icon.small {
  width: 28px;
  height: 28px;
  font-size: 14px;
}

.group-name {
  font-weight: 500;
  font-size: 16px;
}

.group-description {
  color: var(--mxsec-text-3);
  margin-bottom: 16px;
  min-height: 44px;
  display: -webkit-box;
  -webkit-line-clamp: 2;
  -webkit-box-orient: vertical;
  overflow: hidden;
}

.group-stats {
  margin-bottom: 16px;
  padding: 16px;
  background: var(--mxsec-fill-1);
  border-radius: 8px;
  border: 1px solid var(--mxsec-border);
}

.group-footer {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding-top: 12px;
  border-top: 1px solid var(--mxsec-border);
}

.host-count {
  color: var(--mxsec-text-3);
  font-size: 13px;
}

.empty-state {
  grid-column: 1 / -1;
  padding: 60px 0;
}

.group-info-card {
  margin-bottom: 16px;
}
</style>
