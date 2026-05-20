<template>
  <div class="sbom-import-page">
    <div class="page-header">
      <h2>SBOM 导入</h2>
      <span class="page-header-hint">导入 CycloneDX / SPDX 格式的软件物料清单并扫描漏洞</span>
    </div>

    <!-- 导入区域 -->
    <div class="dashboard-card" style="margin-bottom: 16px;">
      <div class="card-body">
        <a-form layout="inline">
          <a-form-item label="项目名称">
            <a-input v-model:value="projectName" placeholder="例如: my-app" style="width: 200px" />
          </a-form-item>
          <a-form-item label="SBOM 文件">
            <a-upload
              :before-upload="beforeUpload"
              :file-list="fileList"
              :max-count="1"
              accept=".json,.xml"
            >
              <a-button>选择文件</a-button>
            </a-upload>
          </a-form-item>
          <a-form-item>
            <a-button type="primary" :loading="importing" @click="handleImport">导入并扫描</a-button>
          </a-form-item>
        </a-form>
      </div>
    </div>

    <!-- 导入结果 -->
    <a-alert
      v-if="importResult"
      type="success"
      show-icon
      style="margin-bottom: 16px"
      :message="`项目 ${importResult.projectName} 导入完成：${importResult.componentCount} 个组件，${importResult.vulnCount} 个已知漏洞（${importResult.criticalCount} 严重 / ${importResult.highCount} 高危）`"
    />

    <!-- 项目列表 -->
    <div class="dashboard-card">
      <div class="card-body">
        <div class="filter-bar">
          <span class="section-title">SBOM 项目</span>
          <div class="filter-actions">
            <a-button @click="loadProjects">刷新</a-button>
          </div>
        </div>

        <a-table
          :columns="columns"
          :data-source="projects"
          :loading="loading"
          size="middle"
          row-key="name"
        >
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'action'">
              <a-button type="link" size="small" @click="showDetail(record.name)">查看组件</a-button>
            </template>
          </template>
        </a-table>
      </div>
    </div>

    <!-- 组件详情抽屉 -->
    <a-drawer
      v-model:open="detailVisible"
      :title="`SBOM 组件 - ${detailProject}`"
      :width="800"
      placement="right"
    >
      <a-table
        :columns="detailColumns"
        :data-source="detailComponents"
        :loading="detailLoading"
        size="small"
        row-key="id"
      />
    </a-drawer>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { message } from 'ant-design-vue'
import type { UploadProps } from 'ant-design-vue'
import apiClient from '@/api/client'

const projectName = ref('')
const fileList = ref<any[]>([])
const importing = ref(false)
const importResult = ref<any>(null)

const loading = ref(false)
const projects = ref<any[]>([])

const detailVisible = ref(false)
const detailProject = ref('')
const detailLoading = ref(false)
const detailComponents = ref<any[]>([])

const columns = [
  { title: '项目名称', dataIndex: 'name', width: 200 },
  { title: '组件数', dataIndex: 'componentCount', width: 100 },
  { title: '漏洞数', dataIndex: 'vulnCount', width: 100 },
  { title: '操作', key: 'action', width: 100 },
]

const detailColumns = [
  { title: '组件', dataIndex: 'name', width: 200 },
  { title: '版本', dataIndex: 'version', width: 120 },
  { title: '生态系统', dataIndex: 'ecosystem', width: 100 },
  { title: 'PURL', dataIndex: 'purl', ellipsis: true },
]

const beforeUpload: UploadProps['beforeUpload'] = (file) => {
  fileList.value = [file]
  return false
}

const handleImport = async () => {
  if (!projectName.value.trim()) {
    message.warning('请输入项目名称')
    return
  }
  if (fileList.value.length === 0) {
    message.warning('请选择 SBOM 文件')
    return
  }

  importing.value = true
  try {
    const formData = new FormData()
    formData.append('file', fileList.value[0] as any)
    formData.append('project', projectName.value.trim())
    formData.append('format', 'auto')

    const res = await apiClient.post('/sbom/import', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    importResult.value = res
    message.success('SBOM 导入成功')
    fileList.value = []
    loadProjects()
  } catch {
    message.error('SBOM 导入失败')
  } finally {
    importing.value = false
  }
}

const loadProjects = async () => {
  loading.value = true
  try {
    const res = await apiClient.get<any[]>('/sbom/projects')
    projects.value = res ?? []
  } catch {
    projects.value = []
  } finally {
    loading.value = false
  }
}

const showDetail = async (name: string) => {
  detailProject.value = name
  detailVisible.value = true
  detailLoading.value = true
  try {
    const res = await apiClient.get<any>(`/sbom/projects/${name}`)
    detailComponents.value = res?.components ?? []
  } catch {
    detailComponents.value = []
  } finally {
    detailLoading.value = false
  }
}

onMounted(() => {
  loadProjects()
})
</script>

<style scoped>
.sbom-import-page { width: 100%; }
.page-header { display: flex; align-items: baseline; gap: 12px; margin-bottom: 24px; }
.page-header h2 { margin: 0; font-size: 20px; font-weight: 600; }
.page-header-hint { font-size: 13px; color: #86909C; }
.dashboard-card { background: #FFFFFF; border: 1px solid #E5E8EF; border-radius: 8px; }
.card-body { padding: 20px; }
.filter-bar { display: flex; gap: 12px; margin-bottom: 16px; align-items: center; }
.filter-actions { margin-left: auto; }
.section-title { font-size: 14px; font-weight: 600; color: #262626; }
</style>
