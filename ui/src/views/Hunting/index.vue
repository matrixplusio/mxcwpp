<template>
  <div class="hunting-page">
    <div class="page-header">
      <h2>威胁狩猎</h2>
    </div>

    <!-- MQL 编辑器 -->
    <a-card size="small" class="editor-card">
      <div class="editor-header">
        <span class="editor-title">MQL 查询</span>
        <a-space>
          <a-select
            v-model:value="selectedTemplate"
            placeholder="选择模板"
            style="width: 200px"
            allow-clear
            @change="applyTemplate"
          >
            <a-select-option v-for="tpl in templates" :key="tpl.id" :value="tpl.id">
              {{ tpl.name }}
            </a-select-option>
          </a-select>
          <a-button type="primary" :loading="querying" @click="executeQuery">
            <ThunderboltOutlined /> 执行
          </a-button>
          <a-button @click="saveQueryVisible = true" :disabled="!mql.trim()">
            <SaveOutlined /> 保存
          </a-button>
        </a-space>
      </div>
      <a-textarea
        v-model:value="mql"
        :rows="4"
        placeholder="输入 MQL 查询语句，例如: FROM process WHERE exe CONTAINS '/tmp/' AND cmdline CONTAINS 'bash' LAST 24h LIMIT 100"
        class="mql-input"
      />
      <div class="editor-footer">
        <span class="hint-text">语法: FROM &lt;source&gt; WHERE &lt;conditions&gt; LAST &lt;duration&gt; LIMIT &lt;n&gt;</span>
        <span v-if="queryResult" class="result-meta">
          {{ queryResult.total_rows }} 条结果，耗时 {{ queryResult.elapsed_ms }}ms
        </span>
      </div>
    </a-card>

    <!-- 查询结果 -->
    <a-card v-if="queryResult" size="small" class="result-card">
      <template #title>
        <span>查询结果</span>
        <a-tag color="blue" style="margin-left: 8px">{{ queryResult.total_rows }} 行</a-tag>
      </template>
      <a-table
        :columns="resultColumns"
        :data-source="queryResult.rows"
        :row-key="(_: Record<string, unknown>, index: number) => index"
        size="small"
        :scroll="{ x: 'max-content' }"
        :pagination="{ pageSize: 50, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` }"
      />
    </a-card>

    <!-- 查询错误 -->
    <a-alert v-if="queryError" type="error" :message="queryError" show-icon closable style="margin-top: 16px" />

    <!-- 已保存的查询 -->
    <a-card size="small" title="已保存的查询" class="saved-card">
      <a-table
        :columns="savedColumns"
        :data-source="savedQueries"
        :loading="savedLoading"
        :pagination="savedPagination"
        row-key="id"
        size="small"
        @change="handleSavedTableChange"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'severity'">
            <a-tag :color="getSeverityConfig(record.severity).tagColor">
              {{ getSeverityConfig(record.severity).label }}
            </a-tag>
          </template>
          <template v-if="column.key === 'mql'">
            <code class="mql-preview">{{ record.mql }}</code>
          </template>
          <template v-if="column.key === 'action'">
            <a-space>
              <a @click="loadQuery(record)">加载</a>
              <a-popconfirm
                v-if="!record.is_builtin"
                title="确认删除此查询？"
                @confirm="deleteQuery(record.id)"
              >
                <a style="color: #EF4444">删除</a>
              </a-popconfirm>
              <a-tag v-if="record.is_builtin" size="small">内置</a-tag>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 保存查询弹窗 -->
    <a-modal v-model:open="saveQueryVisible" title="保存查询" @ok="handleSaveQuery" :confirm-loading="saving">
      <a-form layout="vertical">
        <a-form-item label="名称" required>
          <a-input v-model:value="saveForm.name" placeholder="查询名称" />
        </a-form-item>
        <a-form-item label="描述">
          <a-input v-model:value="saveForm.description" placeholder="描述（可选）" />
        </a-form-item>
        <a-form-item label="分类">
          <a-select v-model:value="saveForm.category" placeholder="选择分类" allow-clear>
            <a-select-option value="reconnaissance">侦察</a-select-option>
            <a-select-option value="persistence">持久化</a-select-option>
            <a-select-option value="exfiltration">数据窃取</a-select-option>
            <a-select-option value="lateral_movement">横向移动</a-select-option>
            <a-select-option value="command_and_control">C2 通信</a-select-option>
            <a-select-option value="other">其他</a-select-option>
          </a-select>
        </a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted } from 'vue'
import { ThunderboltOutlined, SaveOutlined } from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import { huntingApi } from '@/api/hunting'
import type { HuntQuery, QueryResult } from '@/api/hunting'
import { getSeverityConfig } from '@/constants/severity'

const mql = ref('')
const querying = ref(false)
const saving = ref(false)
const savedLoading = ref(false)
const saveQueryVisible = ref(false)
const selectedTemplate = ref<number | undefined>(undefined)
const queryResult = ref<QueryResult | null>(null)
const queryError = ref('')

const savedQueries = ref<HuntQuery[]>([])
const templates = computed(() => savedQueries.value.filter(q => q.is_builtin))

const saveForm = reactive({
  name: '',
  description: '',
  category: undefined as string | undefined,
})

const savedPagination = reactive({
  current: 1,
  pageSize: 10,
  total: 0,
  showTotal: (total: number) => `共 ${total} 条`,
})

const resultColumns = computed(() => {
  if (!queryResult.value?.columns) return []
  return queryResult.value.columns.map(col => ({
    title: col,
    dataIndex: col,
    key: col,
    ellipsis: true,
  }))
})

const savedColumns = [
  { title: '名称', dataIndex: 'name', width: 180 },
  { title: '分类', dataIndex: 'category', width: 100 },
  { title: '严重度', key: 'severity', width: 80, align: 'center' as const },
  { title: 'MQL', key: 'mql', ellipsis: true },
  { title: '创建者', dataIndex: 'owner', width: 100 },
  { title: '更新时间', dataIndex: 'updated_at', width: 170 },
  { title: '操作', key: 'action', width: 120 },
]

const executeQuery = async () => {
  if (!mql.value.trim()) {
    message.warning('请输入 MQL 查询语句')
    return
  }
  querying.value = true
  queryError.value = ''
  queryResult.value = null
  try {
    queryResult.value = await huntingApi.executeQuery(mql.value)
  } catch (err: any) {
    queryError.value = err.message || '查询执行失败'
  } finally {
    querying.value = false
  }
}

const fetchSavedQueries = async () => {
  savedLoading.value = true
  try {
    const res = await huntingApi.listQueries({
      page: savedPagination.current,
      page_size: savedPagination.pageSize,
    })
    savedQueries.value = res.items || []
    savedPagination.total = res.total
  } catch {
    // handled
  } finally {
    savedLoading.value = false
  }
}

const loadQuery = (query: HuntQuery) => {
  mql.value = query.mql
  message.info(`已加载查询: ${query.name}`)
}

const applyTemplate = (id: number) => {
  const tpl = savedQueries.value.find(q => q.id === id)
  if (tpl) {
    mql.value = tpl.mql
  }
}

const handleSaveQuery = async () => {
  if (!saveForm.name.trim()) {
    message.warning('请输入查询名称')
    return
  }
  saving.value = true
  try {
    await huntingApi.createQuery({
      name: saveForm.name,
      description: saveForm.description,
      mql: mql.value,
      category: saveForm.category,
    })
    message.success('查询已保存')
    saveQueryVisible.value = false
    saveForm.name = ''
    saveForm.description = ''
    saveForm.category = undefined
    fetchSavedQueries()
  } catch {
    // handled
  } finally {
    saving.value = false
  }
}

const deleteQuery = async (id: number) => {
  try {
    await huntingApi.deleteQuery(id)
    message.success('查询已删除')
    fetchSavedQueries()
  } catch {
    // handled
  }
}

const handleSavedTableChange = (pag: any) => {
  savedPagination.current = pag.current
  savedPagination.pageSize = pag.pageSize
  fetchSavedQueries()
}

onMounted(() => {
  fetchSavedQueries()
})
</script>

<style scoped>
.hunting-page { padding: 0; }
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 16px;
}
.page-header h2 { margin: 0; font-size: 20px; }
.editor-card { margin-bottom: 16px; }
.editor-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}
.editor-title { font-weight: 600; font-size: 14px; }
.mql-input { font-family: monospace; font-size: 13px; }
.editor-footer {
  display: flex;
  justify-content: space-between;
  margin-top: 8px;
}
.hint-text { color: #999; font-size: 12px; }
.result-meta { color: var(--mxsec-primary); font-size: 12px; }
.result-card { margin-bottom: 16px; }
.saved-card { margin-top: 16px; }
.mql-preview {
  font-size: 12px;
  color: #555;
  max-width: 300px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  display: inline-block;
}
</style>
