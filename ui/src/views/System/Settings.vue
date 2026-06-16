<template>
  <div class="system-settings-page">
    <div class="page-header">
      <h2>基本设置</h2>
      <p class="page-description">配置产品信息、站点名称、Logo 和域名设置</p>
    </div>

    <a-form
      :model="form"
      :rules="rules"
      ref="formRef"
      layout="vertical"
      @finish="handleSubmit"
      class="settings-form"
    >
      <a-form-item label="站点名称" name="site_name">
        <a-input
          v-model:value="form.site_name"
          placeholder="请输入站点名称"
          :maxlength="50"
          show-count
        />
        <div class="form-item-hint">站点名称将显示在登录页面、导航栏和网页标题中</div>
      </a-form-item>

      <a-form-item label="站点 Logo" name="site_logo">
        <div class="logo-upload-section">
          <div v-if="logoPreview || form.site_logo" class="logo-preview">
            <img
              v-if="logoPreview"
              :src="logoPreview"
              alt="Logo 预览"
              class="logo-image"
            />
            <img
              v-else-if="form.site_logo"
              :src="form.site_logo"
              alt="当前 Logo"
              class="logo-image"
              @error="handleImageError"
            />
            <div class="logo-actions">
              <a-button type="link" size="small" @click="handleRemoveLogo" danger>
                删除 Logo
              </a-button>
            </div>
          </div>
          <div v-if="!logoPreview && !form.site_logo">
            <a-upload
              v-model:file-list="fileList"
              :before-upload="beforeUpload"
              :custom-request="handleUpload"
              :show-upload-list="false"
              accept="image/*"
            >
              <a-button type="primary">
                <template #icon>
                  <UploadOutlined />
                </template>
                上传 Logo
              </a-button>
            </a-upload>
          </div>
          <div v-else style="margin-top: 8px">
            <a-button @click="triggerUpload">
              <template #icon>
                <UploadOutlined />
              </template>
              更换 Logo
            </a-button>
          </div>
          <div class="upload-hint">
            支持 JPG、PNG、GIF、SVG、WEBP 格式，文件大小不超过 5MB
          </div>
        </div>
      </a-form-item>

      <a-form-item label="前端访问域名" name="site_domain">
        <a-input
          v-model:value="form.site_domain"
          placeholder="例如：http://192.168.8.140:3000"
          :maxlength="200"
        />
        <div class="form-item-hint">设置前端访问地址，用于生成安装脚本中的下载链接</div>
      </a-form-item>

      <a-form-item label="后端接口地址" name="backend_url">
        <a-input
          v-model:value="form.backend_url"
          placeholder="例如：http://192.168.8.140:8080 或 http://manager:8080"
          :maxlength="200"
        />
        <div class="form-item-hint">设置后端 API 地址，用于 Agent 下载更新和插件（必填）</div>
      </a-form-item>

      <a-form-item>
        <a-space>
          <a-button type="primary" html-type="submit" :loading="saving">
            保存设置
          </a-button>
          <a-button @click="handleReset">重置</a-button>
        </a-space>
      </a-form-item>
    </a-form>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { UploadOutlined } from '@ant-design/icons-vue'
import type { UploadFile, UploadProps } from 'ant-design-vue'
import { systemConfigApi, type SiteConfig } from '@/api/system-config'

const saving = ref(false)
const logoPreview = ref<string>('')
const fileList = ref<UploadFile[]>([])

const form = reactive<SiteConfig>({
  site_name: '矩阵云安全平台',
  site_logo: '',
  site_domain: '',
  backend_url: '',
})

const rules = {
  site_name: [
    { required: true, message: '请输入站点名称', trigger: 'blur' },
    { max: 50, message: '站点名称不能超过 50 个字符', trigger: 'blur' },
  ],
  site_domain: [
    {
      // 支持 IP 地址、域名、端口号和路径
      pattern: /^https?:\/\/([\w-]+(\.[\w-]+)*|(\d{1,3}\.){3}\d{1,3}|[\w-]+)(:\d+)?(\/.*)?$/,
      message: '请输入有效的URL格式（例如：http://192.168.8.140:3000）',
      trigger: 'blur',
    },
  ],
  backend_url: [
    { required: true, message: '请输入后端接口地址', trigger: 'blur' },
    {
      // 支持 IP 地址、域名、端口号
      pattern: /^https?:\/\/([\w-]+(\.[\w-]+)*|(\d{1,3}\.){3}\d{1,3}|[\w-]+)(:\d+)?(\/.*)?$/,
      message: '请输入有效的URL格式（例如：http://192.168.8.140:8080 或 http://manager:8080）',
      trigger: 'blur',
    },
  ],
}

// 加载配置
const loadConfig = async () => {
  try {
    const config = (await systemConfigApi.getSiteConfig()) as any as SiteConfig
    form.site_name = config.site_name || '矩阵云安全平台'
    form.site_logo = config.site_logo || ''
    form.site_domain = config.site_domain || ''
    form.backend_url = config.backend_url || ''
  } catch (error) {
    console.error('加载站点配置失败:', error)
    // 使用默认值，不显示错误（因为可能是首次访问，配置不存在）
  }
}

// 触发文件选择
const triggerUpload = () => {
  const input = document.createElement('input')
  input.type = 'file'
  input.accept = 'image/*'
  input.onchange = (e: Event) => {
    const target = e.target as HTMLInputElement
    if (target.files && target.files[0]) {
      handleFileSelect(target.files[0])
    }
  }
  input.click()
}

// 处理文件选择
const handleFileSelect = async (file: File) => {
  // 验证文件类型
  const isImage = file.type.startsWith('image/')
  if (!isImage) {
    message.error('只能上传图片文件！')
    return
  }
  // 验证文件大小
  const isLt5M = file.size / 1024 / 1024 < 5
  if (!isLt5M) {
    message.error('图片大小不能超过 5MB！')
    return
  }

  // 创建预览
  const reader = new FileReader()
  reader.onload = (e) => {
    logoPreview.value = e.target?.result as string
  }
  reader.readAsDataURL(file)

  // 上传文件
  saving.value = true
  try {
    const response = (await systemConfigApi.uploadLogo(file)) as any as { logo_url: string }
    form.site_logo = response.logo_url
    // 清除预览，使用实际的logo URL
    logoPreview.value = ''
    message.success('Logo 上传成功')
    fileList.value = []
    // 触发全局配置更新
    window.dispatchEvent(new CustomEvent('site-config-updated'))
  } catch (error) {
    console.error('上传 Logo 失败:', error)
    logoPreview.value = ''
  } finally {
    saving.value = false
  }
}

// 上传前验证
const beforeUpload: UploadProps['beforeUpload'] = (file) => {
  handleFileSelect(file as File)
  return false // 阻止自动上传，使用自定义上传
}

// 自定义上传（Upload 组件回调）
const handleUpload = async (options: any) => {
  const { file } = options
  await handleFileSelect(file as File)
}

// 删除 Logo
const handleRemoveLogo = () => {
  form.site_logo = ''
  logoPreview.value = ''
  fileList.value = []
  message.success('Logo 已删除')
}

// 图片加载错误
const handleImageError = () => {
  form.site_logo = ''
  message.warning('Logo 图片加载失败，请重新上传')
}

// 提交表单
const handleSubmit = async () => {
  try {
    saving.value = true
    // 构建请求数据：如果 site_logo 为空字符串，不传递该字段（让后端保留现有值）
    const requestData: {
      site_name: string
      site_logo?: string
      site_domain: string
      backend_url: string
    } = {
      site_name: form.site_name,
      site_domain: form.site_domain,
      backend_url: form.backend_url,
    }
    // 只有当 site_logo 有值时才传递（包括用户上传的新logo）
    // 如果为空字符串，不传递，让后端保留现有logo
    if (form.site_logo) {
      requestData.site_logo = form.site_logo
    }
    await systemConfigApi.updateSiteConfig(requestData)
    message.success('设置保存成功')
    // 触发全局配置更新（如果有 store）
    window.dispatchEvent(new CustomEvent('site-config-updated'))
  } catch (error) {
    console.error('保存设置失败:', error)
  } finally {
    saving.value = false
  }
}

// 重置表单
const handleReset = async () => {
  await loadConfig()
  logoPreview.value = ''
  fileList.value = []
  message.info('已重置为当前配置')
}

onMounted(() => {
  loadConfig()
})
</script>

<style scoped>
.system-settings-page {
  width: 100%;
}

.page-header {
  margin-bottom: 32px;
}

.page-header h2 {
  margin: 0 0 8px 0;
  font-size: 20px;
  font-weight: 600;
}

.page-description {
  margin: 0;
  color: var(--mxsec-text-3);
  font-size: 14px;
}

.settings-form {
  max-width: 800px;
}

.form-item-hint {
  margin-top: 4px;
  color: var(--mxsec-text-3);
  font-size: 12px;
}

.logo-upload-section {
  display: flex;
  flex-direction: column;
  gap: 16px;
}

.logo-preview {
  position: relative;
  display: inline-block;
  border: 1px solid #e8e8e8;
  border-radius: 8px;
  padding: 16px;
  background: var(--mxsec-fill-1);
  margin-bottom: 8px;
  transition: all 0.2s ease;
}

.logo-preview:hover {
  border-color: var(--mxsec-primary);
  box-shadow: 0 2px 8px rgba(24, 144, 255, 0.1);
}

.logo-image {
  max-width: 200px;
  max-height: 100px;
  object-fit: contain;
  display: block;
}

.logo-actions {
  margin-top: 8px;
  text-align: center;
}

.upload-hint {
  margin-top: 8px;
  color: var(--mxsec-text-3);
  font-size: 12px;
}
</style>
