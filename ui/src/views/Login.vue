<template>
  <div class="login-page">
    <!-- 背景动画 -->
    <div class="bg-grid">
      <div class="grid-line" v-for="i in 20" :key="'h'+i" :style="{ top: (i * 5) + '%' }"></div>
      <div class="grid-line vertical" v-for="i in 20" :key="'v'+i" :style="{ left: (i * 5) + '%' }"></div>
    </div>
    <div class="bg-nodes">
      <div class="node" v-for="i in 8" :key="'n'+i" :class="'node-' + i"></div>
    </div>

    <!-- 左侧：Logo + 介绍 -->
    <div class="left-side">
      <div class="left-inner">
        <img src="/logo-wide.png" alt="MxSec Platform" class="brand-logo" />
        <h2 class="brand-headline">蓝队实战化安全运营平台</h2>
        <p class="brand-sub">威胁监测 · 攻击溯源 · 应急响应 · 持续防御</p>
      </div>
    </div>

    <!-- 右侧：登录悬浮卡片 -->
    <div class="right-side">
      <div class="login-card">
        <div class="card-header">
          <h1>{{ siteConfigStore.siteName }}</h1>
          <p>安全管理控制台</p>
        </div>

        <a-form
          :model="form"
          :rules="rules"
          @finish="handleLogin"
          class="login-form"
          layout="vertical"
        >
          <a-form-item name="username">
            <a-input
              v-model:value="form.username"
              size="large"
              placeholder="用户名"
              :prefix="h(UserOutlined)"
              class="login-input"
            />
          </a-form-item>
          <a-form-item name="password">
            <a-input-password
              v-model:value="form.password"
              size="large"
              placeholder="密码"
              :prefix="h(LockOutlined)"
              class="login-input"
            />
          </a-form-item>
          <a-form-item name="captcha_code">
            <div class="captcha-row">
              <a-input
                v-model:value="form.captcha_code"
                size="large"
                placeholder="验证码"
                :prefix="h(SafetyCertificateOutlined)"
                @pressEnter="handleLogin"
                class="captcha-input"
              />
              <img
                v-if="captchaImage"
                :src="captchaImage"
                alt="验证码"
                class="captcha-image"
                @click="refreshCaptcha"
                title="点击刷新验证码"
              />
              <div v-else class="captcha-placeholder" @click="refreshCaptcha">
                加载中...
              </div>
            </div>
          </a-form-item>
          <a-form-item>
            <a-button
              type="primary"
              html-type="submit"
              size="large"
              block
              :loading="loading"
              class="login-button"
            >
              登录
            </a-button>
          </a-form-item>
        </a-form>

        <div v-if="error" class="error-message">
          <a-alert :message="error" type="error" show-icon />
        </div>

        <!-- 强制修改密码弹窗 -->
        <a-modal
          v-model:open="showChangePassword"
          title="首次登录 — 请修改默认密码"
          :closable="false"
          :maskClosable="false"
          :footer="null"
        >
          <p style="color: #86909C; margin-bottom: 16px;">为确保账户安全，请设置新密码（至少 8 位）</p>
          <a-form layout="vertical" @finish="handleChangePassword">
            <a-form-item label="新密码" required>
              <a-input-password
                v-model:value="changePasswordForm.new_password"
                placeholder="请输入新密码（至少 8 位）"
              />
            </a-form-item>
            <a-form-item label="确认新密码" required>
              <a-input-password
                v-model:value="changePasswordForm.confirm_password"
                placeholder="请再次输入新密码"
              />
            </a-form-item>
            <a-form-item>
              <a-button type="primary" html-type="submit" block :loading="changePwdLoading">
                确认修改
              </a-button>
            </a-form-item>
          </a-form>
        </a-modal>
      </div>
    </div>

    <!-- 页脚：全局居中 -->
    <div class="login-footer">
      &copy; {{ new Date().getFullYear() }} {{ siteConfigStore.siteName }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, h, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { UserOutlined, LockOutlined, SafetyCertificateOutlined } from '@ant-design/icons-vue'
import { useAuthStore } from '@/stores/auth'
import { useSiteConfigStore } from '@/stores/site-config'
import { authApi } from '@/api/auth'
import type { Rule } from 'ant-design-vue/es/form'

const router = useRouter()
const authStore = useAuthStore()
const siteConfigStore = useSiteConfigStore()

const captchaId = ref('')
const captchaImage = ref('')

const refreshCaptcha = async () => {
  try {
    const res = await authApi.getCaptcha()
    captchaId.value = res.captcha_id
    captchaImage.value = res.captcha_image
  } catch (e) {
    console.error('获取验证码失败:', e)
  }
}

onMounted(() => {
  siteConfigStore.init()
  refreshCaptcha()
})

const loading = ref(false)
const error = ref('')

const form = reactive({
  username: '',
  password: '',
  captcha_code: '',
})

const rules: Record<string, Rule[]> = {
  username: [{ required: true, message: '请输入用户名', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
  captcha_code: [{ required: true, message: '请输入验证码', trigger: 'blur' }],
}

const showChangePassword = ref(false)
const changePasswordForm = reactive({
  old_password: '',
  new_password: '',
  confirm_password: '',
})
const changePwdLoading = ref(false)

const handleLogin = async () => {
  error.value = ''
  loading.value = true
  try {
    const response = await authStore.login({
      username: form.username,
      password: form.password,
      captcha_id: captchaId.value,
      captcha_code: form.captcha_code,
    })
    if (response.need_change_password) {
      showChangePassword.value = true
      changePasswordForm.old_password = form.password
    } else {
      router.push('/')
    }
  } catch (err: any) {
    error.value = err.message || '登录失败，请检查用户名和密码'
    form.captcha_code = ''
    refreshCaptcha()
  } finally {
    loading.value = false
  }
}

const handleChangePassword = async () => {
  if (changePasswordForm.new_password !== changePasswordForm.confirm_password) {
    error.value = '两次输入的密码不一致'
    return
  }
  if (changePasswordForm.new_password.length < 8) {
    error.value = '新密码长度至少 8 位'
    return
  }
  changePwdLoading.value = true
  error.value = ''
  try {
    await authApi.changePassword({
      old_password: changePasswordForm.old_password,
      new_password: changePasswordForm.new_password,
    })
    showChangePassword.value = false
    router.push('/')
  } catch (err: any) {
    error.value = err.message || '修改密码失败'
  } finally {
    changePwdLoading.value = false
  }
}
</script>

<style scoped>
.login-page {
  display: flex;
  min-height: 100vh;
  width: 100%;
  background: linear-gradient(160deg, #0c0e14 0%, #111520 50%, #141824 100%);
  position: relative;
  overflow: hidden;
}

/* ===== 背景动画 ===== */
.bg-grid {
  position: absolute;
  inset: 0;
  opacity: 0.04;
  pointer-events: none;
}

.grid-line {
  position: absolute;
  left: 0;
  right: 0;
  height: 1px;
  background: linear-gradient(90deg, transparent 0%, #3b82f6 50%, transparent 100%);
}

.grid-line.vertical {
  top: 0;
  bottom: 0;
  width: 1px;
  height: auto;
  background: linear-gradient(180deg, transparent 0%, #3b82f6 50%, transparent 100%);
}

.bg-nodes {
  position: absolute;
  inset: 0;
  pointer-events: none;
}

.node {
  position: absolute;
  width: 6px;
  height: 6px;
  background: #3b82f6;
  border-radius: 50%;
  opacity: 0.4;
  animation: pulse 3s ease-in-out infinite;
}

.node-1 { top: 15%; left: 10%; animation-delay: 0s; }
.node-2 { top: 30%; left: 35%; animation-delay: 0.5s; }
.node-3 { top: 50%; left: 20%; animation-delay: 1s; }
.node-4 { top: 70%; left: 40%; animation-delay: 1.5s; }
.node-5 { top: 25%; left: 45%; animation-delay: 2s; }
.node-6 { top: 60%; left: 8%; animation-delay: 0.8s; }
.node-7 { top: 80%; left: 30%; animation-delay: 1.2s; }
.node-8 { top: 40%; left: 50%; animation-delay: 1.8s; }

@keyframes pulse {
  0%, 100% {
    transform: scale(1);
    opacity: 0.4;
    box-shadow: 0 0 0 0 rgba(59, 130, 246, 0.4);
  }
  50% {
    transform: scale(1.8);
    opacity: 0.8;
    box-shadow: 0 0 12px 4px rgba(59, 130, 246, 0.2);
  }
}

/* ===== 左侧 ===== */
.left-side {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  z-index: 1;
  padding: 60px;
}

.left-inner {
  max-width: 520px;
}

.brand-logo {
  width: 100%;
  max-width: 520px;
  height: auto;
  margin-bottom: 48px;
  filter: drop-shadow(0 0 50px rgba(30, 80, 180, 0.2));
}

.brand-headline {
  font-size: 22px;
  font-weight: 500;
  color: rgba(255, 255, 255, 0.9);
  margin: 0 0 12px 0;
  letter-spacing: 1px;
}

.brand-sub {
  font-size: 15px;
  color: rgba(255, 255, 255, 0.4);
  margin: 0;
  letter-spacing: 2px;
}

/* ===== 右侧 ===== */
.right-side {
  flex: 1;
  display: flex;
  align-items: center;
  justify-content: center;
  position: relative;
  z-index: 1;
  padding: 40px;
}

.login-card {
  width: 440px;
  background: rgba(255, 255, 255, 0.97);
  backdrop-filter: blur(20px);
  border-radius: 16px;
  padding: 44px 40px 36px;
  box-shadow: 0 24px 80px rgba(0, 0, 0, 0.35);
}

.card-header {
  text-align: center;
  margin-bottom: 32px;
}

.card-header h1 {
  margin: 0 0 4px 0;
  font-size: 22px;
  font-weight: 600;
  color: #1D2129;
}

.card-header p {
  font-size: 13px;
  color: #86909C;
  margin: 0;
}

/* ===== 表单 ===== */
.login-form {
  margin-bottom: 0;
}

.login-input {
  height: 46px;
  border-radius: 8px;
}

.login-input :deep(.ant-input) {
  font-size: 15px;
}

.login-input :deep(.anticon) {
  color: #86909C;
  font-size: 16px;
}

.login-button {
  height: 46px;
  border-radius: 8px;
  font-size: 16px;
  font-weight: 500;
  margin-top: 4px;
  background: linear-gradient(135deg, #165DFF 0%, #0E42D2 100%);
  border: none;
  box-shadow: 0 4px 12px rgba(22, 93, 255, 0.35);
  transition: all 0.3s ease;
}

.login-button:hover {
  box-shadow: 0 6px 16px rgba(22, 93, 255, 0.45);
  transform: translateY(-1px);
}

.captcha-row {
  display: flex;
  gap: 12px;
  align-items: center;
}

.captcha-input {
  flex: 1;
  height: 46px;
  border-radius: 8px;
}

.captcha-input :deep(.ant-input) {
  font-size: 15px;
}

.captcha-input :deep(.anticon) {
  color: #86909C;
  font-size: 16px;
}

.captcha-image {
  height: 46px;
  border-radius: 8px;
  cursor: pointer;
  border: 1px solid #e5e6eb;
  flex-shrink: 0;
  transition: opacity 0.2s;
}

.captcha-image:hover {
  opacity: 0.75;
}

.captcha-placeholder {
  height: 46px;
  width: 150px;
  border-radius: 8px;
  border: 1px solid #e5e6eb;
  display: flex;
  align-items: center;
  justify-content: center;
  color: #86909C;
  font-size: 13px;
  cursor: pointer;
  flex-shrink: 0;
}

.error-message {
  margin-top: 16px;
}

/* ===== 页脚 ===== */
.login-footer {
  position: absolute;
  bottom: 20px;
  left: 50%;
  transform: translateX(-50%);
  font-size: 13px;
  color: rgba(255, 255, 255, 0.25);
  text-align: center;
  z-index: 1;
  white-space: nowrap;
}

/* ===== 响应式 ===== */
@media (max-width: 900px) {
  .login-page {
    flex-direction: column;
  }

  .left-side {
    flex: none;
    padding: 40px 24px 0;
  }

  .brand-logo {
    max-width: 300px;
  }

  .right-side {
    flex: 1;
    padding: 24px;
  }
}
</style>
