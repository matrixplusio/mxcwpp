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
          <a-form-item v-if="needCaptcha" name="captcha_code">
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

        <!-- 强制修改密码弹窗 -->
        <a-modal
          v-model:open="showChangePassword"
          title="首次登录 — 请修改默认密码"
          :closable="false"
          :maskClosable="false"
          :footer="null"
        >
          <p style="color: var(--mxsec-text-3); margin-bottom: 16px;">为确保账户安全，请设置新密码（至少 8 位）</p>
          <a-form layout="vertical">
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
              <a-button
                type="primary"
                html-type="button"
                block
                :loading="changePwdLoading"
                @click="handleChangePassword"
              >
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
import { message } from 'ant-design-vue'
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
const needCaptcha = ref(false) // 风控：仅在需要时显示验证码

// 设备标识：浏览器本地生成并持久化，用于可信设备判定
const getDeviceId = (): string => {
  let id = localStorage.getItem('mxsec_device_id')
  if (!id) {
    id =
      typeof crypto !== 'undefined' && crypto.randomUUID
        ? crypto.randomUUID()
        : 'dev-' + Math.random().toString(36).slice(2) + Date.now().toString(36)
    localStorage.setItem('mxsec_device_id', id)
  }
  return id
}
const deviceId = getDeviceId()

const refreshCaptcha = async () => {
  try {
    const res = await authApi.getCaptcha()
    captchaId.value = res.captcha_id
    captchaImage.value = res.captcha_image
  } catch (e) {
    console.error('获取验证码失败:', e)
  }
}

// 风控预检：决定是否需要验证码；需要则加载验证码
const ensureCaptchaIfNeeded = async (): Promise<boolean> => {
  try {
    const res = await authApi.loginPrecheck({ username: form.username, device_id: deviceId })
    if (res.need_captcha && !needCaptcha.value) {
      needCaptcha.value = true
      await refreshCaptcha()
    }
    return needCaptcha.value
  } catch {
    return needCaptcha.value
  }
}

onMounted(() => {
  siteConfigStore.init()
})

const loading = ref(false)

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
  // 风控预检：未显示验证码时先判定。可信设备/近期无失败 → 免验证码；否则显示验证码让用户填写后再提交。
  if (!needCaptcha.value) {
    await ensureCaptchaIfNeeded()
    if (needCaptcha.value && !form.captcha_code) {
      message.warning('请输入验证码')
      return
    }
  }
  loading.value = true
  try {
    const response = await authStore.login({
      username: form.username,
      password: form.password,
      captcha_id: needCaptcha.value ? captchaId.value : undefined,
      captcha_code: needCaptcha.value ? form.captcha_code : undefined,
      device_id: deviceId,
    })
    if (response.need_change_password) {
      showChangePassword.value = true
      changePasswordForm.old_password = form.password
    } else {
      router.push('/')
    }
  } catch {
    // 具体错误已由全局拦截器统一弹窗提示，这里只做失败后的验证码刷新
    form.captcha_code = ''
    await ensureCaptchaIfNeeded()
    if (needCaptcha.value) await refreshCaptcha()
  } finally {
    loading.value = false
  }
}

const handleChangePassword = async () => {
  if (changePwdLoading.value) return
  if (changePasswordForm.new_password !== changePasswordForm.confirm_password) {
    message.error('两次输入的密码不一致')
    return
  }
  if (changePasswordForm.new_password.length < 8) {
    message.error('新密码长度至少 8 位')
    return
  }
  changePwdLoading.value = true
  try {
    await authApi.changePassword({
      old_password: changePasswordForm.old_password,
      new_password: changePasswordForm.new_password,
    })
    message.success('密码修改成功')
    showChangePassword.value = false
    router.push('/')
  } catch {
    // 错误由全局拦截器统一弹窗提示
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
  background: rgba(22, 27, 34, 0.92);
  backdrop-filter: blur(20px);
  border: 1px solid rgba(30, 58, 95, 0.4);
  border-radius: 16px;
  padding: 44px 40px 36px;
  box-shadow: 0 24px 80px rgba(0, 0, 0, 0.5);
}

.card-header {
  text-align: center;
  margin-bottom: 32px;
}

/* 登录页强制暗色背景，文字 hard-code 浅色以避免被亮色主题 var 覆盖 */
.card-header h1 {
  margin: 0 0 4px 0;
  font-size: 22px;
  font-weight: 600;
  color: rgba(255, 255, 255, 0.95);
}

.card-header p {
  font-size: 13px;
  color: rgba(255, 255, 255, 0.55);
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
  color: rgba(255, 255, 255, 0.55);
  font-size: 16px;
}

/* ===== 输入框暗色主题覆盖（适配登录页暗色背景） ===== */
.login-card :deep(.ant-input-affix-wrapper),
.login-card :deep(.ant-input) {
  background-color: rgba(255, 255, 255, 0.06);
  border-color: rgba(255, 255, 255, 0.12);
  color: rgba(255, 255, 255, 0.92);
}

.login-card :deep(.ant-input-affix-wrapper:hover),
.login-card :deep(.ant-input:hover) {
  border-color: rgba(59, 130, 246, 0.6);
  background-color: rgba(255, 255, 255, 0.08);
}

.login-card :deep(.ant-input-affix-wrapper-focused),
.login-card :deep(.ant-input-affix-wrapper:focus-within),
.login-card :deep(.ant-input:focus) {
  border-color: #3B82F6;
  background-color: rgba(255, 255, 255, 0.08);
  box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.18);
}

/* 内层 input（被 affix-wrapper 包裹时）需要透明背景，避免出现双层颜色 */
.login-card :deep(.ant-input-affix-wrapper > input.ant-input) {
  background-color: transparent;
  color: rgba(255, 255, 255, 0.92);
}

.login-card :deep(.ant-input::placeholder),
.login-card :deep(.ant-input-affix-wrapper input::placeholder) {
  color: rgba(255, 255, 255, 0.38);
}

/* 密码框右侧"显示/隐藏密码"图标 */
.login-card :deep(.ant-input-password-icon) {
  color: rgba(255, 255, 255, 0.55);
}

.login-card :deep(.ant-input-password-icon:hover) {
  color: rgba(255, 255, 255, 0.85);
}

/* 自动填充时浏览器默认亮色背景覆盖（Chrome/Safari/Edge）*/
.login-card :deep(input:-webkit-autofill),
.login-card :deep(input:-webkit-autofill:hover),
.login-card :deep(input:-webkit-autofill:focus) {
  -webkit-text-fill-color: rgba(255, 255, 255, 0.92);
  -webkit-box-shadow: 0 0 0 1000px rgba(22, 27, 34, 0.95) inset;
  caret-color: rgba(255, 255, 255, 0.92);
  transition: background-color 5000s ease-in-out 0s;
}

.login-button {
  height: 46px;
  border-radius: 8px;
  font-size: 16px;
  font-weight: 500;
  margin-top: 4px;
  background: linear-gradient(135deg, #3B82F6 0%, #2563EB 100%);
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
  color: var(--mxsec-text-3);
  font-size: 16px;
}

.captcha-image {
  height: 46px;
  border-radius: 8px;
  cursor: pointer;
  border: 1px solid var(--mxsec-border);
  flex-shrink: 0;
  transition: opacity 0.2s;
  /* 服务端 captcha 是深色文字在透明背景上；暗黑模式必须有亮底，否则不可见 */
  background: #ffffff;
}

.captcha-image:hover {
  opacity: 0.75;
}

.captcha-placeholder {
  height: 46px;
  width: 150px;
  border-radius: 8px;
  border: 1px solid var(--mxsec-border);
  display: flex;
  align-items: center;
  justify-content: center;
  color: var(--mxsec-text-3);
  font-size: 13px;
  cursor: pointer;
  flex-shrink: 0;
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
