<template>
  <a-layout class="layout" :style="{ minWidth: '1200px' }">
    <!-- ========== Logo 区域 (左上角, 与侧边栏等宽) ========== -->
    <div class="logo-area" :style="{ width: collapsed ? '48px' : '200px' }" @click="router.push('/dashboard')" style="cursor: pointer;">
      <img
        v-show="!collapsed"
        src="/logo-wide.png"
        alt="MxSec Platform"
        class="logo-wide"
      />
      <img
        v-show="collapsed"
        src="/logo.png"
        alt="MxSec Platform"
        class="logo-icon"
      />
    </div>

    <!-- ========== 顶部导航栏 (Logo 右侧) ========== -->
    <div class="header-bar" :style="{ left: collapsed ? '48px' : '200px' }">
      <div class="header-left">
        <span class="navbar-version">{{ appVersion }}</span>
      </div>
      <div class="header-right">
        <div class="theme-toggle" @click="themeStore.toggle" :title="themeStore.isDark ? '切换到浅色模式' : '切换到暗色模式'">
          <svg v-if="themeStore.isDark" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="5"/>
            <line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>
            <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
            <line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>
            <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
          </svg>
          <svg v-else width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
          </svg>
        </div>
        <a-dropdown>
          <a class="user-dropdown" @click.prevent>
            <a-avatar :size="28" class="user-avatar">
              {{ (authStore.user?.username || 'A').charAt(0).toUpperCase() }}
            </a-avatar>
            <span class="user-name">{{ authStore.user?.username || 'admin' }}</span>
            <DownOutlined class="user-arrow" />
          </a>
          <template #overlay>
            <a-menu>
              <a-menu-item @click="showChangePasswordModal = true">
                <KeyOutlined />
                <span style="margin-left: 8px">修改密码</span>
              </a-menu-item>
              <a-menu-divider />
              <a-menu-item @click="handleLogout">
                <LogoutOutlined />
                <span style="margin-left: 8px">退出登录</span>
              </a-menu-item>
            </a-menu>
          </template>
        </a-dropdown>
      </div>
    </div>

    <!-- ========== Body (侧边栏 + 内容) ========== -->
    <a-layout class="body-layout">
      <!-- 暗色侧边栏 -->
      <a-layout-sider
        v-model:collapsed="collapsed"
        :width="200"
        :collapsed-width="48"
        class="sider"
        :theme="themeStore.isDark ? 'dark' : 'light'"
        :trigger="null"
      >
        <div class="sider-wrapper">
          <!-- 菜单 (数据驱动) -->
          <div class="sider-menu">
            <a-menu
              v-model:selectedKeys="selectedKeys"
              v-model:openKeys="openKeys"
              mode="inline"
              :inline-collapsed="collapsed"
              @click="handleMenuClick"
              @openChange="handleOpenChange"
            >
              <template v-for="item in filteredMenu" :key="item.key">
                <!-- 无子菜单: 直接渲染 menu-item -->
                <a-menu-item
                  v-if="!item.children"
                  :key="item.key"
                  @click.native="(e: MouseEvent) => handleNavClick(e, item.key)"
                >
                  <template #icon>
                    <component :is="item.icon" v-if="item.icon" />
                  </template>
                  <span>{{ item.title }}</span>
                </a-menu-item>

                <!-- 有子菜单: 渲染 sub-menu -->
                <a-sub-menu v-else :key="item.key">
                  <template #icon>
                    <component :is="item.icon" v-if="item.icon" />
                  </template>
                  <template #title>{{ item.title }}</template>
                  <a-menu-item
                    v-for="child in item.children"
                    :key="child.key"
                    @click.native="(e: MouseEvent) => handleNavClick(e, child.key)"
                  >
                    {{ child.title }}
                  </a-menu-item>
                </a-sub-menu>
              </template>
            </a-menu>
          </div>

          <!-- 折叠按钮 -->
          <div class="sider-trigger" @click="collapsed = !collapsed">
            <MenuUnfoldOutlined v-if="collapsed" />
            <MenuFoldOutlined v-else />
          </div>
        </div>
      </a-layout-sider>

      <!-- 内容区 -->
      <a-layout-content class="content" :style="{ marginLeft: collapsed ? '48px' : '200px' }">
        <!-- P0-7: keep-alive 缓存路由组件, 切回时复用实例避免重拉数据 -->
        <router-view v-slot="{ Component, route }">
          <transition name="page-fade" mode="out-in">
            <keep-alive :max="10" :exclude="['PrintReport', 'Login']">
              <component :is="Component" :key="route.fullPath" />
            </keep-alive>
          </transition>
        </router-view>
      </a-layout-content>
    </a-layout>

    <!-- ========== 修改密码 Modal ========== -->
    <a-modal
      v-model:open="showChangePasswordModal"
      title="修改密码"
      :confirm-loading="changePasswordLoading"
      @ok="handleChangePassword"
      @cancel="resetChangePasswordForm"
    >
      <a-form :model="changePasswordForm" :rules="changePasswordRules" ref="changePasswordFormRef" layout="vertical">
        <a-form-item label="旧密码" name="oldPassword">
          <a-input-password v-model:value="changePasswordForm.oldPassword" placeholder="请输入旧密码" />
        </a-form-item>
        <a-form-item label="新密码" name="newPassword">
          <a-input-password v-model:value="changePasswordForm.newPassword" placeholder="请输入新密码（至少6位）" />
        </a-form-item>
        <a-form-item label="确认新密码" name="confirmPassword">
          <a-input-password v-model:value="changePasswordForm.confirmPassword" placeholder="请再次输入新密码" />
        </a-form-item>
      </a-form>
    </a-modal>
  </a-layout>
</template>

<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import {
  DownOutlined,
  LogoutOutlined,
  KeyOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
} from '@ant-design/icons-vue'
import { message } from 'ant-design-vue'
import type { FormInstance } from 'ant-design-vue'
import { useAuthStore } from '@/stores/auth'
import { useSiteConfigStore } from '@/stores/site-config'
import { useThemeStore } from '@/stores/theme'
import { authApi } from '@/api/auth'
import apiClient from '@/api/client'
import { menuConfig, filterMenuByRole, routeMap, resolveMenuKeys } from '@/config/menu'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()
const siteConfigStore = useSiteConfigStore()
const themeStore = useThemeStore()

// 应用版本号
const appVersion = ref('--')

const fetchAppVersion = async () => {
  try {
    const response = await apiClient.get<{ version: string; status: string }>('/health')
    appVersion.value = response.version ? `v${response.version}` : '--'
  } catch {
    appVersion.value = '--'
  }
}

onMounted(() => {
  siteConfigStore.init()
  fetchAppVersion()
})

// ========== 菜单状态 ==========
const collapsed = ref(false)
const selectedKeys = ref<string[]>([])
const openKeys = ref<string[]>([])

// 根据角色过滤菜单
const filteredMenu = computed(() => {
  const role = authStore.user?.role || 'user'
  return filterMenuByRole(menuConfig, role)
})

// 根据路由自动更新菜单选中态
watch(
  () => route.path,
  (path) => {
    const { selectedKey, openKey } = resolveMenuKeys(path)
    if (selectedKey) {
      selectedKeys.value = [selectedKey]
    }
    if (openKey && !collapsed.value) {
      openKeys.value = [openKey]
    } else if (!openKey) {
      openKeys.value = []
    }
  },
  { immediate: true }
)

// 手风琴模式: 同一时间只展开一个子菜单
const rootSubmenuKeys = computed(() =>
  filteredMenu.value.filter(item => item.children).map(item => item.key)
)

const handleOpenChange = (keys: string[]) => {
  const latestOpenKey = keys.find(key => !openKeys.value.includes(key))
  if (latestOpenKey && rootSubmenuKeys.value.includes(latestOpenKey)) {
    openKeys.value = [latestOpenKey]
  } else {
    openKeys.value = keys
  }
}

// Ctrl/Cmd+Click 新开标签页
let isNewTabClick = false

const handleNavClick = (e: MouseEvent, key: string) => {
  const path = routeMap[key]
  if (!path) return

  if (e.ctrlKey || e.metaKey) {
    isNewTabClick = true
    e.preventDefault()
    e.stopPropagation()
    window.open(router.resolve(path).href, '_blank')
    // 恢复当前选中
    const { selectedKey } = resolveMenuKeys(route.path)
    if (selectedKey) {
      selectedKeys.value = [selectedKey]
    }
  }
}

const handleMenuClick = ({ key }: { key: string }) => {
  if (isNewTabClick) {
    isNewTabClick = false
    return
  }
  const path = routeMap[key]
  if (path) {
    router.push(path)
  }
}

// ========== 用户操作 ==========
const handleLogout = async () => {
  await authStore.logout()
  message.success('已退出登录')
  router.push('/login')
}

// ========== 修改密码 ==========
const showChangePasswordModal = ref(false)
const changePasswordLoading = ref(false)
const changePasswordFormRef = ref<FormInstance>()
const changePasswordForm = ref({
  oldPassword: '',
  newPassword: '',
  confirmPassword: '',
})

const validateConfirmPassword = async (_rule: any, value: string) => {
  if (!value) {
    return Promise.reject('请确认新密码')
  }
  if (value !== changePasswordForm.value.newPassword) {
    return Promise.reject('两次输入的密码不一致')
  }
  return Promise.resolve()
}

const changePasswordRules = {
  oldPassword: [{ required: true, message: '请输入旧密码', trigger: 'blur' }],
  newPassword: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 6, message: '密码长度至少6位', trigger: 'blur' },
  ],
  confirmPassword: [{ required: true, validator: validateConfirmPassword, trigger: 'change' }],
}

const handleChangePassword = async () => {
  try {
    await changePasswordFormRef.value?.validate()
    changePasswordLoading.value = true
    await authApi.changePassword({
      old_password: changePasswordForm.value.oldPassword,
      new_password: changePasswordForm.value.newPassword,
    })
    message.success('密码修改成功')
    showChangePasswordModal.value = false
    resetChangePasswordForm()
  } catch (error: any) {
    if (error?.response?.data?.message) {
      message.error(error.response.data.message)
    } else if (error?.errorFields) {
      // 表单验证错误, 不处理
    } else {
      message.error('密码修改失败')
    }
  } finally {
    changePasswordLoading.value = false
  }
}

const resetChangePasswordForm = () => {
  changePasswordForm.value = { oldPassword: '', newPassword: '', confirmPassword: '' }
  changePasswordFormRef.value?.resetFields()
}
</script>

<style scoped>
.layout {
  min-height: 100vh;
}

/* ========== Logo 区域 (左上角) ========== */
.logo-area {
  position: fixed;
  top: 0;
  left: 0;
  height: 60px;
  background: var(--mxsec-navbar-bg);
  border-bottom: 1px solid var(--mxsec-border);
  border-right: 1px solid var(--mxsec-border);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1002;
  transition: width 0.2s;
  overflow: hidden;
}

.logo-wide {
  height: 44px;
  object-fit: contain;
  padding: 0 12px;
}

.logo-icon {
  width: 32px;
  height: 32px;
  object-fit: contain;
}

/* ========== 顶部导航栏 (Logo 右侧) ========== */
.header-bar {
  position: fixed;
  top: 0;
  right: 0;
  height: 60px;
  background: var(--mxsec-navbar-bg);
  border-bottom: 1px solid var(--mxsec-border);
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 20px;
  z-index: 1001;
  transition: left 0.2s;
}

.header-left {
  display: flex;
  align-items: center;
  gap: 12px;
}

.navbar-version {
  font-size: 12px;
  color: var(--mxsec-text-3);
  background: var(--mxsec-fill-1);
  padding: 2px 8px;
  border-radius: 10px;
  line-height: 1.5;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 4px;
}

.theme-toggle {
  width: 36px;
  height: 36px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 6px;
  cursor: pointer;
  color: var(--mxsec-text-3);
  transition: all 0.2s;
}

.theme-toggle:hover {
  background: var(--mxsec-fill-1);
  color: var(--mxsec-text-1);
}

.user-dropdown {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 8px;
  border-radius: 6px;
  color: var(--mxsec-text-2);
  transition: background 0.2s;
}

.user-dropdown:hover {
  background: var(--mxsec-fill-1);
  color: var(--mxsec-text-1);
}

.user-avatar {
  background: linear-gradient(135deg, #3B82F6, #2563EB);
  color: #fff;
  font-size: 13px;
  font-weight: 600;
}

.user-name {
  font-size: 14px;
}

.user-arrow {
  font-size: 10px;
  color: var(--mxsec-text-3);
}

/* ========== Body Layout ========== */
.body-layout {
  margin-top: 60px;
}

/* ========== Sider — 暗色主题 ========== */
.sider {
  position: fixed !important;
  left: 0;
  top: 60px;
  height: calc(100vh - 60px);
  background: var(--mxsec-sider-bg) !important;
  border-right: 1px solid var(--mxsec-border);
  z-index: 1000;
  overflow: hidden;
}

.sider :deep(.ant-layout-sider-children) {
  display: flex;
  flex-direction: column;
  height: 100%;
  overflow: hidden;
}

.sider-wrapper {
  display: flex;
  flex-direction: column;
  height: 100%;
}

/* 菜单滚动区域 */
.sider-menu {
  flex: 1;
  overflow-y: auto;
  overflow-x: hidden;
  padding: 8px 0;
}

.sider-menu::-webkit-scrollbar {
  width: 4px;
}

.sider-menu::-webkit-scrollbar-track {
  background: transparent;
}

.sider-menu::-webkit-scrollbar-thumb {
  background: var(--mxsec-scrollbar-thumb);
  border-radius: 2px;
}

/* 菜单样式覆盖 — 暗色风格 */
.sider :deep(.ant-menu) {
  border-right: none;
  background: transparent;
}

.sider :deep(.ant-menu-item) {
  margin: 2px 8px;
  border-radius: 6px;
  height: 40px;
  line-height: 40px;
  color: var(--mxsec-text-2);
}

.sider :deep(.ant-menu-submenu-title) {
  margin: 2px 8px;
  border-radius: 6px;
  height: 40px;
  line-height: 40px;
  color: var(--mxsec-text-2);
}

.sider :deep(.ant-menu-submenu .ant-menu-item) {
  height: 36px;
  line-height: 36px;
  margin: 1px 8px;
  padding-left: 44px !important;
}

/* 选中态 — 蓝色竖条 + 蓝色半透明背景 */
.sider :deep(.ant-menu-item-selected) {
  background: rgba(59, 130, 246, 0.15) !important;
  color: #3B82F6 !important;
  font-weight: 500;
  position: relative;
}

.sider :deep(.ant-menu-item-selected::before) {
  content: '';
  position: absolute;
  left: 0;
  top: 50%;
  transform: translateY(-50%);
  width: 3px;
  height: 20px;
  background: #3B82F6;
  border-radius: 0 2px 2px 0;
}

.sider :deep(.ant-menu-item-selected::after) {
  display: none;
}

/* 悬停态 */
.sider :deep(.ant-menu-item:not(.ant-menu-item-selected):hover),
.sider :deep(.ant-menu-submenu-title:hover) {
  background: rgba(59, 130, 246, 0.08) !important;
  color: var(--mxsec-text-1) !important;
}

/* 子菜单展开区域 */
.sider :deep(.ant-menu-sub.ant-menu-inline) {
  background: transparent !important;
}

/* 菜单图标 */
.sider :deep(.ant-menu-item .anticon),
.sider :deep(.ant-menu-submenu-title .anticon) {
  font-size: 16px;
}

/* ========== 折叠按钮 ========== */
.sider-trigger {
  height: 40px;
  display: flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  border-top: 1px solid var(--mxsec-border);
  color: var(--mxsec-text-3);
  font-size: 14px;
  transition: all 0.2s;
  flex-shrink: 0;
}

.sider-trigger:hover {
  background: rgba(59, 130, 246, 0.08);
  color: var(--mxsec-text-1);
}

/* ========== Content ========== */
.content {
  padding: 20px;
  background: var(--mxsec-body-bg);
  min-height: calc(100vh - 60px);
  transition: margin-left 0.2s;
}
</style>
