<template>
  <div class="system-collection-page">
    <div class="page-header">
      <h2>平台授权</h2>
    </div>

    <div class="license-card">
      <!-- 授权状态 -->
      <div class="license-status">
        <img src="/logo-wide.png" alt="MxSec Platform" class="status-logo" />
        <h3 class="status-title">社区版 · Community Edition</h3>
        <p class="status-desc">{{ appVersion }} · AGPL-3.0 · 开源免费</p>
      </div>

      <!-- 信息区域 -->
      <div class="license-details">
        <div class="detail-section">
          <div class="section-title">
            <InfoCircleOutlined />
            <span>版本信息</span>
          </div>
          <div class="info-table">
            <div class="info-row">
              <span class="info-label">产品名称</span>
              <span class="info-value">矩阵云安全平台（MxSec Platform）</span>
            </div>
            <div class="info-row">
              <span class="info-label">当前版本</span>
              <span class="info-value">{{ appVersion }} Community Edition</span>
            </div>
            <div class="info-row">
              <span class="info-label">开源协议</span>
              <span class="info-value">AGPL-3.0</span>
            </div>
            <div class="info-row">
              <span class="info-label">系统架构</span>
              <span class="info-value">Agent + Plugin + Server（分布式）</span>
            </div>
          </div>
        </div>

        <a-divider />

        <div class="detail-section">
          <div class="section-title">
            <SafetyCertificateOutlined />
            <span>授权说明</span>
          </div>
          <div class="feature-list">
            <div class="feature-item">
              <CheckOutlined class="feature-check" />
              <span>源码完全开放，免费使用、修改和分发</span>
            </div>
            <div class="feature-item">
              <CheckOutlined class="feature-check" />
              <span>不限制 Agent 接入数量、用户数量和数据存储量</span>
            </div>
            <div class="feature-item">
              <CheckOutlined class="feature-check" />
              <span>所有安全能力全部开放：安全基线、告警管理、FIM、容器安全、病毒查杀、漏洞管理、威胁情报、自动响应等</span>
            </div>
            <div class="feature-item">
              <CheckOutlined class="feature-check" />
              <span>修改和衍生作品必须以相同 AGPL-3.0 协议开源，并保留版权信息</span>
            </div>
            <div class="feature-item">
              <CheckOutlined class="feature-check" />
              <span>作为网络服务提供时，必须向用户公开完整源码</span>
            </div>
            <div class="feature-item">
              <CloseOutlined class="feature-close" />
              <span>商业闭源使用（售卖、托管服务、集成至商业产品等）需联系获取商业授权</span>
            </div>
          </div>
        </div>

        <a-divider />

        <div class="detail-section">
          <div class="section-title">
            <LinkOutlined />
            <span>更多信息</span>
          </div>
          <div class="link-list">
            <div class="link-item">
              <GithubOutlined />
              <a href="https://github.com/imkerbos/mxsec-platform" target="_blank">
                github.com/imkerbos/mxsec-platform
              </a>
            </div>
            <div class="link-item">
              <MailOutlined />
              <span>商业授权联系：0xkerbos@gmail.com</span>
            </div>
            <div class="link-item">
              <UserOutlined />
              <span>Maintained by Kerbos</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import {
  CheckOutlined,
  CloseOutlined,
  MailOutlined,
  InfoCircleOutlined,
  SafetyCertificateOutlined,
  LinkOutlined,
  GithubOutlined,
  UserOutlined,
} from '@ant-design/icons-vue'
import apiClient from '@/api/client'

const appVersion = ref('--')

onMounted(async () => {
  try {
    const response = await apiClient.get<{ version: string; status: string }>('/health')
    appVersion.value = response.version ? `v${response.version}` : '--'
  } catch {
    appVersion.value = '--'
  }
})
</script>

<style scoped>
.system-collection-page {
  width: 100%;
}

.page-header {
  margin-bottom: 16px;
}

.page-header h2 {
  margin: 0;
  font-size: 20px;
  font-weight: 600;
}

.license-card {
  max-width: 860px;
  margin: 0 auto;
}

/* 授权状态 */
.license-status {
  text-align: center;
  padding: 24px 24px 20px;
  background: linear-gradient(135deg, #f6ffed 0%, #E8F3FF 100%);
  border-radius: 12px;
  margin-bottom: 16px;
}

.status-logo {
  height: 56px;
  object-fit: contain;
  margin-bottom: 10px;
}

.status-title {
  font-size: 20px;
  font-weight: 600;
  color: #262626;
  margin: 0 0 4px 0;
}

.status-desc {
  font-size: 14px;
  color: rgba(0, 0, 0, 0.45);
  margin: 0;
}

/* 详情区域 */
.license-details {
  background: #fff;
  border-radius: 12px;
  padding: 20px 24px;
  border: 1px solid #f0f0f0;
}

.license-details :deep(.ant-divider) {
  margin: 16px 0;
}

.detail-section {
  padding: 0;
}

.section-title {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 15px;
  font-weight: 600;
  color: #262626;
  margin-bottom: 12px;
}

.section-title :deep(.anticon) {
  color: #165DFF;
  font-size: 16px;
}

/* 版本信息表格 */
.info-table {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding-left: 24px;
}

.info-row {
  display: flex;
  align-items: center;
  font-size: 13px;
  line-height: 1.6;
}

.info-label {
  width: 80px;
  flex-shrink: 0;
  color: #86909C;
}

.info-value {
  color: #1D2129;
}

/* 功能列表 */
.feature-list {
  display: flex;
  flex-direction: column;
  gap: 9px;
  padding-left: 24px;
}

.feature-item {
  display: flex;
  align-items: flex-start;
  gap: 8px;
  color: #595959;
  font-size: 13px;
  line-height: 1.6;
}

.feature-check {
  color: #00B42A;
  font-size: 13px;
  margin-top: 3px;
  flex-shrink: 0;
}

.feature-close {
  color: #F53F3F;
  font-size: 13px;
  margin-top: 3px;
  flex-shrink: 0;
}

/* 链接列表 */
.link-list {
  display: flex;
  flex-direction: column;
  gap: 8px;
  padding-left: 24px;
}

.link-item {
  display: flex;
  align-items: center;
  gap: 8px;
  color: #595959;
  font-size: 13px;
}

.link-item :deep(.anticon) {
  font-size: 14px;
  color: #86909C;
}

.link-item a {
  color: #165DFF;
  text-decoration: none;
}

.link-item a:hover {
  text-decoration: underline;
}
</style>
