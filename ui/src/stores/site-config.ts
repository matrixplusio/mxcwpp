import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { systemConfigApi, type SiteConfig } from '@/api/system-config'

export const useSiteConfigStore = defineStore('siteConfig', () => {
  const config = ref<SiteConfig>({
    site_name: '矩阵云安全平台',
    site_logo: '',
    site_domain: '',
    backend_url: '',
  })

  const siteName = computed(() => config.value.site_name || '矩阵云安全平台')
  const siteLogo = computed(() => config.value.site_logo)
  const siteDomain = computed(() => config.value.site_domain)

  // 加载配置
  const loadConfig = async () => {
    try {
      const data = await systemConfigApi.getSiteConfig()
      config.value = data
      // 更新网页标题
      updateDocumentTitle()
    } catch (error) {
      console.error('加载站点配置失败:', error)
      // 使用默认值
      config.value = {
        site_name: '矩阵云安全平台',
        site_logo: '',
        site_domain: '',
        backend_url: '',
      }
      updateDocumentTitle()
    }
  }

  // 更新配置
  const updateConfig = (newConfig: SiteConfig) => {
    config.value = newConfig
    updateDocumentTitle()
  }

  // 更新网页标题
  const updateDocumentTitle = () => {
    const title = siteName.value || '矩阵云安全平台'
    document.title = title
    // 更新 favicon
    const link = document.querySelector("link[rel~='icon']") as HTMLLinkElement
    if (link) {
      link.href = siteLogo.value || '/favicon.png'
    }
  }

  // 初始化（幂等：多次调用只触发一次 loadConfig + 一次 listener 绑定）
  // 旧实现每次 init 都 addEventListener，加上 router beforeEach 反复触发 init，
  // 导致 listener 累积 N 个，一次事件触发 N 次 loadConfig → 雪崩
  let initialized = false
  let initPromise: Promise<void> | null = null
  const init = async () => {
    if (initialized) return
    if (initPromise) return initPromise
    initPromise = (async () => {
      await loadConfig()
      window.addEventListener('site-config-updated', loadConfig)
      initialized = true
    })()
    return initPromise
  }

  return {
    config,
    siteName,
    siteLogo,
    siteDomain,
    loadConfig,
    updateConfig,
    init,
  }
})
