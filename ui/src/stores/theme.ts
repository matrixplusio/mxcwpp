import { defineStore } from 'pinia'
import { ref, watch } from 'vue'

export const useThemeStore = defineStore('theme', () => {
  const isDark = ref(localStorage.getItem('mxsec-theme') !== 'light')

  const applyTheme = (dark: boolean) => {
    document.documentElement.classList.toggle('dark', dark)
    localStorage.setItem('mxsec-theme', dark ? 'dark' : 'light')
  }

  // 初始化
  applyTheme(isDark.value)

  watch(isDark, (val) => applyTheme(val))

  const toggle = () => {
    isDark.value = !isDark.value
  }

  return { isDark, toggle }
})
