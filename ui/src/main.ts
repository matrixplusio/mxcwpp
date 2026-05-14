import { createApp } from 'vue'
import { createPinia } from 'pinia'
import Antd from 'ant-design-vue'
import 'ant-design-vue/dist/reset.css'
import ECharts from 'vue-echarts'
import { use } from 'echarts/core'
import { CanvasRenderer } from 'echarts/renderers'
import {
  BarChart,
  LineChart,
  PieChart,
  RadarChart,
} from 'echarts/charts'
import {
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
  RadarComponent,
} from 'echarts/components'

// 注册 ECharts 组件（只注册需要的组件）
use([
  CanvasRenderer,
  BarChart,
  LineChart,
  PieChart,
  RadarChart,
  TitleComponent,
  TooltipComponent,
  LegendComponent,
  GridComponent,
  RadarComponent,
])

import './styles/global.less'
import App from './App.vue'
import router from './router'
import { useSiteConfigStore } from './stores/site-config'

const app = createApp(App)

app.use(createPinia())
app.use(router)
app.use(Antd)
app.component('v-chart', ECharts)

// 初始化站点配置
const siteConfigStore = useSiteConfigStore()
siteConfigStore.init()

app.mount('#app')
