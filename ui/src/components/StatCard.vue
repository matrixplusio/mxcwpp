<template>
  <div
    class="stat-card-ds"
    :class="{ clickable }"
    :style="{ borderTopColor: color }"
    @click="clickable && $emit('click')"
  >
    <!-- 右上角微光晕 -->
    <div class="stat-card-glow" :style="{ background: `radial-gradient(circle at top right, ${color}12, transparent)` }" />

    <div class="stat-card-title">{{ title }}</div>
    <div class="stat-card-value">
      <span ref="valueRef">{{ displayValue }}</span>
      <span v-if="suffix" class="stat-card-suffix">{{ suffix }}</span>
    </div>

    <!-- 趋势指示 -->
    <div v-if="trend" class="stat-card-trend" :class="trend.direction === 'up' ? 'trend-up' : 'trend-down'">
      <span v-if="trend.direction === 'up'">&#9650;</span>
      <span v-else>&#9660;</span>
      {{ trend.value }}
    </div>

    <!-- 进度条 -->
    <div v-if="progress !== undefined" class="stat-card-progress">
      <div class="progress-bar" :style="{ width: `${Math.min(progress, 100)}%`, background: color }" />
    </div>

    <!-- 底部标签 -->
    <div v-if="tags && tags.length > 0" class="stat-card-tags">
      <span
        v-for="(tag, i) in tags"
        :key="i"
        class="stat-tag"
        :style="{ color: tag.color, background: tag.color + '18' }"
      >
        {{ tag.label }}
      </span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch, onMounted } from 'vue'

interface TagItem {
  label: string
  color: string
}

interface TrendItem {
  value: string
  direction: 'up' | 'down'
}

const props = withDefaults(defineProps<{
  title: string
  value: number | string
  color?: string
  suffix?: string
  tags?: TagItem[]
  progress?: number
  trend?: TrendItem
  clickable?: boolean
  animate?: boolean
}>(), {
  color: '#3B82F6',
  clickable: false,
  animate: true,
})

defineEmits<{
  click: []
}>()

const displayValue = ref<number | string>(props.animate && typeof props.value === 'number' ? 0 : props.value)

// countUp 动画
const animateValue = (target: number) => {
  if (!props.animate || typeof target !== 'number') {
    displayValue.value = target
    return
  }

  const duration = 800
  const startTime = performance.now()
  const startVal = 0

  const step = (currentTime: number) => {
    const elapsed = currentTime - startTime
    const progress = Math.min(elapsed / duration, 1)
    // ease-out cubic
    const eased = 1 - Math.pow(1 - progress, 3)
    const current = Math.round(startVal + (target - startVal) * eased)
    displayValue.value = current.toLocaleString()

    if (progress < 1) {
      requestAnimationFrame(step)
    } else {
      displayValue.value = target.toLocaleString()
    }
  }

  requestAnimationFrame(step)
}

onMounted(() => {
  if (typeof props.value === 'number') {
    animateValue(props.value)
  }
})

watch(() => props.value, (newVal) => {
  if (typeof newVal === 'number') {
    animateValue(newVal)
  } else {
    displayValue.value = newVal
  }
})
</script>

<style scoped>
.stat-card-ds {
  background: var(--mxsec-card-bg);
  border-radius: 10px;
  padding: 18px;
  border: 1px solid var(--mxsec-border);
  border-top: 2px solid;
  position: relative;
  overflow: hidden;
  transition: transform 0.2s ease, border-color 0.2s ease;
}

.stat-card-ds.clickable {
  cursor: pointer;
}

.stat-card-ds:hover {
  transform: translateY(-2px);
  border-color: rgba(59, 130, 246, 0.4);
}

.stat-card-glow {
  position: absolute;
  top: 0;
  right: 0;
  width: 60px;
  height: 60px;
  pointer-events: none;
}

.stat-card-title {
  font-size: 11px;
  color: var(--mxsec-text-3);
  letter-spacing: 0.5px;
  margin-bottom: 8px;
  text-transform: uppercase;
}

.stat-card-value {
  font-size: 28px;
  font-weight: 700;
  color: var(--mxsec-text-1);
  line-height: 1;
}

.stat-card-suffix {
  font-size: 16px;
  font-weight: 500;
  color: var(--mxsec-text-3);
  margin-left: 2px;
}

.stat-card-trend {
  font-size: 12px;
  margin-top: 6px;
}

.trend-up {
  color: #EF4444;
}

.trend-down {
  color: #22C55E;
}

.stat-card-progress {
  height: 4px;
  background: rgba(30, 58, 95, 0.3);
  border-radius: 4px;
  margin-top: 10px;
  overflow: hidden;
}

.progress-bar {
  height: 100%;
  border-radius: 4px;
  transition: width 0.8s ease-out;
}

.stat-card-tags {
  display: flex;
  gap: 6px;
  margin-top: 8px;
  flex-wrap: wrap;
}

.stat-tag {
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 10px;
  font-weight: 500;
}
</style>
