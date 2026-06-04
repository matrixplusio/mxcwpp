<template>
  <div class="stat-grid">
    <div
      v-for="(item, idx) in items"
      :key="idx"
      class="stat-grid__item"
      :class="`stat-grid__item--${item.tone || 'default'}`"
      :style="{ flexBasis: itemWidth }"
    >
      <div class="stat-grid__label">{{ item.label }}</div>
      <div class="stat-grid__value-line">
        <span class="stat-grid__prefix" v-if="item.prefix">{{ item.prefix }}</span>
        <span class="stat-grid__value">{{ formatValue(item) }}</span>
        <span v-if="item.suffix" class="stat-grid__suffix">{{ item.suffix }}</span>
      </div>
      <div v-if="item.trend !== undefined" class="stat-grid__trend">
        <span :class="['stat-grid__trend-arrow', `stat-grid__trend-arrow--${trendDir(item.trend)}`]">
          {{ trendArrow(item.trend) }}
        </span>
        <span :class="['stat-grid__trend-value', `stat-grid__trend-value--${trendDir(item.trend)}`]">
          {{ Math.abs(item.trend).toFixed(1) }}%
        </span>
        <span v-if="item.trendLabel" class="stat-grid__trend-label">{{ item.trendLabel }}</span>
      </div>
      <div v-if="item.hint" class="stat-grid__hint">{{ item.hint }}</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'

export interface StatItem {
  label: string
  value: number | string
  prefix?: string
  suffix?: string
  hint?: string
  /** 趋势百分比（正 = 上升，负 = 下降，0 = 持平） */
  trend?: number
  trendLabel?: string
  /** 配色调性 */
  tone?: 'default' | 'success' | 'warning' | 'danger' | 'info' | 'critical'
  /** 数字格式化（默认千分位） */
  precision?: number
}

interface Props {
  items: StatItem[]
  /** 每行最多几列 */
  columns?: number
}
const props = withDefaults(defineProps<Props>(), { columns: 4 })

const itemWidth = computed(() => `calc(${100 / props.columns}% - 12px)`)

const formatValue = (item: StatItem): string => {
  if (typeof item.value === 'string') return item.value
  const v = item.value
  if (item.precision !== undefined) return v.toFixed(item.precision)
  // 大数字千分位
  return v.toLocaleString('zh-CN')
}

const trendDir = (t: number): 'up' | 'down' | 'flat' => {
  if (t > 0.5) return 'up'
  if (t < -0.5) return 'down'
  return 'flat'
}
const trendArrow = (t: number): string => {
  const d = trendDir(t)
  return d === 'up' ? '↑' : d === 'down' ? '↓' : '→'
}
</script>

<style scoped lang="scss">
@import '@/styles/tokens.scss';

.stat-grid {
  display: flex;
  flex-wrap: wrap;
  gap: $space-md;

  &__item {
    padding: $space-md $space-lg;
    background: $bg-secondary;
    border-radius: $radius-md;
    border-left: 3px solid $brand-primary;
    flex-grow: 1;
    min-width: 160px;

    &--success { border-left-color: $brand-success; }
    &--warning { border-left-color: $brand-warning; }
    &--danger  { border-left-color: $brand-danger; }
    &--info    { border-left-color: $brand-info; }
    &--critical { border-left-color: $severity-critical; }
  }

  &__label {
    font-size: $text-xs;
    color: $text-tertiary;
    margin-bottom: $space-2xs;
    font-weight: $weight-medium;
  }

  &__value-line {
    display: flex;
    align-items: baseline;
    gap: $space-2xs;
  }

  &__value {
    font-size: $text-xl;
    font-weight: $weight-semibold;
    color: $text-primary;
    line-height: $leading-tight;
    font-feature-settings: 'tnum';
  }

  &__prefix, &__suffix {
    font-size: $text-sm;
    color: $text-secondary;
  }

  &__trend {
    display: flex;
    align-items: center;
    gap: 4px;
    margin-top: $space-xs;
    font-size: $text-xs;

    &-arrow {
      font-weight: $weight-bold;

      &--up   { color: $trend-up; }
      &--down { color: $trend-down; }
      &--flat { color: $trend-stable; }
    }

    &-value {
      font-weight: $weight-medium;

      &--up   { color: $trend-up; }
      &--down { color: $trend-down; }
      &--flat { color: $trend-stable; }
    }

    &-label {
      color: $text-tertiary;
      margin-left: $space-2xs;
    }
  }

  &__hint {
    margin-top: $space-2xs;
    font-size: $text-xs;
    color: $text-tertiary;
  }
}

@media print {
  .stat-grid__item {
    page-break-inside: avoid;
    background: #f9fafb !important;
  }
}
</style>
