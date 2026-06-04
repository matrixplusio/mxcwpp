<template>
  <header class="report-header">
    <div class="report-header__brand">
      <div class="report-header__logo">
        <slot name="logo">
          <svg viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
            <rect width="48" height="48" rx="10" fill="url(#brandG)" />
            <path d="M14 17L24 11L34 17V31L24 37L14 31V17Z" stroke="#fff" stroke-width="2.5" stroke-linejoin="round" />
            <path d="M24 11V37" stroke="#fff" stroke-width="1.5" stroke-dasharray="2 2" />
            <defs>
              <linearGradient id="brandG" x1="0" y1="0" x2="48" y2="48" gradientUnits="userSpaceOnUse">
                <stop stop-color="#2563eb" />
                <stop offset="1" stop-color="#722ed1" />
              </linearGradient>
            </defs>
          </svg>
        </slot>
      </div>
      <div class="report-header__brand-text">
        <div class="report-header__brand-name">{{ brandName }}</div>
        <div class="report-header__brand-tagline">{{ brandTagline }}</div>
      </div>
    </div>

    <div class="report-header__center">
      <h1 class="report-header__title">{{ title }}</h1>
      <div v-if="subtitle" class="report-header__subtitle">{{ subtitle }}</div>
      <div v-if="period" class="report-header__period">
        <span class="report-header__period-label">报告周期</span>
        <span class="report-header__period-value">{{ period }}</span>
      </div>
    </div>

    <div class="report-header__meta">
      <div v-if="reportId" class="report-header__meta-row">
        <span class="report-header__meta-label">报告编号</span>
        <span class="report-header__meta-value">{{ reportId }}</span>
      </div>
      <div v-if="generatedAt" class="report-header__meta-row">
        <span class="report-header__meta-label">生成时间</span>
        <span class="report-header__meta-value">{{ generatedAt }}</span>
      </div>
      <div v-if="classification" class="report-header__classification">
        {{ classification }}
      </div>
    </div>
  </header>
</template>

<script setup lang="ts">
interface Props {
  brandName?: string
  brandTagline?: string
  title: string
  subtitle?: string
  period?: string
  reportId?: string
  generatedAt?: string
  classification?: string
}
withDefaults(defineProps<Props>(), {
  brandName: '矩阵云安全平台',
  brandTagline: 'MxSec Security Platform',
  subtitle: '',
  period: '',
  reportId: '',
  generatedAt: '',
  classification: '机密 · 仅限内部使用',
})
</script>

<style scoped lang="scss">
@import '@/styles/tokens.scss';

.report-header {
  display: grid;
  grid-template-columns: minmax(180px, auto) 1fr minmax(180px, auto);
  gap: $space-lg;
  align-items: center;
  padding: $space-lg $space-xl;
  background: linear-gradient(135deg, #f8fafc 0%, #f1f5f9 100%);
  border-radius: $radius-lg;
  border: 1px solid $border-default;
  margin-bottom: $space-lg;

  &__brand {
    display: flex;
    align-items: center;
    gap: $space-sm;
  }

  &__logo {
    width: 48px;
    height: 48px;
    flex-shrink: 0;

    svg { width: 100%; height: 100%; }
  }

  &__brand-text {
    display: flex;
    flex-direction: column;
  }

  &__brand-name {
    font-size: $text-md;
    font-weight: $weight-semibold;
    color: $text-primary;
    line-height: $leading-tight;
  }

  &__brand-tagline {
    font-size: $text-xs;
    color: $text-tertiary;
    font-family: $font-mono;
  }

  &__center {
    text-align: center;
  }

  &__title {
    font-size: $text-xl;
    font-weight: $weight-semibold;
    color: $text-primary;
    margin: 0 0 $space-2xs 0;
    line-height: $leading-tight;
  }

  &__subtitle {
    font-size: $text-sm;
    color: $text-secondary;
    margin-bottom: $space-2xs;
  }

  &__period {
    display: inline-flex;
    align-items: center;
    gap: $space-2xs;
    padding: $space-2xs $space-sm;
    background: $bg-primary;
    border: 1px solid $border-default;
    border-radius: $radius-pill;
    font-size: $text-xs;

    &-label {
      color: $text-tertiary;
    }

    &-value {
      color: $text-primary;
      font-weight: $weight-medium;
    }
  }

  &__meta {
    text-align: right;
    display: flex;
    flex-direction: column;
    gap: $space-2xs;
  }

  &__meta-row {
    font-size: $text-xs;
  }

  &__meta-label {
    color: $text-tertiary;
    margin-right: $space-2xs;
  }

  &__meta-value {
    color: $text-primary;
    font-family: $font-mono;
    font-weight: $weight-medium;
  }

  &__classification {
    margin-top: $space-2xs;
    padding: 2px 8px;
    background: rgba(220, 38, 38, 0.08);
    color: $brand-danger;
    border: 1px solid rgba(220, 38, 38, 0.3);
    border-radius: $radius-sm;
    font-size: $text-xs;
    font-weight: $weight-medium;
    display: inline-block;
    align-self: flex-end;
  }
}

@media print {
  .report-header {
    background: #f8fafc !important;
    page-break-inside: avoid;
    page-break-after: avoid;
  }
}
</style>
