<template>
  <footer class="report-footer">
    <div class="report-footer__divider"></div>
    <div class="report-footer__content">
      <div class="report-footer__left">
        <span class="report-footer__brand">{{ brandName }}</span>
        <span class="report-footer__sep">·</span>
        <span class="report-footer__id">{{ reportId }}</span>
      </div>
      <div class="report-footer__center">
        <span class="report-footer__disclaimer">{{ disclaimer }}</span>
      </div>
      <div class="report-footer__right">
        <span v-if="pageNo">第 {{ pageNo }} 页 / 共 {{ pageTotal }} 页</span>
        <span v-else>{{ generatedAt }}</span>
      </div>
    </div>
    <!-- 打印水印 -->
    <div v-if="watermark" class="report-footer__watermark">{{ watermark }}</div>
  </footer>
</template>

<script setup lang="ts">
interface Props {
  brandName?: string
  reportId?: string
  disclaimer?: string
  generatedAt?: string
  pageNo?: number
  pageTotal?: number
  watermark?: string
}
withDefaults(defineProps<Props>(), {
  brandName: '矩阵云安全平台',
  reportId: '',
  disclaimer: '本报告由系统自动生成，数据基于检测周期内的真实采集结果。',
  generatedAt: '',
  pageNo: 0,
  pageTotal: 0,
  watermark: '',
})
</script>

<style scoped lang="scss">
@import '@/styles/tokens.scss';

.report-footer {
  position: relative;
  margin-top: $space-xl;

  &__divider {
    height: 2px;
    background: linear-gradient(90deg, transparent 0%, $border-strong 50%, transparent 100%);
    margin-bottom: $space-sm;
  }

  &__content {
    display: grid;
    grid-template-columns: minmax(160px, auto) 1fr minmax(160px, auto);
    gap: $space-md;
    align-items: center;
    font-size: $text-xs;
    color: $text-tertiary;
  }

  &__left, &__right {
    display: flex;
    align-items: center;
    gap: $space-2xs;
  }

  &__brand {
    color: $text-secondary;
    font-weight: $weight-medium;
  }

  &__id {
    font-family: $font-mono;
  }

  &__center {
    text-align: center;
  }

  &__right {
    justify-content: flex-end;
  }

  &__watermark {
    position: absolute;
    bottom: 50%;
    left: 50%;
    transform: translate(-50%, 50%) rotate(-30deg);
    font-size: 120px;
    font-weight: $weight-bold;
    color: rgba(0, 0, 0, 0.04);
    pointer-events: none;
    white-space: nowrap;
    z-index: -1;
  }
}

@media print {
  .report-footer {
    page-break-inside: avoid;

    &__watermark {
      display: block !important;
      color: rgba(0, 0, 0, 0.06);
    }
  }
}
</style>
