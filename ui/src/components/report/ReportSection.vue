<template>
  <section class="report-section" :class="{ 'report-section--collapsed': collapsed }">
    <header v-if="title || $slots.title || $slots.extra" class="report-section__header">
      <div class="report-section__title">
        <slot name="title">
          <span class="report-section__title-text">{{ title }}</span>
          <a-tag v-if="badge" :color="badgeColor" class="report-section__badge">
            {{ badge }}
          </a-tag>
          <span v-if="subtitle" class="report-section__subtitle">{{ subtitle }}</span>
        </slot>
      </div>
      <div class="report-section__extra">
        <slot name="extra" />
        <a-button
          v-if="collapsible"
          type="text"
          size="small"
          @click="collapsed = !collapsed"
        >
          {{ collapsed ? '展开' : '收起' }}
        </a-button>
      </div>
    </header>
    <div v-show="!collapsed" class="report-section__body">
      <slot />
    </div>
  </section>
</template>

<script setup lang="ts">
import { ref } from 'vue'

interface Props {
  title?: string
  subtitle?: string
  badge?: string
  badgeColor?: string
  collapsible?: boolean
  defaultCollapsed?: boolean
}
const props = withDefaults(defineProps<Props>(), {
  title: '',
  subtitle: '',
  badge: '',
  badgeColor: 'blue',
  collapsible: false,
  defaultCollapsed: false,
})

const collapsed = ref(props.defaultCollapsed)
</script>

<style scoped lang="scss">
@import '@/styles/tokens.scss';

.report-section {
  background: $bg-primary;
  border: 1px solid $border-default;
  border-radius: $radius-lg;
  margin-bottom: $space-md;
  overflow: hidden;
  transition: box-shadow 0.2s ease;

  &:hover {
    box-shadow: $shadow-md;
  }

  &__header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: $space-md $space-lg;
    border-bottom: 1px solid $border-default;
    background: $bg-secondary;
  }

  &__title {
    display: flex;
    align-items: center;
    gap: $space-xs;
    font-size: $text-md;
    font-weight: $weight-semibold;
    color: $text-primary;

    &-text {
      font-size: $text-md;
      font-weight: $weight-semibold;
    }
  }

  &__subtitle {
    font-size: $text-xs;
    color: $text-tertiary;
    font-weight: $weight-regular;
    margin-left: $space-xs;
  }

  &__badge {
    margin-left: $space-xs;
  }

  &__extra {
    display: flex;
    align-items: center;
    gap: $space-xs;
  }

  &__body {
    padding: $space-lg;
  }

  &--collapsed &__body {
    display: none;
  }
}

// 打印优化
@media print {
  .report-section {
    page-break-inside: avoid;
    box-shadow: none !important;
    border: 1px solid #d1d5db;

    &:hover {
      box-shadow: none !important;
    }

    &__header {
      background: #f9fafb;
    }
  }
}
</style>
