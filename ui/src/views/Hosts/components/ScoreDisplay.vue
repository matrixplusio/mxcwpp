<template>
  <div v-if="loading" class="score-loading">
    <a-spin size="small" />
  </div>
  <div v-else-if="score" class="score-display">
    <a-progress
      type="circle"
      :percent="score.baseline_score"
      :stroke-color="getScoreColor(score.baseline_score)"
      :size="60"
    />
    <div class="score-info">
      <div class="score-value">{{ score.baseline_score }}</div>
      <div class="score-detail">
        {{ score.pass_count }}/{{ score.total_rules }}
      </div>
    </div>
  </div>
  <span v-else>-</span>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { hostsApi } from '@/api/hosts'
import type { BaselineScore } from '@/api/types'

const props = defineProps<{
  hostId: string
}>()

const loading = ref(false)
const score = ref<BaselineScore | null>(null)

const loadScore = async () => {
  loading.value = true
  try {
    const data = await hostsApi.getScore(props.hostId)
    score.value = data
  } catch (error) {
    console.error('加载基线得分失败:', error)
  } finally {
    loading.value = false
  }
}

const getScoreColor = (score: number) => {
  if (score >= 80) return '#00B42A'
  if (score >= 60) return '#FF7D00'
  return '#F53F3F'
}

onMounted(() => {
  loadScore()
})
</script>

<style scoped>
.score-loading {
  display: flex;
  align-items: center;
  justify-content: center;
}

.score-display {
  display: flex;
  align-items: center;
  gap: 8px;
}

.score-info {
  display: flex;
  flex-direction: column;
}

.score-value {
  font-size: 18px;
  font-weight: bold;
  line-height: 1;
}

.score-detail {
  font-size: 12px;
  color: #999;
}
</style>
