<template>
  <div class="role-permissions">
    <a-spin :spinning="loading">
      <a-row :gutter="24">
        <!-- Left: Role list -->
        <a-col :span="6">
          <a-card title="角色列表" :bordered="false" size="small">
            <a-menu
              v-model:selectedKeys="selectedRoleKeys"
              mode="inline"
              @click="handleRoleSelect"
            >
              <a-menu-item v-for="role in roles" :key="role.code">
                <span>{{ role.name }}</span>
                <a-tag v-if="role.code === 'admin'" color="red" style="margin-left: 8px">
                  全部权限
                </a-tag>
              </a-menu-item>
            </a-menu>
          </a-card>
        </a-col>

        <!-- Right: Permission checkboxes -->
        <a-col :span="18">
          <a-card :bordered="false" size="small">
            <template #title>
              <div class="perm-header">
                <span>{{ selectedRoleName }} — 权限配置</span>
                <a-button
                  v-if="selectedRole && selectedRole !== 'admin'"
                  type="primary"
                  size="small"
                  :loading="saving"
                  @click="handleSave"
                >
                  保存
                </a-button>
              </div>
            </template>

            <template v-if="selectedRole === 'admin'">
              <a-alert message="管理员角色拥有全部权限，不可修改" type="info" show-icon />
            </template>

            <template v-else-if="selectedRole">
              <div class="perm-modules">
                <div v-for="mod in permissionModules" :key="mod.name" class="perm-module">
                  <div class="module-title">{{ mod.label }}</div>
                  <a-row :gutter="[16, 8]">
                    <a-col v-for="perm in mod.items" :key="perm.code" :span="8">
                      <a-checkbox
                        :checked="checkedPermissions.includes(perm.code)"
                        @change="(e: any) => handlePermToggle(perm.code, e.target.checked)"
                      >
                        {{ perm.name }}
                      </a-checkbox>
                    </a-col>
                  </a-row>
                </div>
              </div>
            </template>

            <template v-else>
              <a-empty description="请选择角色" />
            </template>
          </a-card>
        </a-col>
      </a-row>
    </a-spin>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { rbacApi } from '@/api/auth'

interface Permission {
  id: number
  code: string
  name: string
  module: string
}

interface Role {
  code: string
  name: string
  permissions: string[]
}

const loading = ref(false)
const saving = ref(false)
const permissions = ref<Permission[]>([])
const roles = ref<Role[]>([])
const selectedRoleKeys = ref<string[]>([])
const checkedPermissions = ref<string[]>([])

const selectedRole = computed(() => selectedRoleKeys.value[0] || '')
const selectedRoleName = computed(() => {
  const role = roles.value.find((r) => r.code === selectedRole.value)
  return role?.name || '未选择'
})

const moduleLabels: Record<string, string> = {
  core: '核心功能',
  security: '安全模块',
  system: '系统管理',
}

const permissionModules = computed(() => {
  const modules: Record<string, { name: string; label: string; items: Permission[] }> = {}
  for (const perm of permissions.value) {
    if (!modules[perm.module]) {
      modules[perm.module] = {
        name: perm.module,
        label: moduleLabels[perm.module] || perm.module,
        items: [],
      }
    }
    modules[perm.module].items.push(perm)
  }
  return Object.values(modules)
})

const loadData = async () => {
  loading.value = true
  try {
    const [permsRes, rolesRes] = await Promise.all([
      rbacApi.listPermissions(),
      rbacApi.listRoles(),
    ])
    permissions.value = permsRes as Permission[]
    roles.value = rolesRes as Role[]
  } catch (error) {
    console.error('加载权限数据失败:', error)
  } finally {
    loading.value = false
  }
}

const handleRoleSelect = ({ key }: { key: string }) => {
  const role = roles.value.find((r) => r.code === key)
  checkedPermissions.value = role ? [...role.permissions] : []
}

const handlePermToggle = (code: string, checked: boolean) => {
  if (checked) {
    if (!checkedPermissions.value.includes(code)) {
      checkedPermissions.value = [...checkedPermissions.value, code]
    }
  } else {
    checkedPermissions.value = checkedPermissions.value.filter((c) => c !== code)
  }
}

const handleSave = async () => {
  if (!selectedRole.value || selectedRole.value === 'admin') return

  saving.value = true
  try {
    await rbacApi.updateRolePermissions(selectedRole.value, checkedPermissions.value)
    // Update local state
    const role = roles.value.find((r) => r.code === selectedRole.value)
    if (role) {
      role.permissions = [...checkedPermissions.value]
    }
    message.success('权限更新成功')
  } catch (error) {
    console.error('更新角色权限失败:', error)
  } finally {
    saving.value = false
  }
}

onMounted(() => {
  loadData()
})
</script>

<style scoped>
.role-permissions {
  width: 100%;
}

.perm-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.perm-modules {
  display: flex;
  flex-direction: column;
  gap: 20px;
}

.perm-module {
  padding: 12px 16px;
  background: var(--mxsec-fill-1);
  border-radius: 6px;
  border: 1px solid var(--mxsec-border);
}

.module-title {
  font-weight: 600;
  margin-bottom: 10px;
  color: #333;
}
</style>
