<template>
  <a-modal
    :visible="visible"
    :title="user ? '编辑用户' : '新建用户'"
    :confirm-loading="loading"
    @ok="handleSubmit"
    @cancel="handleCancel"
    width="600px"
  >
    <a-form
      ref="formRef"
      :model="form"
      :rules="rules"
      :label-col="{ span: 6 }"
      :wrapper-col="{ span: 18 }"
    >
      <a-form-item label="用户名" name="username">
        <a-input
          v-model:value="form.username"
          placeholder="请输入用户名（3-64个字符）"
          :disabled="!!user"
        />
      </a-form-item>
      <a-form-item label="密码" name="password" :required="!user">
        <a-input-password
          v-model:value="form.password"
          :placeholder="user ? '留空则不修改密码' : '请输入密码（至少6个字符）'"
        />
      </a-form-item>
      <a-form-item label="邮箱" name="email">
        <a-input v-model:value="form.email" placeholder="请输入邮箱" />
      </a-form-item>
      <a-form-item label="角色" name="role">
        <a-select v-model:value="form.role" placeholder="请选择角色">
          <a-select-option value="admin">管理员</a-select-option>
          <a-select-option value="user">普通用户</a-select-option>
        </a-select>
      </a-form-item>
      <a-form-item label="状态" name="status">
        <a-select v-model:value="form.status" placeholder="请选择状态">
          <a-select-option value="active">启用</a-select-option>
          <a-select-option value="inactive">禁用</a-select-option>
        </a-select>
      </a-form-item>
    </a-form>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, reactive, watch } from 'vue'
import { message } from 'ant-design-vue'
import type { FormInstance } from 'ant-design-vue/es/form'
import { usersApi, type User, type CreateUserRequest, type UpdateUserRequest } from '@/api/users'

interface Props {
  visible: boolean
  user?: User | null
}

const props = defineProps<Props>()

const emit = defineEmits<{
  'update:visible': [value: boolean]
  success: []
}>()

const formRef = ref<FormInstance>()
const loading = ref(false)

const form = reactive<{
  username: string
  password: string
  email: string
  role: 'admin' | 'user'
  status: 'active' | 'inactive'
}>({
  username: '',
  password: '',
  email: '',
  role: 'user',
  status: 'active',
})

const rules = {
  username: [
    { required: true, message: '请输入用户名', trigger: 'blur' },
    { min: 3, max: 64, message: '用户名长度为3-64个字符', trigger: 'blur' },
  ],
  password: [
    {
      validator: (_rule: any, value: string) => {
        if (!props.user && !value) {
          return Promise.reject('请输入密码')
        }
        if (value && value.length < 6) {
          return Promise.reject('密码长度至少6个字符')
        }
        return Promise.resolve()
      },
      trigger: 'blur',
    },
  ],
  email: [
    { type: 'email', message: '请输入有效的邮箱地址', trigger: 'blur' },
  ],
  role: [{ required: true, message: '请选择角色', trigger: 'change' }],
  status: [{ required: true, message: '请选择状态', trigger: 'change' }],
}

watch(
  () => props.visible,
  (visible) => {
    if (visible) {
      if (props.user) {
        // 编辑模式
        form.username = props.user.username
        form.password = ''
        form.email = props.user.email || ''
        form.role = props.user.role
        form.status = props.user.status
      } else {
        // 新建模式
        form.username = ''
        form.password = ''
        form.email = ''
        form.role = 'user'
        form.status = 'active'
      }
      formRef.value?.resetFields()
    }
  }
)

const handleSubmit = async () => {
  try {
    await formRef.value?.validate()
    loading.value = true

    if (props.user) {
      // 更新用户
      const updateData: UpdateUserRequest = {
        email: form.email,
        role: form.role,
        status: form.status,
      }
      if (form.password) {
        updateData.password = form.password
      }
      await usersApi.update(props.user.id, updateData)
      message.success('更新成功')
    } else {
      // 创建用户
      const createData: CreateUserRequest = {
        username: form.username,
        password: form.password,
        email: form.email,
        role: form.role,
        status: form.status,
      }
      await usersApi.create(createData)
      message.success('创建成功')
    }

    emit('success')
  } catch (error: any) {
    if (error?.errorFields) {
      // 表单验证错误
      return
    }
    message.error('操作失败: ' + (error.message || '未知错误'))
  } finally {
    loading.value = false
  }
}

const handleCancel = () => {
  emit('update:visible', false)
}
</script>
