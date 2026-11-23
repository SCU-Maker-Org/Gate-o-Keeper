<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { describeApiError } from '../lib/api'
import { consumePkceSession } from '../lib/pkce'
import { useSession } from '../stores/session'

const route = useRoute()
const router = useRouter()
const { completeCallback } = useSession()

const errorMessage = ref<string | null>(null)
const statusText = ref('正在向后端核验 Authentik 授权码…')

onMounted(async () => {
  const errParam = route.query.error
  if (typeof errParam === 'string' && errParam) {
    const desc =
      typeof route.query.error_description === 'string' ? route.query.error_description : errParam
    errorMessage.value = `Authentik 拒绝授权：${desc}`
    return
  }

  const code = typeof route.query.code === 'string' ? route.query.code : ''
  const returnedState = typeof route.query.state === 'string' ? route.query.state : null
  if (!code) {
    errorMessage.value = '回调地址缺少授权码参数，请重新发起登录。'
    return
  }

  try {
    const { verifier, redirectUri } = consumePkceSession(returnedState)
    await completeCallback(code, verifier, redirectUri)
    router.replace('/access')
  } catch (err) {
    errorMessage.value = describeApiError(err)
  }
})
</script>

<template>
  <main class="callback-stage">
    <section class="panel callback-panel">
      <h1 class="callback-title">完成登录验证</h1>
      <p v-if="!errorMessage" class="callback-status">{{ statusText }}</p>

      <template v-else>
        <div class="notice-bar error">
          <span>{{ errorMessage }}</span>
        </div>
        <router-link to="/login" class="btn btn-primary">返回登录页</router-link>
      </template>
    </section>
  </main>
</template>

<style scoped>
.callback-stage {
  min-height: calc(100vh - 57px);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px 16px;
}

.callback-panel {
  width: 100%;
  max-width: 460px;
  padding: 28px;
}

.callback-title {
  margin: 0 0 12px;
  font-size: 20px;
  font-weight: 600;
}

.callback-status {
  margin: 0;
  color: var(--ink-muted);
}
</style>
