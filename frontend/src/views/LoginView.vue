<script setup lang="ts">
import { onMounted, ref } from 'vue'
import logoWhiteUrl from '../assets/logo-white.png'
import { getOidcConfig, loadOidcConfig } from '../lib/pkce'
import { useSession } from '../stores/session'

const { state, startLogin, clearNotice } = useSession()
const redirecting = ref(false)
const oidc = ref(getOidcConfig())

onMounted(async () => {
  oidc.value = await loadOidcConfig()
})

async function handleLogin() {
  redirecting.value = true
  try {
    await startLogin()
  } catch (err) {
    redirecting.value = false
    state.notice = err instanceof Error ? err.message : '无法启动 Authentik 登录。'
  }
}
</script>

<template>
  <main class="login-stage">
    <section class="panel login-panel">
      <div class="login-head">
        <div class="login-mark" aria-hidden="true">
          <img :src="logoWhiteUrl" alt="" class="login-logo" />
        </div>
        <h1 class="login-title">Maker 门禁控制台</h1>
      </div>

      <div v-if="state.notice" class="notice-bar error">
        <span>{{ state.notice }}</span>
        <button type="button" class="btn btn-sm" @click="clearNotice">关闭</button>
      </div>

      <div class="login-actions">
        <button
          type="button"
          class="btn btn-primary login-btn"
          :disabled="redirecting"
          @click="handleLogin"
        >
          {{ redirecting ? '正在前往 Maker 统一认证…' : '使用 Maker 统一认证登录' }}
        </button>
      </div>
    </section>
  </main>
</template>

<style scoped>
.login-stage {
  min-height: calc(100vh - 57px);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px 16px;
}

.login-panel {
  width: 100%;
  max-width: 460px;
  padding: 32px 28px;
}

.login-head {
  margin-bottom: 24px;
}

.login-mark {
  width: 56px;
  height: 56px;
  padding: 4px;
  background: var(--cobalt-btn);
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  margin-bottom: 16px;
}

.login-logo {
  width: 100%;
  height: 100%;
  object-fit: contain;
  display: block;
}

.login-title {
  margin: 0;
  font-size: 24px;
  font-weight: 600;
  letter-spacing: -0.02em;
}

.login-desc {
  margin: 10px 0 0;
  color: var(--ink-muted);
}

.login-actions {
  margin-bottom: 24px;
}

.login-btn {
  width: 100%;
  padding: 11px 16px;
  font-size: 15px;
}

.oidc-meta {
  margin: 0;
  padding-top: 18px;
  border-top: 1px solid var(--hairline);
  display: flex;
  flex-direction: column;
  gap: 10px;
  font-size: 13px;
}

.oidc-meta div {
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.oidc-meta dt {
  color: var(--ink-muted);
  font-weight: 500;
}

.oidc-meta dd {
  margin: 0;
  word-break: break-all;
}
</style>
