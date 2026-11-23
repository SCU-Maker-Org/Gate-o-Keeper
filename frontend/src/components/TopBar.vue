<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import logoWhiteUrl from '../assets/logo-white.png'
import { useSession } from '../stores/session'
import { useTheme } from '../stores/theme'

const route = useRoute()
const router = useRouter()
const { state, isAuthenticated, isAdmin, signOut } = useSession()
const { preference, cycleTheme } = useTheme()

const themeLabel = computed(() => {
  if (preference.value === 'dark') return '深色'
  if (preference.value === 'light') return '浅色'
  return '跟随系统'
})

async function handleSignOut() {
  await signOut()
  router.replace('/login')
}
</script>

<template>
  <header class="topbar">
    <div class="topbar-inner">
      <div class="brand-group">
        <router-link to="/access" class="brand-link">
          <span class="brand-mark" aria-hidden="true">
            <img :src="logoWhiteUrl" alt="" class="brand-logo" />
          </span>
          <span class="brand-title">Maker 门禁控制台</span>
        </router-link>

        <nav v-if="isAuthenticated" class="nav-links" aria-label="主导航">
          <router-link
            to="/access"
            class="nav-link"
            :class="{ active: route.path === '/access' }"
          >
            门锁控制
          </router-link>
          <router-link
            v-if="isAdmin"
            to="/steward"
            class="nav-link"
            :class="{ active: route.path.startsWith('/steward') }"
          >
            系统管理
          </router-link>
        </nav>
      </div>

      <div class="topbar-right">
        <div v-if="isAuthenticated && state.me" class="user-strip">
          <span class="user-name">{{ state.me.displayName }}</span>
          <span class="badge" :class="isAdmin ? 'badge-cobalt' : ''">
            {{ isAdmin ? '管理员' : '成员' }}
          </span>
          <button type="button" class="btn btn-sm" @click="handleSignOut">
            退出登录
          </button>
        </div>

        <button
          type="button"
          class="btn btn-sm theme-btn"
          :title="`当前外观：${themeLabel}（点击切换）`"
          @click="cycleTheme"
        >
          <svg
            v-if="preference === 'light'"
            class="theme-icon"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="4" />
            <path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41" />
          </svg>
          <svg
            v-else-if="preference === 'dark'"
            class="theme-icon"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            aria-hidden="true"
          >
            <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
          </svg>
          <svg
            v-else
            class="theme-icon"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            stroke-width="2"
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="9" />
            <path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor" stroke="none" />
          </svg>
          <span>{{ themeLabel }}</span>
        </button>
      </div>
    </div>
  </header>
</template>

<style scoped>
.topbar {
  background: var(--surface);
  border-bottom: 1px solid var(--hairline);
}

.topbar-inner {
  max-width: 1120px;
  margin: 0 auto;
  min-height: 56px;
  padding: 8px 20px;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.brand-group {
  display: flex;
  align-items: center;
  gap: 28px;
}

.brand-link {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  text-decoration: none;
  color: var(--ink);
  font-weight: 600;
  font-size: 15px;
}

.brand-mark {
  width: 32px;
  height: 32px;
  padding: 2px;
  background: var(--cobalt-btn);
  border-radius: 50%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}

.topbar-right {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}

.theme-btn {
  gap: 6px;
}

.theme-icon {
  width: 14px;
  height: 14px;
  flex-shrink: 0;
}

.brand-logo {
  width: 100%;
  height: 100%;
  object-fit: contain;
  display: block;
}

.nav-links {
  display: flex;
  align-items: center;
  gap: 4px;
}

.nav-link {
  text-decoration: none;
  color: var(--ink-muted);
  padding: 6px 12px;
  border-radius: var(--radius-sm);
  font-size: 14px;
  font-weight: 500;
}

.nav-link:hover {
  background: var(--surface-subtle);
  color: var(--ink);
}

.nav-link.active {
  background: var(--cobalt-tint);
  color: var(--cobalt);
}

.user-strip {
  display: flex;
  align-items: center;
  gap: 10px;
}

.user-name {
  font-weight: 500;
  font-size: 14px;
}

@media (max-width: 720px) {
  .topbar-inner {
    padding: 8px 14px;
  }
  .brand-group {
    gap: 14px;
  }
}
</style>
