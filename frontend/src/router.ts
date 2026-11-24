import { createRouter, createWebHistory } from 'vue-router'
import { setSessionExpiredHandler, useSession } from './stores/session'

const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/access' },
    {
      path: '/login',
      component: () => import('./views/LoginView.vue'),
      meta: { public: true },
    },
    {
      path: '/callback',
      component: () => import('./views/CallbackView.vue'),
      meta: { public: true },
    },
    {
      path: '/access',
      component: () => import('./views/AccessView.vue'),
    },
    {
      path: '/steward',
      component: () => import('./views/StewardView.vue'),
      meta: { requiresAdmin: true },
    },
  ],
})

router.beforeEach(async (to) => {
  const { isAuthenticated, isAdmin, restoreSession } = useSession()

  if (to.meta.public) {
    if (to.path === '/login' && (isAuthenticated.value || (await restoreSession()))) {
      return '/access'
    }
    return true
  }

  if (!isAuthenticated.value) {
    const ok = await restoreSession()
    if (!ok) {
      return '/login'
    }
  }

  if (to.meta.requiresAdmin && !isAdmin.value) {
    return '/access'
  }

  return true
})

setSessionExpiredHandler(() => {
  if (!router.currentRoute.value.meta.public) {
    void router.replace('/login')
  }
})

export default router
