<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import '../components/steward/steward.css'
import AdaptersTab from '../components/steward/AdaptersTab.vue'
import AuditLogsTab, { type AuditFilterParams } from '../components/steward/AuditLogsTab.vue'
import LocksTab from '../components/steward/LocksTab.vue'
import PolicyTab from '../components/steward/PolicyTab.vue'
import UsersTab from '../components/steward/UsersTab.vue'
import { defaultSystemConfig } from '../components/steward/defaults'
import { adminApi } from '../lib/adminApi'
import { describeApiError } from '../lib/api'
import { useSession } from '../stores/session'
import type {
  AdminAdapterView,
  AdminLockView,
  AuditLogRow,
  SystemConfig,
  UserPage,
  UserStatus,
} from '../types/api'

type TabKey = 'locks' | 'adapters' | 'audit' | 'users' | 'policy'

const SECTIONS: { key: TabKey; label: string; summary: string }[] = [
  {
    key: 'locks',
    label: '门锁管理',
    summary: '创建与管理抽象门锁，绑定门锁适配器并配置群组授权规则。',
  },
  {
    key: 'adapters',
    label: '门锁适配器',
    summary: '审批设备接入与凭证指纹，管理硬件在线态、状态查询、紧急开锁与密钥轮换。',
  },
  {
    key: 'audit',
    label: '审计日志',
    summary: '按操作者、目标门锁或适配器与结果检索安全事件，查看完整请求明细。',
  },
  {
    key: 'users',
    label: '成员管理',
    summary: '成员账号、停用状态与群组统一在 Authentik SSO 侧维护；本页展示已同步的成员快照与本地强踢入口。',
  },
  {
    key: 'policy',
    label: '系统策略',
    summary: '调整开锁防重放窗口、指令超时、最大设备数、管理员群组及审计保留天数。',
  },
]

const route = useRoute()
const router = useRouter()
const { state: sessionState } = useSession()

function resolveTab(raw: unknown): TabKey {
  if (
    raw === 'locks' ||
    raw === 'adapters' ||
    raw === 'audit' ||
    raw === 'users' ||
    raw === 'policy'
  ) {
    return raw
  }
  return 'locks'
}

const activeTab = ref<TabKey>(resolveTab(route.query.section))
const activeSection = computed(
  () => SECTIONS.find((s) => s.key === activeTab.value) || SECTIONS[0],
)
const pendingAdapterCount = computed(
  () => adapters.value.filter((a) => a.approvalStatus === 'pending').length,
)
const busyCount = ref(0)
const busy = computed(() => busyCount.value > 0)
const banner = ref<{ kind: 'success' | 'error'; text: string } | null>(null)

const locks = ref<AdminLockView[]>([])
const adapters = ref<AdminAdapterView[]>([])
const usersPage = ref<UserPage>({
  items: [],
  total: 0,
  page: 1,
  pageSize: 20,
  status: 'active',
})
const userQuery = ref<{ status: UserStatus; page: number; pageSize: number }>({
  status: 'active',
  page: 1,
  pageSize: 20,
})
const auditLogs = ref<AuditLogRow[]>([])
const systemConfig = ref<SystemConfig>(defaultSystemConfig())
const configVersion = ref(0)

function showSuccess(text: string) {
  banner.value = { kind: 'success', text }
}

function showErrorText(text: string) {
  banner.value = { kind: 'error', text }
}

function showError(err: unknown) {
  banner.value = { kind: 'error', text: describeApiError(err) }
}

async function runAction(fn: () => Promise<void>) {
  busyCount.value += 1
  banner.value = null
  try {
    await fn()
  } catch (err) {
    showError(err)
  } finally {
    busyCount.value -= 1
  }
}

async function loadLocks() {
  locks.value = await adminApi.listLocks()
}

async function loadAdapters() {
  adapters.value = await adminApi.listAdapters()
}

async function loadAuditLogs(params: AuditFilterParams = { limit: 50, offset: 0 }) {
  auditLogs.value = await adminApi.listAuditLogs(params)
}

async function loadUsers(params?: { status: UserStatus; page: number; pageSize: number }) {
  if (params) {
    userQuery.value = { ...params }
  }
  usersPage.value = await adminApi.listUsers(userQuery.value)
}

async function loadPolicy() {
  systemConfig.value = await adminApi.getConfig()
  configVersion.value += 1
}

async function refreshLocksAndAdapters() {
  await Promise.all([loadLocks(), loadAdapters()])
}

async function handleQueryAudit(params: AuditFilterParams) {
  await runAction(() => loadAuditLogs(params))
}

async function switchTab(tab: TabKey, syncUrl = true) {
  activeTab.value = tab
  if (syncUrl && route.query.section !== tab) {
    router.replace({ path: '/steward', query: { ...route.query, section: tab } })
  }
  await runAction(async () => {
    if (tab === 'locks') await refreshLocksAndAdapters()
    else if (tab === 'adapters') await loadAdapters()
    else if (tab === 'audit') await loadAuditLogs()
    else if (tab === 'users') await loadUsers()
    else if (tab === 'policy') await loadPolicy()
  })
}

watch(
  () => route.query.section,
  (val) => {
    const next = resolveTab(val)
    if (next !== activeTab.value) {
      switchTab(next, false)
    }
  },
)

onMounted(() => {
  void switchTab(activeTab.value, false)
  if (activeTab.value !== 'locks' && activeTab.value !== 'adapters') {
    void loadAdapters().catch(() => {})
  }
})
</script>

<template>
  <main class="page-wrap steward-wrap">
    <div class="steward-layout">
      <aside class="steward-sidebar panel" aria-label="系统管理导航">
        <div class="sidebar-title">系统管理</div>
        <nav class="sidebar-nav" role="tablist" aria-orientation="vertical">
          <button
            v-for="item in SECTIONS"
            :key="item.key"
            type="button"
            role="tab"
            class="sidebar-item"
            :class="{ active: activeTab === item.key }"
            :aria-selected="activeTab === item.key"
            @click="switchTab(item.key)"
          >
            <span>{{ item.label }}</span>
            <span
              v-if="item.key === 'adapters' && pendingAdapterCount > 0"
              class="badge badge-warn tabular"
            >
              {{ pendingAdapterCount }}
            </span>
          </button>
        </nav>
      </aside>

      <div class="steward-workspace">
        <div class="page-header workspace-header">
          <div>
            <h1 class="page-title">{{ activeSection.label }}</h1>
            <p class="page-subtitle">{{ activeSection.summary }}</p>
          </div>
        </div>

        <div v-if="banner" class="notice-bar" :class="banner.kind" role="status">
          <span>{{ banner.text }}</span>
          <button type="button" class="btn btn-sm" @click="banner = null">关闭</button>
        </div>

        <LocksTab
          v-if="activeTab === 'locks'"
          :locks="locks"
          :adapters="adapters"
          :busy="busy"
          :run-action="runAction"
          :on-reload="refreshLocksAndAdapters"
          :on-refresh-locks="loadLocks"
          :on-success="showSuccess"
          :on-error-text="showErrorText"
        />

        <AdaptersTab
          v-if="activeTab === 'adapters'"
          :adapters="adapters"
          :busy="busy"
          :run-action="runAction"
          :on-reload="refreshLocksAndAdapters"
          :on-refresh-adapters="loadAdapters"
          :on-success="showSuccess"
          :on-error-text="showErrorText"
        />

        <AuditLogsTab
          v-show="activeTab === 'audit'"
          :audit-logs="auditLogs"
          :busy="busy"
          @query="handleQueryAudit"
        />

        <UsersTab
          v-if="activeTab === 'users'"
          :user-page="usersPage"
          :current-user-id="sessionState.me?.userId"
          :busy="busy"
          :run-action="runAction"
          :on-load-users="loadUsers"
          :on-success="showSuccess"
        />

        <PolicyTab
          v-if="activeTab === 'policy'"
          :config="systemConfig"
          :config-version="configVersion"
          :busy="busy"
          :run-action="runAction"
          :on-config-updated="(cfg) => { systemConfig = cfg; }"
          :on-success="showSuccess"
        />
      </div>
    </div>
  </main>
</template>
