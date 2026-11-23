import { computed, ref } from 'vue'

export type ThemePreference = 'system' | 'light' | 'dark'

const STORAGE_KEY = 'locker.theme'

function readStoredPreference(): ThemePreference {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (raw === 'light' || raw === 'dark' || raw === 'system') {
      return raw
    }
  } catch {
    // ignore storage failures
  }
  return 'system'
}

const mediaQuery =
  typeof window !== 'undefined' ? window.matchMedia('(prefers-color-scheme: dark)') : null

const preference = ref<ThemePreference>(readStoredPreference())
const systemDark = ref<boolean>(mediaQuery ? mediaQuery.matches : false)

function applyTheme() {
  const dark = preference.value === 'dark' || (preference.value === 'system' && systemDark.value)
  if (typeof document !== 'undefined') {
    document.documentElement.dataset.theme = dark ? 'dark' : 'light'
  }
}

if (mediaQuery) {
  const onChange = (ev: MediaQueryListEvent) => {
    systemDark.value = ev.matches
    applyTheme()
  }
  mediaQuery.addEventListener('change', onChange)
}

applyTheme()

export function useTheme() {
  const effectiveTheme = computed<'light' | 'dark'>(() =>
    preference.value === 'dark' || (preference.value === 'system' && systemDark.value)
      ? 'dark'
      : 'light',
  )

  function setPreference(next: ThemePreference) {
    preference.value = next
    try {
      localStorage.setItem(STORAGE_KEY, next)
    } catch {
      // ignore storage failures
    }
    applyTheme()
  }

  function cycleTheme() {
    const order: ThemePreference[] = ['system', 'light', 'dark']
    const idx = order.indexOf(preference.value)
    setPreference(order[(idx + 1) % order.length])
  }

  return {
    preference,
    effectiveTheme,
    setPreference,
    cycleTheme,
  }
}
