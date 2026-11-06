import { useSyncExternalStore } from 'react'

const KEY = 'vault-theme'
export type Theme = 'dark' | 'light'

const listeners = new Set<() => void>()

function apply(t: Theme) {
  document.documentElement.classList.toggle('dark', t === 'dark')
}

export function getTheme(): Theme {
  try {
    return (localStorage.getItem(KEY) as Theme) || 'dark'
  } catch {
    return 'dark'
  }
}

export function initTheme() {
  apply(getTheme())
}

export function toggleTheme(): Theme {
  const next: Theme = getTheme() === 'dark' ? 'light' : 'dark'
  try {
    localStorage.setItem(KEY, next)
  } catch {
    // A private window: the choice lasts for this page only.
  }
  apply(next)
  listeners.forEach((l) => l())
  return next
}

/** The current theme, re-rendering subscribers when it flips (the header toggle, the toaster). */
export function useTheme(): Theme {
  return useSyncExternalStore(
    (cb) => {
      listeners.add(cb)
      return () => listeners.delete(cb)
    },
    getTheme,
    () => 'dark',
  )
}
