const KEY = 'vault-theme'

function apply(t: string) {
  document.documentElement.classList.toggle('dark', t === 'dark')
}

export function getTheme(): 'dark' | 'light' {
  return (localStorage.getItem(KEY) as 'dark' | 'light') || 'dark'
}

export function initTheme() {
  apply(getTheme())
}

export function toggleTheme(): 'dark' | 'light' {
  const next = getTheme() === 'dark' ? 'light' : 'dark'
  localStorage.setItem(KEY, next)
  apply(next)
  return next
}
