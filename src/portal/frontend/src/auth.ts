import { UserManager, type User, WebStorageStateStore } from 'oidc-client-ts'

// Generic OIDC (Authorization Code + PKCE). Vendor-neutral: issuer/client/scopes come from
// the BFF's /api/config at runtime, so the same build works against any OIDC IdP.
let mgr: UserManager | null = null
let current: User | null = null

export async function initAuth(): Promise<void> {
  const cfg = await fetch('/api/config').then((r) => r.json()).catch(() => ({}))
  if (!cfg.authEnabled || !cfg.authority) {
    return // auth disabled (local/dev)
  }

  mgr = new UserManager({
    authority: cfg.authority,
    client_id: cfg.clientId,
    redirect_uri: window.location.origin + '/',
    post_logout_redirect_uri: window.location.origin + '/',
    response_type: 'code',
    scope: cfg.scopes || 'openid profile email',
    automaticSilentRenew: true,
    loadUserInfo: true,
    userStore: new WebStorageStateStore({ store: window.localStorage }),
  })

  const p = new URLSearchParams(window.location.search)
  if (p.has('code') && p.has('state')) {
    current = await mgr.signinRedirectCallback()
    window.history.replaceState({}, '', window.location.pathname)
  } else {
    current = await mgr.getUser()
  }

  if (!current || current.expired) {
    await mgr.signinRedirect()
    await new Promise<never>(() => {}) // browser navigates away; don't render first
  }
}

export async function getToken(): Promise<string> {
  if (!mgr) return ''
  let u = await mgr.getUser()
  if (!u || u.expired) {
    try {
      u = await mgr.signinSilent()
    } catch {
      await mgr.signinRedirect()
      await new Promise<never>(() => {})
    }
  }
  return u?.access_token ?? ''
}

export function logout(): void {
  if (mgr) void mgr.signoutRedirect()
  else window.location.reload()
}

export function profile() {
  return current?.profile
}
