import { UserManager, type User, WebStorageStateStore } from 'oidc-client-ts'

// Generic OIDC (Authorization Code + PKCE). Vendor-neutral: issuer/client/scopes come from
// the BFF's /api/config at runtime, so the same build works against any OIDC IdP.
//
// The public landing ("/") renders without auth — login is an explicit action (login()), not a
// forced redirect on load. After the IdP round-trip the browser returns to "/", we complete the
// sign-in, then restore the route the user was heading to (default /credentials).
let mgr: UserManager | null = null
let current: User | null = null
let authEnabled = false

const RETURN_TO_KEY = 'vault.returnTo'

export async function initAuth(): Promise<void> {
  const cfg = await fetch('/api/config').then((r) => r.json()).catch(() => ({}))
  if (!cfg.authEnabled || !cfg.authority) {
    return // auth disabled (local/dev) — treated as signed in
  }
  authEnabled = true

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
    try {
      current = await mgr.signinRedirectCallback()
    } catch {
      current = null
    }
    // Restore where the user was going, then drop the OIDC query params.
    const returnTo = sessionStorage.getItem(RETURN_TO_KEY) || '/credentials'
    sessionStorage.removeItem(RETURN_TO_KEY)
    window.history.replaceState({}, '', returnTo)
  } else {
    current = await mgr.getUser()
  }
}

/** True when there's a valid session, or when auth is disabled (dev). */
export function isAuthed(): boolean {
  return !authEnabled || (!!current && !current.expired)
}

/** Start the OIDC login; on return the app lands on `returnTo`. */
export function login(returnTo = '/credentials'): void {
  if (!mgr) {
    window.location.assign(returnTo) // auth disabled — just enter the app
    return
  }
  sessionStorage.setItem(RETURN_TO_KEY, returnTo)
  void mgr.signinRedirect()
}

export async function getToken(): Promise<string> {
  if (!mgr) return ''
  let u = await mgr.getUser()
  if (!u || u.expired) {
    try {
      u = await mgr.signinSilent()
    } catch {
      login(window.location.pathname)
      await new Promise<never>(() => {})
    }
  }
  return u?.access_token ?? ''
}

export function logout(): void {
  if (mgr) void mgr.signoutRedirect()
  else window.location.assign('/')
}

export function profile() {
  return current?.profile
}
