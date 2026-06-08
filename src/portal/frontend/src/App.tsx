import { useEffect, useState } from 'react'
import { AppLayout } from './components/AppLayout'
import type { Tab } from './components/Sidebar'
import { api, type Me } from './api'
import { CredentialsPage } from './pages/Credentials'
import { ProvidersPage } from './pages/Providers'
import { ConnectPage } from './pages/Connect'
import { ProfilePage } from './pages/Profile'

export function App() {
  const [tab, setTab] = useState<Tab>('credentials')
  const [me, setMe] = useState<Me | null>(null)
  const [flash, setFlash] = useState<string>()

  useEffect(() => { api.me().then(setMe).catch(() => {}) }, [])

  useEffect(() => {
    const p = new URLSearchParams(location.search)
    if (p.get('connected')) { setTab('connect'); setFlash(`Connected ${p.get('connected')}`); history.replaceState({}, '', '/') }
    else if (p.get('oauth_error')) { setTab('connect'); setFlash(`OAuth error: ${p.get('oauth_error')}`); history.replaceState({}, '', '/') }
  }, [])

  return (
    <AppLayout me={me} active={tab} onSelect={setTab}>
      {flash && (
        <div className="rounded-xl border border-accent/30 bg-accent/10 px-4 py-2 text-sm text-accent">{flash}</div>
      )}
      {tab === 'credentials' && <CredentialsPage />}
      {tab === 'providers' && <ProvidersPage />}
      {tab === 'connect' && <ConnectPage />}
      {tab === 'profile' && <ProfilePage me={me} />}
      {me && (
        <p className="pt-2 text-xs text-muted-foreground">
          {me.name || me.email} · userId {me.userId} · tenantId {me.tenantId || '(default)'}
        </p>
      )}
    </AppLayout>
  )
}
