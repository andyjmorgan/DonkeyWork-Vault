import { useEffect, useState } from 'react'
import { Routes, Route, Navigate, Outlet } from 'react-router-dom'
import { AppLayout } from './components/AppLayout'
import { isAuthed } from './auth'
import { api, type Me } from './api'
import { LandingPage } from './pages/Landing'
import { CredentialsPage } from './pages/Credentials'
import { ProvidersPage } from './pages/Providers'
import { ConnectPage } from './pages/Connect'
import { AuditPage } from './pages/Audit'
import { ProfilePage } from './pages/Profile'

// The signed-in shell: gated, loads the caller, and renders the app chrome around the active route.
function AppShell() {
  const [me, setMe] = useState<Me | null>(null)
  useEffect(() => { api.me().then(setMe).catch(() => {}) }, [])
  if (!isAuthed()) return <Navigate to="/" replace />
  return (
    <AppLayout me={me}>
      <Outlet context={{ me }} />
    </AppLayout>
  )
}

export function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route element={<AppShell />}>
        <Route path="/credentials" element={<CredentialsPage />} />
        <Route path="/providers" element={<ProvidersPage />} />
        <Route path="/oauthconnect" element={<ConnectPage />} />
        <Route path="/audit" element={<AuditPage />} />
        <Route path="/profile" element={<ProfilePage />} />
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
