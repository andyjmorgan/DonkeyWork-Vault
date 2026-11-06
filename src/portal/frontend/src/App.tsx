import { useEffect, useState } from 'react'
import { Routes, Route, Navigate, Outlet, useLocation } from 'react-router-dom'
import { Toaster } from 'sonner'
import { AppLayout } from './components/AppLayout'
import { isAuthed } from './auth'
import { useTheme } from './theme'
import { api, type Me } from './api'
import { LoginPage } from './pages/Login'
import { CredentialsPage } from './pages/Credentials'
import { ProvidersPage } from './pages/Providers'
import { ConnectPage } from './pages/Connect'
import { AuditPage } from './pages/Audit'
import { ApiKeysPage } from './pages/ApiKeys'
import { ProfilePage } from './pages/Profile'

// The signed-in shell: gated, loads the caller, and renders the app chrome around the active route.
// An unauthenticated visit bounces to the sign-in screen remembering where it was headed.
function AppShell() {
  const [me, setMe] = useState<Me | null>(null)
  const location = useLocation()
  const authed = isAuthed()
  useEffect(() => {
    if (authed) api.me().then(setMe).catch(() => {})
  }, [authed])
  if (!authed) return <Navigate to="/" replace state={{ from: location.pathname + location.search }} />
  return (
    <AppLayout me={me}>
      <Outlet context={{ me }} />
    </AppLayout>
  )
}

// "/" is the sign-in screen until there's a session, then the app.
function Root() {
  return isAuthed() ? <Navigate to="/credentials" replace /> : <LoginPage />
}

export function App() {
  const theme = useTheme()
  return (
    <>
      <Routes>
        <Route path="/" element={<Root />} />
        <Route element={<AppShell />}>
          <Route path="/credentials" element={<CredentialsPage />} />
          <Route path="/providers" element={<ProvidersPage />} />
          <Route path="/oauthconnect" element={<ConnectPage />} />
          <Route path="/access-keys" element={<ApiKeysPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="/profile" element={<ProfilePage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      <Toaster
        theme={theme}
        position="bottom-right"
        toastOptions={{
          classNames: {
            toast: '!rounded-xl !border !border-border !bg-card !text-foreground !shadow-2xl !font-sans',
            description: '!text-muted-foreground',
            success: '[&_svg]:!text-success',
            error: '[&_svg]:!text-danger',
          },
        }}
      />
    </>
  )
}
