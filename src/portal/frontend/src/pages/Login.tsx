import { useLocation } from 'react-router-dom'
import { Button } from '../ui/components/button'
import { Logo } from '../components/Logo'
import { login } from '../auth'

// Sign-in: the am.ai mark, a greeting, one icon button per identity provider (Keycloak
// kc_idp_hint), and a quiet fallback for the realm's own username/password form. Same
// composition as the sandbox and chalk so the family of apps opens the same way.

function MicrosoftIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 21 21" aria-hidden="true">
      <rect x="1" y="1" width="9" height="9" fill="#F25022" />
      <rect x="11" y="1" width="9" height="9" fill="#7FBA00" />
      <rect x="1" y="11" width="9" height="9" fill="#00A4EF" />
      <rect x="11" y="11" width="9" height="9" fill="#FFB900" />
    </svg>
  )
}

function AppleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M17.05 20.28c-.98.95-2.05.88-3.08.4-1.09-.5-2.08-.48-3.24 0-1.44.62-2.2.44-3.06-.4C2.79 15.25 3.51 7.59 9.05 7.31c1.35.07 2.29.74 3.08.8 1.18-.24 2.31-.93 3.57-.84 1.51.12 2.65.72 3.4 1.8-3.12 1.87-2.38 5.98.48 7.13-.57 1.5-1.31 2.99-2.54 4.09zM12.03 7.25c-.15-2.23 1.66-4.07 3.74-4.25.29 2.58-2.34 4.5-3.74 4.25z" />
    </svg>
  )
}

function GoogleIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" aria-hidden="true">
      <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4" />
      <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853" />
      <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05" />
      <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335" />
    </svg>
  )
}

function GitHubIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 .7a11.5 11.5 0 0 0-3.64 22.4c.58.1.79-.25.79-.56v-2.23c-3.22.7-3.9-1.37-3.9-1.37-.52-1.34-1.28-1.69-1.28-1.69-1.05-.72.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.57-.29-5.27-1.28-5.27-5.68 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.47.11-3.05 0 0 .97-.31 3.16 1.18a10.9 10.9 0 0 1 5.76 0c2.19-1.49 3.16-1.18 3.16-1.18.63 1.58.23 2.76.11 3.05.74.81 1.19 1.83 1.19 3.09 0 4.41-2.71 5.38-5.29 5.67.42.36.79 1.06.79 2.14v3.18c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .7Z" />
    </svg>
  )
}

const providers = [
  { id: 'google', name: 'Google', icon: GoogleIcon },
  { id: 'github', name: 'GitHub', icon: GitHubIcon },
  { id: 'microsoft', name: 'Microsoft', icon: MicrosoftIcon },
  { id: 'apple', name: 'Apple', icon: AppleIcon },
]

export function LoginPage() {
  const location = useLocation()
  const returnTo = (location.state as { from?: string } | null)?.from
  return (
    <div className="flex min-h-dvh flex-col bg-background text-foreground">
      <main className="flex flex-1 items-center justify-center p-4">
        <div className="w-full max-w-sm space-y-6 text-center">
          <div className="flex flex-col items-center space-y-4">
            <Logo compact imageClassName="size-24" />
            <div className="space-y-2">
              <h1 className="text-3xl font-semibold">Welcome back</h1>
              <p className="text-muted-foreground">Sign in to manage your credentials</p>
            </div>
          </div>
          <div className="flex justify-center gap-4">
            {providers.map((provider) => (
              <Button
                key={provider.id}
                variant="outline"
                className="size-12 px-0"
                title={`Sign in with ${provider.name}`}
                aria-label={`Sign in with ${provider.name}`}
                onClick={() => login(returnTo, provider.id)}
              >
                <provider.icon className="!size-6" />
              </Button>
            ))}
          </div>
          <Button variant="ghost" size="sm" className="text-sm" onClick={() => login(returnTo)}>
            Sign in with a username and password
          </Button>
        </div>
      </main>
      <footer className="p-4 text-center text-sm text-muted-foreground">Built with questionable decisions and caffeine</footer>
    </div>
  )
}
