import { useState, type ReactNode } from 'react'
import { NavLink, useNavigate } from 'react-router-dom'
import {
  Activity,
  BookOpen,
  Boxes,
  Github,
  KeyRound,
  KeySquare,
  LogOut,
  Menu,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Plug,
  Sun,
  UserRound,
  X,
} from 'lucide-react'
import { Logo } from './Logo'
import { Button } from '../ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '../ui/components/dropdown-menu'
import { cn, initials } from '../lib'
import { logout } from '../auth'
import { toggleTheme, useTheme } from '../theme'
import type { Me } from '../api'

export const REPO = 'https://github.com/andyjmorgan/DonkeyWork-Vault'
export const DOCS = 'https://andyjmorgan.github.io/DonkeyWork-Vault/'

// Sidebar groups. Each icon carries its own hue so the rail reads at a glance when collapsed.
const navigation: { label?: string; items: { name: string; href: string; icon: typeof KeyRound; color: string }[] }[] = [
  { items: [{ name: 'Credentials', href: '/credentials', icon: KeyRound, color: 'text-accent' }] },
  {
    label: 'OAuth',
    items: [
      { name: 'Providers', href: '/providers', icon: Boxes, color: 'text-plum' },
      { name: 'Connect', href: '/oauthconnect', icon: Plug, color: 'text-info' },
    ],
  },
  { label: 'Auth', items: [{ name: 'API keys', href: '/access-keys', icon: KeySquare, color: 'text-success' }] },
  { label: 'Audit', items: [{ name: 'Audit trail', href: '/audit', icon: Activity, color: 'text-warning' }] },
]

const COLLAPSED_KEY = 'vault-sidebar-collapsed'

/** The desktop sidebar's collapsed state, remembered per browser (storage may be unavailable). */
function useCollapsed() {
  const [collapsed, setCollapsed] = useState(() => {
    try {
      return localStorage.getItem(COLLAPSED_KEY) === '1'
    } catch {
      return false
    }
  })
  const toggle = () =>
    setCollapsed((value) => {
      try {
        localStorage.setItem(COLLAPSED_KEY, value ? '0' : '1')
      } catch {
        // A private window: the choice lasts for this page only.
      }
      return !value
    })
  return [collapsed, toggle] as const
}

export function AppLayout({ me, children }: { me: Me | null; children: ReactNode }) {
  const [open, setOpen] = useState(false)
  // Collapsed applies from md up, where the sidebar is a rail of icons; the mobile drawer is always full.
  const [collapsed, toggleCollapsed] = useCollapsed()
  const theme = useTheme()
  const navigate = useNavigate()

  return (
    <div className="flex h-dvh overflow-hidden bg-background text-foreground">
      {open && (
        <button aria-label="Close navigation" className="fixed inset-0 z-40 bg-black/60 md:hidden" onClick={() => setOpen(false)} />
      )}
      <aside
        className={cn(
          'fixed inset-y-0 left-0 z-50 flex w-64 flex-col border-r border-border bg-sidebar transition-[transform,width] duration-200 md:relative md:translate-x-0',
          open ? 'translate-x-0' : '-translate-x-full',
          collapsed && 'md:w-16',
        )}
      >
        <div className={cn('flex h-14 items-center justify-between border-b border-border px-4', collapsed && 'md:justify-center md:px-0')}>
          <Logo className={cn(collapsed && 'md:hidden')} />
          {collapsed && <Logo compact className="hidden md:flex" />}
          <Button variant="ghost" size="icon" className="md:hidden" aria-label="Close navigation" onClick={() => setOpen(false)}>
            <X className="size-5" />
          </Button>
        </div>
        <nav className={cn('flex-1 space-y-3 overflow-y-auto p-4', collapsed && 'md:px-2')} aria-label="Main">
          {navigation.map((group, index) => (
            <div key={group.label ?? index} className="space-y-1">
              {group.label && collapsed && <div aria-hidden className="mx-2 hidden border-t border-border md:block" />}
              {group.label && (
                <p
                  aria-hidden
                  className={cn('px-3 pt-1 text-[10px] font-semibold uppercase tracking-widest text-muted-foreground', collapsed && 'md:hidden')}
                >
                  {group.label}
                </p>
              )}
              {group.items.map((item) => (
                <NavLink
                  key={item.href}
                  to={item.href}
                  onClick={() => setOpen(false)}
                  title={collapsed ? item.name : undefined}
                  aria-label={item.name}
                  className={({ isActive }) =>
                    cn(
                      'flex items-center gap-3 rounded-md px-3 py-2 text-sm font-medium transition-colors',
                      collapsed && 'md:justify-center md:px-0',
                      isActive ? 'bg-elevated text-foreground' : 'text-muted-foreground hover:bg-elevated hover:text-foreground',
                    )
                  }
                >
                  <item.icon className={cn('size-4 shrink-0', item.color)} />
                  <span className={cn('truncate', collapsed && 'md:hidden')}>{item.name}</span>
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <div className={cn('flex items-center justify-between gap-2 border-t border-border p-4 text-xs text-muted-foreground', collapsed && 'md:justify-center md:px-0')}>
          <span className={cn('truncate', collapsed && 'md:hidden')}>Build something rad</span>
          <Button
            variant="ghost"
            size="iconSm"
            className="hidden shrink-0 md:inline-flex"
            onClick={toggleCollapsed}
            aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
            aria-expanded={!collapsed}
            title={collapsed ? 'Expand' : 'Collapse'}
          >
            {collapsed ? <PanelLeftOpen /> : <PanelLeftClose />}
          </Button>
        </div>
      </aside>

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <header className="flex h-14 shrink-0 items-center gap-2 border-b border-border bg-background px-4 md:px-6">
          <Button variant="ghost" size="icon" className="md:hidden" aria-label="Open navigation" onClick={() => setOpen(true)}>
            <Menu className="size-5" />
          </Button>
          <div className="flex-1" />
          <Button variant="ghost" size="icon" onClick={() => toggleTheme()} aria-label="Toggle theme" title={theme === 'dark' ? 'Light mode' : 'Dark mode'}>
            {theme === 'dark' ? <Sun /> : <Moon />}
          </Button>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="ghost" size="icon" className="rounded-full" aria-label="Account menu">
                <span className="grid size-8 place-items-center rounded-full bg-elevated text-xs font-semibold">{initials(me?.name, me?.email)}</span>
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuLabel>
                <p className="truncate text-sm font-medium">{me?.name ?? me?.email ?? 'Signed in'}</p>
                {me?.email && <p className="mt-1 truncate text-xs text-muted-foreground">{me.email}</p>}
              </DropdownMenuLabel>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => navigate('/profile')}>
                <UserRound /> Profile
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <a href={DOCS} target="_blank" rel="noreferrer">
                  <BookOpen /> Documentation
                </a>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <a href={REPO} target="_blank" rel="noreferrer">
                  <Github /> GitHub
                </a>
              </DropdownMenuItem>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => logout()}>
                <LogOut /> Sign out
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </header>
        <main className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-[1400px] space-y-6 p-4 md:p-6 lg:p-8">{children}</div>
        </main>
      </div>
    </div>
  )
}
