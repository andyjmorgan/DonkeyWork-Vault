import { KeyRound, Boxes, Plug, ScrollText } from 'lucide-react'
import { NavLink } from 'react-router-dom'
import { cn } from '../ui/lib/utils'

export const navItems: { to: string; label: string; icon: typeof KeyRound }[] = [
  { to: '/credentials', label: 'Credentials', icon: KeyRound },
  { to: '/providers', label: 'Providers', icon: Boxes },
  { to: '/oauthconnect', label: 'OAuth Connect', icon: Plug },
  { to: '/audit', label: 'Audit trail', icon: ScrollText },
]

/** The nav links, shared by the desktop sidebar and the mobile drawer. */
export function NavList({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav className="space-y-1">
      {navItems.map((it) => (
        <NavLink
          key={it.to}
          to={it.to}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              'flex w-full items-center gap-2 rounded-xl px-3 py-2 text-sm transition-all duration-200',
              isActive ? 'bg-accent/10 text-accent' : 'text-muted-foreground hover:bg-muted hover:text-foreground',
            )
          }
        >
          <it.icon className="size-4" />
          {it.label}
        </NavLink>
      ))}
    </nav>
  )
}

export function Sidebar() {
  return (
    <aside className="hidden w-56 shrink-0 border-r border-border p-3 sm:block">
      <NavList />
    </aside>
  )
}
