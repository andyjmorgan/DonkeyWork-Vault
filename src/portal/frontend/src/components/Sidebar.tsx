import { KeyRound, Boxes, Plug, ScrollText } from 'lucide-react'
import { cn } from '../ui/lib/utils'

export type Tab = 'credentials' | 'providers' | 'connect' | 'audit' | 'profile'

export const navItems: { id: Tab; label: string; icon: typeof KeyRound }[] = [
  { id: 'credentials', label: 'Credentials', icon: KeyRound },
  { id: 'providers', label: 'Providers', icon: Boxes },
  { id: 'connect', label: 'OAuth Connect', icon: Plug },
  { id: 'audit', label: 'Audit trail', icon: ScrollText },
]

/** The nav buttons, shared by the desktop sidebar and the mobile drawer. */
export function NavList({ active, onSelect }: { active: Tab; onSelect: (t: Tab) => void }) {
  return (
    <nav className="space-y-1">
      {navItems.map((it) => (
        <button
          key={it.id}
          onClick={() => onSelect(it.id)}
          className={cn(
            'flex w-full items-center gap-2 rounded-xl px-3 py-2 text-sm transition-all duration-200',
            active === it.id ? 'bg-accent/10 text-accent' : 'text-muted-foreground hover:bg-muted hover:text-foreground',
          )}
        >
          <it.icon className="size-4" />
          {it.label}
        </button>
      ))}
    </nav>
  )
}

export function Sidebar({ active, onSelect }: { active: Tab; onSelect: (t: Tab) => void }) {
  return (
    <aside className="hidden w-56 shrink-0 border-r border-border p-3 sm:block">
      <NavList active={active} onSelect={onSelect} />
    </aside>
  )
}
