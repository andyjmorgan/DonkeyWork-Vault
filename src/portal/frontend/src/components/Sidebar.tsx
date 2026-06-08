import { KeyRound, Boxes, Plug } from 'lucide-react'
import { cn } from '../ui/lib/utils'

export type Tab = 'credentials' | 'providers' | 'connect' | 'profile'

const items: { id: Tab; label: string; icon: typeof KeyRound }[] = [
  { id: 'credentials', label: 'Credentials', icon: KeyRound },
  { id: 'providers', label: 'Providers', icon: Boxes },
  { id: 'connect', label: 'OAuth Connect', icon: Plug },
]

export function Sidebar({ active, onSelect }: { active: Tab; onSelect: (t: Tab) => void }) {
  return (
    <aside className="hidden w-56 shrink-0 border-r border-border p-3 sm:block">
      <nav className="space-y-1">
        {items.map((it) => (
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
    </aside>
  )
}
