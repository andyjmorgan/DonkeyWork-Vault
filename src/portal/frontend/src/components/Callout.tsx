import type { ReactNode } from 'react'
import { AlertTriangle, Info, ShieldAlert } from 'lucide-react'
import { cn } from '../lib'

const tones = {
  info: { box: 'border-info/20 bg-info/5 text-foreground', icon: 'text-info', Icon: Info },
  warning: { box: 'border-warning/20 bg-warning/5 text-foreground', icon: 'text-warning', Icon: AlertTriangle },
  danger: { box: 'border-danger/20 bg-danger/5 text-foreground', icon: 'text-danger', Icon: ShieldAlert },
}

/** An inline notice with an icon; the icon carries the state so colour isn't the only cue. */
export function Callout({ tone = 'info', children, className }: { tone?: keyof typeof tones; children: ReactNode; className?: string }) {
  const t = tones[tone]
  return (
    <div className={cn('flex gap-3 rounded-xl border p-3 text-sm leading-6', t.box, className)}>
      <t.Icon className={cn('mt-1 size-4 shrink-0', t.icon)} />
      <div className="min-w-0 flex-1">{children}</div>
    </div>
  )
}
