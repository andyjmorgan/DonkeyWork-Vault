import { Circle } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '../lib'

export type Tone = 'success' | 'warning' | 'danger' | 'info' | 'accent' | 'muted'

const tones: Record<Tone, string> = {
  success: 'border-success/20 bg-success/10 text-success',
  warning: 'border-warning/20 bg-warning/10 text-warning',
  danger: 'border-danger/20 bg-danger/10 text-danger',
  info: 'border-info/20 bg-info/10 text-info',
  accent: 'border-accent/20 bg-accent/10 text-accent',
  muted: 'border-border bg-elevated text-muted-foreground',
}

/** A state pill: a dot plus a label, so the state never relies on colour alone. */
export function StatusPill({ tone, children, className }: { tone: Tone; children: ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-1 text-xs font-semibold',
        tones[tone],
        className,
      )}
    >
      <Circle className="size-1.5 fill-current" />
      {children}
    </span>
  )
}
