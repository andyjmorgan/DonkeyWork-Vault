import type { ReactNode } from 'react'
import { cn } from '../ui/lib/utils'

/**
 * A compact label-over-value pair used in the mobile card layouts (the two-column grids that
 * replace wide tables below the `sm` breakpoint). Truncates by default; pass truncate={false}
 * for wrapping content like scope badges.
 */
export function Field({ label, truncate = true, children }: { label: string; truncate?: boolean; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="text-[10px] font-medium uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className={cn('text-sm', truncate && 'truncate')}>{children}</div>
    </div>
  )
}
