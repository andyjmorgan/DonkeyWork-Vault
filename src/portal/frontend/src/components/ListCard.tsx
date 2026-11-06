import type { CSSProperties, HTMLAttributes, ReactNode } from 'react'
import { ChevronLeft, ChevronRight, type LucideIcon } from 'lucide-react'
import { Button } from '../ui/components/button'
import { cn } from '../lib'

// The list "table" (after the sandbox): a bordered card whose rows are CSS grids sharing one
// column template. Below the breakpoint each row stacks into a card and cells show their own
// label, so there's one markup path for desktop and mobile rather than a table plus a card list.

type Breakpoint = 'md' | 'lg'

const gridAt: Record<Breakpoint, string> = {
  md: 'md:grid-cols-[var(--cols)]',
  lg: 'lg:grid-cols-[var(--cols)]',
}
const showAt: Record<Breakpoint, string> = { md: 'hidden md:grid', lg: 'hidden lg:grid' }
const hideAt: Record<Breakpoint, string> = { md: 'md:hidden', lg: 'lg:hidden' }
const itemsAt: Record<Breakpoint, string> = { md: 'md:items-center', lg: 'lg:items-center' }

export function ListCard({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('overflow-hidden rounded-2xl border border-border bg-card', className)} {...props} />
}

/** The strip above the header row: a count on the left, filters/search on the right. */
export function ListBar({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('flex flex-wrap items-center justify-between gap-3 border-b border-border px-5 py-3 text-xs text-muted-foreground', className)}
      {...props}
    />
  )
}

export function ListHead({ cols, at = 'md', className, children }: { cols: string; at?: Breakpoint; className?: string; children: ReactNode }) {
  return (
    <div
      style={{ '--cols': cols } as CSSProperties}
      className={cn(
        showAt[at],
        gridAt[at],
        'gap-4 border-b border-border px-5 py-3 text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground',
        className,
      )}
    >
      {children}
    </div>
  )
}

export function ListRows({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('divide-y divide-border', className)} {...props} />
}

export function ListRow({
  cols,
  at = 'md',
  onClick,
  className,
  children,
}: {
  cols: string
  at?: Breakpoint
  onClick?: () => void
  className?: string
  children: ReactNode
}) {
  const interactive = !!onClick
  return (
    <div
      style={{ '--cols': cols } as CSSProperties}
      role={interactive ? 'button' : undefined}
      tabIndex={interactive ? 0 : undefined}
      onClick={onClick}
      onKeyDown={interactive ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onClick() } } : undefined}
      className={cn(
        'grid gap-4 p-5 transition-colors',
        gridAt[at],
        itemsAt[at],
        interactive && 'cursor-pointer hover:bg-elevated/45 focus-visible:bg-elevated/45',
        className,
      )}
    >
      {children}
    </div>
  )
}

/** A cell that shows its column label when the row is stacked. */
export function Cell({ label, at = 'md', className, children }: { label: string; at?: Breakpoint; className?: string; children: ReactNode }) {
  return (
    <div className={cn('min-w-0', className)}>
      <span className={cn('mb-1 block text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground', hideAt[at])}>{label}</span>
      {children}
    </div>
  )
}

/** The actions cell: right-aligned at the breakpoint, left-aligned when stacked. */
export function RowActions({ at = 'md', className, children }: { at?: Breakpoint; className?: string; children: ReactNode }) {
  return (
    <div
      className={cn('flex items-center gap-1', at === 'md' ? 'md:justify-end' : 'lg:justify-end', className)}
      onClick={(e) => e.stopPropagation()}
      onKeyDown={(e) => e.stopPropagation()}
    >
      {children}
    </div>
  )
}

export function ListEmpty({ icon: Icon, title, hint, action }: { icon?: LucideIcon; title: string; hint?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center px-5 py-14 text-center">
      {Icon && (
        <div className="mb-4 grid size-11 place-items-center rounded-2xl bg-elevated text-muted-foreground">
          <Icon className="size-5" />
        </div>
      )}
      <p className="text-sm font-medium">{title}</p>
      {hint && <p className="mt-1 max-w-sm text-xs leading-5 text-muted-foreground">{hint}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function ListPager({
  from,
  to,
  total,
  canPrev,
  canNext,
  busy = false,
  onPrev,
  onNext,
}: {
  from: number
  to: number
  total: number
  canPrev: boolean
  canNext: boolean
  busy?: boolean
  onPrev: () => void
  onNext: () => void
}) {
  return (
    <div className="flex items-center justify-between border-t border-border px-5 py-3">
      <span className="font-mono text-xs text-muted-foreground">
        {total > 0 ? `${from}–${to} of ${total}` : '—'}
      </span>
      <div className="flex items-center gap-1">
        <Button variant="outline" size="iconSm" aria-label="Previous page" disabled={!canPrev || busy} onClick={onPrev}>
          <ChevronLeft />
        </Button>
        <Button variant="outline" size="iconSm" aria-label="Next page" disabled={!canNext || busy} onClick={onNext}>
          <ChevronRight />
        </Button>
      </div>
    </div>
  )
}

/** Name + secondary line, the usual first cell. */
export function Primary({ title, subtitle, mono = false }: { title: ReactNode; subtitle?: ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <div className="truncate text-sm font-medium">{title}</div>
      {subtitle && <div className={cn('mt-0.5 truncate text-xs text-muted-foreground', mono && 'font-mono')}>{subtitle}</div>}
    </div>
  )
}
