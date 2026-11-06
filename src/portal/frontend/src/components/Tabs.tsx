import { useRef, type KeyboardEvent, type ReactNode } from 'react'
import { cn } from '../lib'

// Underline tabs for splitting one page into views of the same shape (e.g. secrets vs OAuth
// accounts). Hand-rolled rather than Radix: the behaviour is a tablist with roving arrow-key
// focus, which is a dozen lines, and it keeps the dependency graph small.

export type Tab<K extends string> = {
  key: K
  label: string
  count?: number
  icon?: ReactNode
}

export function Tabs<K extends string>({
  tabs,
  value,
  onChange,
  label,
  className,
}: {
  tabs: Tab<K>[]
  value: K
  onChange: (key: K) => void
  label: string
  className?: string
}) {
  const refs = useRef<Map<K, HTMLButtonElement>>(new Map())

  const onKeyDown = (event: KeyboardEvent<HTMLButtonElement>, index: number) => {
    const delta =
      event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : event.key === 'Home' ? -index : event.key === 'End' ? tabs.length - 1 - index : 0
    if (!delta) return
    event.preventDefault()
    const next = tabs[(index + delta + tabs.length) % tabs.length]
    onChange(next.key)
    refs.current.get(next.key)?.focus()
  }

  return (
    <div role="tablist" aria-label={label} className={cn('flex gap-1 border-b border-border', className)}>
      {tabs.map((tab, index) => {
        const active = tab.key === value
        return (
          <button
            key={tab.key}
            ref={(el) => {
              if (el) refs.current.set(tab.key, el)
              else refs.current.delete(tab.key)
            }}
            type="button"
            role="tab"
            id={`tab-${tab.key}`}
            aria-selected={active}
            aria-controls={`panel-${tab.key}`}
            tabIndex={active ? 0 : -1}
            onClick={() => onChange(tab.key)}
            onKeyDown={(event) => onKeyDown(event, index)}
            className={cn(
              '-mb-px inline-flex items-center gap-2 border-b-2 px-3 pb-3 pt-1 text-sm font-medium transition-colors',
              active ? 'border-accent text-foreground' : 'border-transparent text-muted-foreground hover:text-foreground',
            )}
          >
            {tab.icon}
            {tab.label}
            {tab.count !== undefined && (
              <span
                className={cn(
                  'rounded-md px-1.5 py-0.5 font-mono text-[11px] leading-none',
                  active ? 'bg-accent/10 text-accent' : 'bg-elevated text-muted-foreground',
                )}
              >
                {tab.count.toLocaleString()}
              </span>
            )}
          </button>
        )
      })}
    </div>
  )
}

/** The content for one tab; render only the active one so the DOM holds a single panel. */
export function TabPanel({ tabKey, children, className }: { tabKey: string; children: ReactNode; className?: string }) {
  return (
    <div role="tabpanel" id={`panel-${tabKey}`} aria-labelledby={`tab-${tabKey}`} className={className}>
      {children}
    </div>
  )
}
