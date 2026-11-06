import type { ReactNode } from 'react'
import { Label } from '../ui/components/label'
import { cn } from '../lib'

/** Label over control, with an optional hint line underneath. */
export function FormField({
  label,
  required,
  hint,
  className,
  children,
}: {
  label: string
  required?: boolean
  hint?: ReactNode
  className?: string
  children: ReactNode
}) {
  return (
    <div className={cn('space-y-1.5', className)}>
      <Label>
        {label}
        {required && <span className="ml-0.5 text-danger">*</span>}
      </Label>
      {children}
      {hint && <p className="text-xs leading-5 text-faint-foreground">{hint}</p>}
    </div>
  )
}

/** A section heading inside a long form — mono-ish uppercase tracking like the list headers. */
export function FormSection({ title, actions, children }: { title: string; actions?: ReactNode; children: ReactNode }) {
  return (
    <section className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-[10px] font-semibold uppercase tracking-[0.16em] text-muted-foreground">{title}</h3>
        {actions}
      </div>
      {children}
    </section>
  )
}
