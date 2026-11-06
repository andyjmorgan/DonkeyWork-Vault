import * as React from 'react'
import { cn } from '../../lib'

export const inputClassName =
  'flex h-10 w-full rounded-lg border border-border bg-elevated px-3 text-sm text-foreground outline-none transition-[border-color,box-shadow] duration-150 placeholder:text-faint-foreground focus:border-accent focus:ring-[3px] focus:ring-accent/15 read-only:cursor-default disabled:cursor-not-allowed disabled:opacity-50'

const Input = React.forwardRef<HTMLInputElement, React.ComponentProps<'input'>>(({ className, type, ...props }, ref) => (
  <input type={type} className={cn(inputClassName, className)} ref={ref} {...props} />
))
Input.displayName = 'Input'

export { Input }
