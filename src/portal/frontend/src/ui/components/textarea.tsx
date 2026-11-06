import * as React from 'react'
import { cn } from '../../lib'
import { inputClassName } from './input'

const Textarea = React.forwardRef<HTMLTextAreaElement, React.ComponentProps<'textarea'>>(({ className, ...props }, ref) => (
  <textarea className={cn(inputClassName, 'h-auto min-h-20 resize-y py-2 leading-6', className)} ref={ref} {...props} />
))
Textarea.displayName = 'Textarea'

export { Textarea }
