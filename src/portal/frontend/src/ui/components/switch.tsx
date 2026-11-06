import * as React from 'react'
import * as SwitchPrimitives from '@radix-ui/react-switch'
import { cn } from '../../lib'

const Switch = React.forwardRef<
  React.ElementRef<typeof SwitchPrimitives.Root>,
  React.ComponentPropsWithoutRef<typeof SwitchPrimitives.Root>
>(({ className, ...props }, ref) => (
  <SwitchPrimitives.Root
    className={cn(
      'peer inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border border-border bg-elevated transition-all duration-200 disabled:cursor-not-allowed disabled:opacity-50 data-[state=checked]:border-accent/60 data-[state=checked]:bg-accent/25',
      className,
    )}
    {...props}
    ref={ref}
  >
    <SwitchPrimitives.Thumb className="pointer-events-none block size-3.5 translate-x-0.5 rounded-full bg-muted-foreground transition-all duration-200 data-[state=checked]:translate-x-[18px] data-[state=checked]:bg-accent" />
  </SwitchPrimitives.Root>
))
Switch.displayName = SwitchPrimitives.Root.displayName

export { Switch }
