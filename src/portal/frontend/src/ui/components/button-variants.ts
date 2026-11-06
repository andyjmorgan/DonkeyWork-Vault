import { cva } from 'class-variance-authority'

// Brand buttons: a flat Sage primary (no gradients — those belong to the mark), bordered
// secondary/outline, quiet ghost, and a tinted danger. Radius matches the sandbox (12px).
export const buttonVariants = cva(
  'inline-flex cursor-pointer items-center justify-center gap-2 whitespace-nowrap rounded-xl text-sm font-semibold transition-all duration-200 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg]:size-4 [&_svg]:shrink-0',
  {
    variants: {
      variant: {
        primary: 'bg-accent text-on-accent shadow-sm hover:bg-accent-strong',
        secondary: 'border border-border bg-card text-foreground shadow-sm hover:border-accent/30 hover:bg-elevated',
        outline: 'border border-border bg-transparent text-foreground hover:bg-elevated',
        ghost: 'text-muted-foreground hover:bg-elevated hover:text-foreground',
        danger: 'border border-danger/20 bg-danger/10 text-danger hover:bg-danger/20',
        link: 'h-auto rounded-none p-0 font-medium text-foreground underline decoration-accent underline-offset-[3px] hover:text-accent',
      },
      size: {
        default: 'h-10 px-4',
        sm: 'h-8 rounded-lg px-3 text-xs',
        lg: 'h-11 px-6',
        icon: 'size-9 px-0',
        iconSm: 'size-8 rounded-lg px-0',
      },
    },
    defaultVariants: {
      variant: 'secondary',
      size: 'default',
    },
  },
)
