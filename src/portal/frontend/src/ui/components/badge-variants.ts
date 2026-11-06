import { cva } from 'class-variance-authority'

// Small rectangular tags (6px radius per the style guide). Status that needs a pill shape
// goes through StatusPill instead.
export const badgeVariants = cva(
  'inline-flex max-w-full items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium leading-5 transition-colors',
  {
    variants: {
      variant: {
        muted: 'border-border bg-elevated text-muted-foreground',
        outline: 'border-border bg-transparent text-foreground',
        accent: 'border-accent/20 bg-accent/10 text-accent',
        success: 'border-success/20 bg-success/10 text-success',
        warning: 'border-warning/20 bg-warning/10 text-warning',
        danger: 'border-danger/20 bg-danger/10 text-danger',
        info: 'border-info/20 bg-info/10 text-info',
        plum: 'border-plum/20 bg-plum/10 text-plum',
      },
    },
    defaultVariants: {
      variant: 'muted',
    },
  },
)
