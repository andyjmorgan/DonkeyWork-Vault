import * as React from 'react'
import { type VariantProps } from 'class-variance-authority'
import { cn } from '../../lib'
import { badgeVariants } from './badge-variants'

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {
  /** Render the label in IBM Plex Mono — scopes, prefixes, and other technical tokens. */
  mono?: boolean
}

function Badge({ className, variant, mono, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), mono && 'font-mono', className)} {...props} />
}

export { Badge }
