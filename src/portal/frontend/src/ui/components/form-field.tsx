import * as React from "react"
import { cn } from '../lib/utils'
import { Label } from "./label"

interface FormFieldProps {
  label: string
  description?: string
  htmlFor?: string
  children: React.ReactNode
  className?: string
}

/**
 * A styled form field container with consistent layout:
 * - Label (title)
 * - Input/control
 * - Description (optional)
 *
 * Includes subtle background shading for better visibility in dark mode.
 */
export function FormField({
  label,
  description,
  htmlFor,
  children,
  className
}: FormFieldProps) {
  return (
    <div className={cn(
      "rounded-xl border border-border bg-muted/30 p-4 space-y-2",
      className
    )}>
      <Label htmlFor={htmlFor} className="text-sm font-medium">
        {label}
      </Label>
      <div>
        {children}
      </div>
      {description && (
        <p className="text-xs text-muted-foreground">
          {description}
        </p>
      )}
    </div>
  )
}
