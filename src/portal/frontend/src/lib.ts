import { clsx, type ClassValue } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { format, formatDistanceToNowStrict, isValid } from 'date-fns'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

/** "3 minutes ago" / "in 2 hours" for a timestamp, or an em dash when it's missing. */
export function relativeTime(value?: string | null): string {
  if (!value) return '—'
  const d = new Date(value)
  if (!isValid(d)) return '—'
  return formatDistanceToNowStrict(d, { addSuffix: true })
}

/** A compact absolute timestamp for monospace cells and tooltips. */
export function absoluteTime(value?: string | null): string {
  if (!value) return '—'
  const d = new Date(value)
  return isValid(d) ? format(d, 'yyyy-MM-dd HH:mm:ss') : '—'
}

/** Initials for an avatar: two letters from the name, else the first letter of the email. */
export function initials(name?: string | null, email?: string | null): string {
  if (name?.trim()) {
    return name
      .trim()
      .split(/\s+/)
      .map((part) => part[0])
      .join('')
      .toUpperCase()
      .slice(0, 2)
  }
  return email?.slice(0, 1).toUpperCase() ?? 'U'
}
