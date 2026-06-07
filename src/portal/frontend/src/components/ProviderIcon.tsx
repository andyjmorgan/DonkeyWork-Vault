import { useState } from 'react'
import { cn } from '../ui/lib/utils'

export function ProviderIcon({ src, name, className }: { src?: string; name: string; className?: string }) {
  const [err, setErr] = useState(false)
  const size = className ?? 'size-9'
  if (!src || err) {
    return (
      <div className={cn('grid shrink-0 place-items-center rounded-lg bg-muted text-sm font-semibold text-muted-foreground', size)}>
        {(name || '?').charAt(0).toUpperCase()}
      </div>
    )
  }
  return (
    <div className={cn('grid shrink-0 place-items-center overflow-hidden rounded-lg bg-white', size)}>
      <img src={src} alt={name} className="size-2/3 object-contain" onError={() => setErr(true)} />
    </div>
  )
}
