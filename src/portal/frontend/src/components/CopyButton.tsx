import { useState } from 'react'
import { Copy, Check } from 'lucide-react'
import { Button } from '../ui/components/button'
import { cn } from '../ui/lib/utils'

export function CopyButton({ value, className }: { value: string; className?: string }) {
  const [done, setDone] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value)
      setDone(true)
      setTimeout(() => setDone(false), 1500)
    } catch { /* clipboard unavailable */ }
  }
  return (
    <Button type="button" variant="ghost" size="icon" aria-label="Copy" onClick={copy} className={cn('size-7', className)}>
      {done ? <Check className="size-4 text-success" /> : <Copy className="size-4" />}
    </Button>
  )
}
