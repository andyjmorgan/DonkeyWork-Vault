import { useId } from 'react'
import { Input } from '../ui/components/input'

/**
 * Editable provider picker — a free-text input with the live catalog as autocomplete
 * suggestions (NOT a fixed enum). Type any provider key; known ones autocomplete.
 */
export function ProviderSelect({ value, onChange, options, placeholder }: {
  value: string
  onChange: (v: string) => void
  options: { key: string; name: string }[]
  placeholder?: string
}) {
  const listId = useId()
  return (
    <>
      <Input
        list={listId}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder ?? 'type or pick a provider'}
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck={false}
      />
      <datalist id={listId}>
        {options.map((o) => <option key={o.key} value={o.key}>{o.name}</option>)}
      </datalist>
    </>
  )
}
