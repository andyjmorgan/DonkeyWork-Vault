import { useEffect, useState } from 'react'
import { api, type ApiKeyItem, type Me, type Provider } from './api'
import { keycloak } from './keycloak'

type Tab = 'dashboard' | 'providers' | 'add'

const btn = 'rounded-xl px-3 py-1.5 text-sm font-medium transition-all duration-200'
const card = 'rounded-2xl border border-border bg-card p-5'

export function App() {
  const [tab, setTab] = useState<Tab>('dashboard')
  const [me, setMe] = useState<Me | null>(null)

  useEffect(() => {
    api.me().then(setMe).catch(() => {})
  }, [])

  return (
    <div className="mx-auto max-w-4xl p-4 sm:p-8 space-y-6">
      <header className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">
          DonkeyWork <span className="text-accent">Vault</span>
        </h1>
        <button className={`${btn} text-muted hover:text-white`} onClick={() => keycloak.logout()}>
          Sign out
        </button>
      </header>

      <nav className="flex gap-1 border-b border-border pb-2 text-sm">
        {(['dashboard', 'providers', 'add'] as Tab[]).map((t) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`${btn} ${tab === t ? 'text-accent' : 'text-muted hover:text-white'}`}
          >
            {t === 'dashboard' ? 'API Keys' : t === 'providers' ? 'Providers' : 'Add Key'}
          </button>
        ))}
      </nav>

      {tab === 'dashboard' && <Dashboard />}
      {tab === 'providers' && <Providers />}
      {tab === 'add' && <AddKey onDone={() => setTab('dashboard')} />}

      {me && (
        <footer className="pt-4 text-xs text-muted">
          {me.name || me.email} · userId {me.userId} · tenantId {me.tenantId || '(default)'}
        </footer>
      )}
    </div>
  )
}

function Dashboard() {
  const [keys, setKeys] = useState<ApiKeyItem[] | null>(null)
  const [err, setErr] = useState<string>()

  const load = () => api.apiKeys().then(setKeys).catch((e) => setErr(String(e)))
  useEffect(() => { load() }, [])

  return (
    <div className={card}>
      <h2 className="mb-3 text-lg font-semibold">Your API keys</h2>
      {err && <p className="text-sm text-red-400">{err}</p>}
      {!keys && !err && <p className="text-sm text-muted">Loading…</p>}
      {keys && keys.length === 0 && <p className="text-sm text-muted">No keys yet. Add one from the “Add Key” tab.</p>}
      {keys && keys.length > 0 && (
        <table className="w-full text-sm">
          <thead className="text-left text-muted">
            <tr><th className="py-1">Provider</th><th>Name</th><th>Created</th><th></th></tr>
          </thead>
          <tbody>
            {keys.map((k) => (
              <tr key={k.id} className="border-t border-border">
                <td className="py-2">{k.provider}</td>
                <td>{k.name}</td>
                <td className="text-muted">{new Date(k.createdAt).toLocaleString()}</td>
                <td className="text-right">
                  <button
                    className={`${btn} text-red-400 hover:text-red-300`}
                    onClick={() => api.deleteApiKey(k.id).then(load)}
                  >
                    Delete
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

function Providers() {
  const [providers, setProviders] = useState<Provider[] | null>(null)
  useEffect(() => { api.providers().then(setProviders).catch(() => setProviders([])) }, [])
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      {(providers || []).map((p) => (
        <div key={p.key} className={card}>
          <div className="flex items-center justify-between">
            <span className="font-semibold">{p.name}</span>
            <span className="text-xs text-muted">{p.key}</span>
          </div>
          <p className="mt-2 text-xs text-muted">
            {p.authScheme} · {p.header}{p.prefix ? ` · “${p.prefix}”` : ''}
          </p>
          <p className="mt-1 text-xs text-muted">
            fields: {p.fields.map((f) => f.name).join(', ')}
          </p>
        </div>
      ))}
    </div>
  )
}

function AddKey({ onDone }: { onDone: () => void }) {
  const [providers, setProviders] = useState<Provider[]>([])
  const [provider, setProvider] = useState('')
  const [name, setName] = useState('')
  const [values, setValues] = useState<Record<string, string>>({})
  const [err, setErr] = useState<string>()
  const [busy, setBusy] = useState(false)

  useEffect(() => { api.providers().then((p) => { setProviders(p); if (p[0]) setProvider(p[0].key) }) }, [])
  const current = providers.find((p) => p.key === provider)

  const submit = async () => {
    setErr(undefined); setBusy(true)
    try {
      await api.createApiKey(provider, name || 'default', values)
      onDone()
    } catch (e) { setErr(String(e)) } finally { setBusy(false) }
  }

  const input = 'w-full rounded-xl border border-border bg-background px-3 py-2 text-sm outline-none focus:border-accent'

  return (
    <div className={`${card} space-y-4 max-w-lg`}>
      <h2 className="text-lg font-semibold">Add an API key</h2>
      <div>
        <label className="mb-1 block text-xs text-muted">Provider</label>
        <select className={input} value={provider} onChange={(e) => { setProvider(e.target.value); setValues({}) }}>
          {providers.map((p) => <option key={p.key} value={p.key}>{p.name}</option>)}
        </select>
      </div>
      <div>
        <label className="mb-1 block text-xs text-muted">Name</label>
        <input className={input} value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. prod" />
      </div>
      {current?.fields.map((f) => (
        <div key={f.name}>
          <label className="mb-1 block text-xs text-muted">{f.label || f.name}{f.required ? ' *' : ''}</label>
          <input
            className={input}
            type={f.secret ? 'password' : 'text'}
            value={values[f.name] || ''}
            onChange={(e) => setValues({ ...values, [f.name]: e.target.value })}
          />
        </div>
      ))}
      {err && <p className="text-sm text-red-400">{err}</p>}
      <button
        disabled={busy}
        onClick={submit}
        className={`${btn} bg-gradient-to-r from-cyan-500 to-blue-600 text-white disabled:opacity-50`}
      >
        {busy ? 'Saving…' : 'Save key'}
      </button>
    </div>
  )
}
