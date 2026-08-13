import { useEffect, useState } from 'react'
import { Pencil, Plus, Trash2 } from 'lucide-react'
import { api, type AccessKey, type ApiKeyItem, type MCPAuditMessage, type MCPConnection, type MCPGrant, type MCPHeaderBinding, type MCPToolPolicy } from '../api'
import { Badge } from '../ui/components/badge'
import { Button } from '../ui/components/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../ui/components/card'
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '../ui/components/dialog'
import { Input } from '../ui/components/input'
import { Label } from '../ui/components/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '../ui/components/select'
import { Switch } from '../ui/components/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '../ui/components/table'

const lbl = 'mb-1 block text-xs text-muted-foreground'

export function MCPPage() {
  const [connections, setConnections] = useState<MCPConnection[]>([])
  const [editing, setEditing] = useState<Partial<MCPConnection>>()
  const [selected, setSelected] = useState<MCPConnection>()
  const [audit, setAudit] = useState<MCPAuditMessage[]>([])
  const [message, setMessage] = useState<string>()
  const load = () => api.mcpConnections().then((rows) => {
    setConnections(rows)
    if (selected) setSelected(rows.find((row) => row.id === selected.id))
  }).catch((e) => setMessage(String(e)))
  useEffect(() => { load() }, [])
  useEffect(() => {
    if (selected) api.mcpAudit({ connectionId: selected.id, limit: 50 }).then((page) => setAudit(page.items)).catch((e) => setMessage(String(e)))
  }, [selected])

  return (
    <>
      <Card>
        <CardHeader className="flex-row items-center justify-between">
          <div><CardTitle>MCP gateway</CardTitle><CardDescription>Modern stateless MCP connections, access grants, upstream credentials, policy and inspected JSON-RPC messages.</CardDescription></div>
          <Button size="sm" onClick={() => setEditing(blankConnection())}><Plus className="size-4" /> Add connection</Button>
        </CardHeader>
        <CardContent className="space-y-2">
          {message && <p className="text-sm text-destructive">{message}</p>}
          {connections.length === 0 && <p className="text-sm text-muted-foreground">No MCP connections yet.</p>}
          {connections.map((connection) => (
            <div key={connection.id} className="flex items-center justify-between rounded-xl border border-border p-3">
              <button className="min-w-0 text-left" onClick={() => setSelected(connection)}>
                <div className="flex items-center gap-2 font-medium">{connection.name}<Badge variant="secondary">{connection.authMode}</Badge>{!connection.enabled && <Badge variant="destructive">disabled</Badge>}</div>
                <div className="truncate text-xs text-muted-foreground">{connection.upstreamUrl}</div>
                <code className="text-xs text-accent">/api/v1/mcp/proxy/{connection.slug}</code>
              </button>
              <div className="flex gap-1">
                <Button variant="ghost" size="icon" onClick={() => setEditing({ ...connection })}><Pencil className="size-4" /></Button>
                <Button variant="ghost" size="icon" onClick={() => api.deleteMcpConnection(connection.id).then(() => { if (selected?.id === connection.id) setSelected(undefined); load() })}><Trash2 className="size-4 text-destructive" /></Button>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      {selected && <ConnectionDetail connection={selected} audit={audit} onError={(e) => setMessage(String(e))} />}
      {editing && <ConnectionEditor value={editing} onClose={() => setEditing(undefined)} onSaved={() => { setEditing(undefined); load() }} />}
    </>
  )
}

function ConnectionEditor({ value, onClose, onSaved }: { value: Partial<MCPConnection>; onClose: () => void; onSaved: () => void }) {
  const [connection, setConnection] = useState(value)
  const [error, setError] = useState<string>()
  const set = (patch: Partial<MCPConnection>) => setConnection((current) => ({ ...current, ...patch }))
  const save = () => api.saveMcpConnection(connection).then(onSaved).catch((e) => setError(String(e)))
  return (
    <Dialog open onOpenChange={(open) => { if (!open) onClose() }}>
      <DialogContent className="sm:max-w-2xl"><DialogHeader><DialogTitle>{value.id ? 'Edit MCP connection' : 'New MCP connection'}</DialogTitle><DialogDescription>July 2026 Streamable HTTP uses one stateless POST per JSON-RPC message.</DialogDescription></DialogHeader>
        <div className="grid gap-3 sm:grid-cols-2">
          <div><Label className={lbl}>Slug</Label><Input disabled={!!value.id} value={connection.slug || ''} onChange={(e) => set({ slug: e.target.value })} placeholder="datadog" /></div>
          <div><Label className={lbl}>Name</Label><Input value={connection.name || ''} onChange={(e) => set({ name: e.target.value })} placeholder="Datadog" /></div>
          <div className="sm:col-span-2"><Label className={lbl}>Upstream HTTPS endpoint</Label><Input value={connection.upstreamUrl || ''} onChange={(e) => set({ upstreamUrl: e.target.value })} placeholder="https://example.com/mcp" /></div>
          <div><Label className={lbl}>Authentication</Label><Select value={connection.authMode || 'none'} onValueChange={(value) => set({ authMode: value as MCPConnection['authMode'] })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="none">None</SelectItem><SelectItem value="headers">Stored headers</SelectItem><SelectItem value="oauth">OAuth</SelectItem></SelectContent></Select></div>
          <div><Label className={lbl}>Audit payload</Label><Select value={connection.auditMode || 'redacted'} onValueChange={(value) => set({ auditMode: value as MCPConnection['auditMode'] })}><SelectTrigger><SelectValue /></SelectTrigger><SelectContent><SelectItem value="redacted">Redacted JSON</SelectItem><SelectItem value="metadata">Metadata only</SelectItem></SelectContent></Select></div>
          <label className="flex items-center gap-2 text-sm"><Switch checked={connection.enabled ?? true} onCheckedChange={(enabled) => set({ enabled })} /> Enabled</label>
          {error && <p className="text-sm text-destructive sm:col-span-2">{error}</p>}
          <div className="sm:col-span-2"><Button onClick={save} disabled={!connection.slug || !connection.name || !connection.upstreamUrl}>Save</Button></div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

function ConnectionDetail({ connection, audit, onError }: { connection: MCPConnection; audit: MCPAuditMessage[]; onError: (e: unknown) => void }) {
  const [accessKeys, setAccessKeys] = useState<AccessKey[]>([])
  const [credentials, setCredentials] = useState<ApiKeyItem[]>([])
  const [grants, setGrants] = useState<MCPGrant[]>([])
  const [headers, setHeaders] = useState<MCPHeaderBinding[]>([])
  const [policies, setPolicies] = useState<MCPToolPolicy[]>([])
  const [grantKey, setGrantKey] = useState('')
  const [credential, setCredential] = useState('')
  const [headerName, setHeaderName] = useState('')
  const [method, setMethod] = useState('tools/call')
  const [tool, setTool] = useState('')
  const [allow, setAllow] = useState(true)
  const [issuer, setIssuer] = useState('')
  const [clientId, setClientId] = useState('')
  const [clientSecret, setClientSecret] = useState('')
  const [scopes, setScopes] = useState('')
  const load = () => Promise.all([api.accessKeys(), api.apiKeys(), api.mcpGrants(connection.id), api.mcpHeaders(connection.id), api.mcpPolicies(connection.id)])
    .then(([keys, creds, gs, hs, ps]) => { setAccessKeys(keys); setCredentials(creds); setGrants(gs); setHeaders(hs); setPolicies(ps) }).catch(onError)
  useEffect(() => { load() }, [connection.id])
  const keyName = (id: string) => accessKeys.find((key) => key.id === id)?.name || id
  const credentialName = (id: string) => credentials.find((item) => item.id === id)?.name || id
  return (
    <>
      <Card><CardHeader><CardTitle>{connection.name} configuration</CardTitle><CardDescription>Only granted access keys with <code>vault:mcp</code> can invoke this connection.</CardDescription></CardHeader><CardContent className="grid gap-5 lg:grid-cols-3">
        <section className="space-y-2"><h3 className="text-sm font-medium">Access grants</h3><div className="flex gap-2"><Select value={grantKey} onValueChange={setGrantKey}><SelectTrigger><SelectValue placeholder="Access key" /></SelectTrigger><SelectContent>{accessKeys.filter((key) => key.scopes.includes('vault:mcp')).map((key) => <SelectItem key={key.id} value={key.id}>{key.name}</SelectItem>)}</SelectContent></Select><Button size="sm" disabled={!grantKey} onClick={() => api.createMcpGrant(connection.id, grantKey).then(load).catch(onError)}>Grant</Button></div>{grants.map((grant) => <Row key={grant.id} label={keyName(grant.accessKeyId)} onDelete={() => api.deleteMcpGrant(grant.id).then(load).catch(onError)} />)}</section>
        <section className="space-y-2"><h3 className="text-sm font-medium">Upstream headers</h3><Select value={credential} onValueChange={setCredential}><SelectTrigger><SelectValue placeholder="Stored credential" /></SelectTrigger><SelectContent>{credentials.map((item) => <SelectItem key={item.id} value={item.id}>{item.name}</SelectItem>)}</SelectContent></Select><div className="flex gap-2"><Input value={headerName} onChange={(e) => setHeaderName(e.target.value)} placeholder="Override header (optional)" /><Button size="sm" disabled={!credential} onClick={() => api.createMcpHeader(connection.id, credential, headerName || undefined).then(load).catch(onError)}>Bind</Button></div>{headers.map((header) => <Row key={header.id} label={`${header.headerName || '(credential default)'} ← ${credentialName(header.credentialId)}`} onDelete={() => api.deleteMcpHeader(header.id).then(load).catch(onError)} />)}</section>
        <section className="space-y-2"><h3 className="text-sm font-medium">Policy rules</h3><Input value={method} onChange={(e) => setMethod(e.target.value)} placeholder="Method" /><Input value={tool} onChange={(e) => setTool(e.target.value)} placeholder="Tool name (tools/call only)" /><div className="flex items-center gap-2"><Switch checked={allow} onCheckedChange={setAllow} /><span className="text-sm">{allow ? 'Allow' : 'Deny'}</span><Button size="sm" disabled={!method} onClick={() => api.saveMcpPolicy(connection.id, method, tool, allow).then(load).catch(onError)}>Save rule</Button></div>{policies.map((policy) => <Row key={policy.id} label={`${policy.allow ? 'allow' : 'deny'} ${policy.method}${policy.toolName ? `:${policy.toolName}` : ''}`} onDelete={() => api.deleteMcpPolicy(policy.id).then(load).catch(onError)} />)}</section>
        {connection.authMode === 'oauth' && <section className="space-y-2 lg:col-span-3"><h3 className="text-sm font-medium">Upstream OAuth</h3><div className="grid gap-2 sm:grid-cols-2"><Input value={issuer} onChange={(e) => setIssuer(e.target.value)} placeholder="Issuer (optional; discovered when blank)" /><Input value={clientId} onChange={(e) => setClientId(e.target.value)} placeholder="Client ID" /><Input type="password" value={clientSecret} onChange={(e) => setClientSecret(e.target.value)} placeholder="Client secret (optional)" /><Input value={scopes} onChange={(e) => setScopes(e.target.value)} placeholder="Space-separated scopes" /></div><div className="flex gap-2"><Button size="sm" disabled={!clientId} onClick={() => api.configureMcpOAuth(connection.id, { issuer: issuer || undefined, clientId, clientSecret: clientSecret || undefined, scopes: scopes.split(/\s+/).filter(Boolean) }).catch(onError)}>Save OAuth client</Button><Button size="sm" variant="outline" onClick={() => api.connectMcpOAuth(connection.id).then((result) => { window.location.href = result.authorizeUrl }).catch(onError)}>Authorize</Button><Button size="sm" variant="ghost" onClick={() => api.deleteMcpOAuth(connection.id).catch(onError)}>Remove OAuth</Button></div></section>}
      </CardContent></Card>
      <Card><CardHeader><CardTitle>Inspected messages</CardTitle><CardDescription>Latest redacted JSON-RPC audit records for this connection.</CardDescription></CardHeader><CardContent><Table><TableHeader><TableRow><TableHead>Time</TableHead><TableHead>Direction</TableHead><TableHead>Method / tool</TableHead><TableHead>Decision</TableHead><TableHead>Payload</TableHead></TableRow></TableHeader><TableBody>{audit.map((message) => <TableRow key={message.id}><TableCell className="whitespace-nowrap text-xs">{new Date(message.observedAt).toLocaleString()}</TableCell><TableCell><Badge variant="secondary">{message.direction}</Badge></TableCell><TableCell><code className="text-xs">{message.method || message.messageKind}{message.toolName ? `:${message.toolName}` : ''}</code></TableCell><TableCell>{message.policyDecision}</TableCell><TableCell><pre className="max-h-32 max-w-xl overflow-auto whitespace-pre-wrap text-xs">{message.payloadRedacted || '(metadata only)'}</pre></TableCell></TableRow>)}</TableBody></Table></CardContent></Card>
    </>
  )
}

function Row({ label, onDelete }: { label: string; onDelete: () => void }) { return <div className="flex items-center justify-between rounded-lg border border-border px-2 py-1 text-xs"><span className="truncate">{label}</span><Button variant="ghost" size="icon" onClick={onDelete}><Trash2 className="size-3.5 text-destructive" /></Button></div> }
const blankConnection = (): Partial<MCPConnection> => ({ slug: '', name: '', upstreamUrl: '', authMode: 'none', auditMode: 'redacted', enabled: true })
