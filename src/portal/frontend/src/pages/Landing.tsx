import { Github, BookOpen, LogIn, ArrowRight, Timer, ShieldCheck, Terminal, RefreshCw, Boxes, Zap } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Button } from '../ui/components/button'
import { CopyButton } from '../components/CopyButton'
import { isAuthed, login } from '../auth'

const REPO = 'https://github.com/andyjmorgan/DonkeyWork-Vault'
const DOCS = 'https://andyjmorgan.github.io/DonkeyWork-Vault/'
const INSTALL = 'curl -fsSL https://raw.githubusercontent.com/andyjmorgan/DonkeyWork-Vault/main/install.sh | sh'

const features = [
  {
    icon: Timer,
    title: 'Short-lived tokens',
    body: 'Access tokens are minted short-lived and refreshed server-side automatically. Client secrets are envelope-encrypted at rest and write-only — never readable back out.',
  },
  {
    icon: ShieldCheck,
    title: 'Agents use it responsibly',
    body: 'Ships an agent skill that enforces safe usage: secrets are consumed via shell substitution, never echoed to a transcript, logged, or committed.',
  },
  {
    icon: Terminal,
    title: 'Skill from the binary',
    body: 'dwvault skill prints the agent skill straight from the CLI — drop it into any agent and it always matches your installed version.',
  },
  {
    icon: RefreshCw,
    title: 'Auto-updating',
    body: 'dwvault update keeps the CLI current — a single checksum-verified binary, no package manager required.',
  },
  {
    icon: Boxes,
    title: 'Custom OAuth providers',
    body: 'Built-in templates for Google, Microsoft, GitHub and Dropbox — or add any OIDC provider straight from its discovery URL.',
  },
  {
    icon: Zap,
    title: 'Dead easy',
    body: 'One-line install, OIDC login, done. Self-hosted, vendor-neutral, and entirely yours.',
  },
]

export function LandingPage() {
  const navigate = useNavigate()
  const authed = isAuthed()
  const enter = () => (authed ? navigate('/credentials') : login('/credentials'))

  return (
    <div className="min-h-full bg-background text-foreground">
      {/* top bar */}
      <header className="mx-auto flex max-w-6xl items-center justify-between px-4 py-4 sm:px-6">
        <div className="flex items-center gap-2 font-semibold">
          <img src="/donkeywork.png" alt="DonkeyWork" className="h-8 w-8" />
          <span>DonkeyWork <span className="text-accent">Vault</span></span>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" asChild>
            <a href={DOCS} target="_blank" rel="noreferrer"><BookOpen className="size-4" /> Docs</a>
          </Button>
          <Button variant="ghost" size="icon" asChild aria-label="GitHub">
            <a href={REPO} target="_blank" rel="noreferrer"><Github /></a>
          </Button>
          <Button onClick={enter}><LogIn className="size-4" /> {authed ? 'Open app' : 'Log in'}</Button>
        </div>
      </header>

      {/* hero */}
      <section className="mx-auto max-w-4xl px-4 pb-10 pt-12 text-center sm:px-6 sm:pt-20">
        <span className="inline-flex items-center gap-1.5 rounded-full border border-border bg-card px-3 py-1 text-xs text-muted-foreground">
          Self-hosted · envelope-encrypted · vendor-neutral
        </span>
        <h1 className="mt-6 text-4xl font-semibold tracking-tight sm:text-6xl">
          The secrets &amp; OAuth broker<br />
          <span className="bg-gradient-to-r from-cyan-500 to-blue-600 bg-clip-text text-transparent">built for agents</span>
        </h1>
        <p className="mx-auto mt-5 max-w-2xl text-balance text-base text-muted-foreground sm:text-lg">
          One vault for your API keys and OAuth connections. Stores them encrypted, hands agents
          short-lived tokens on demand, and refreshes them for you — so credentials never live in code.
        </p>

        {/* install command — front and center */}
        <div className="mx-auto mt-8 flex max-w-2xl items-center gap-2 rounded-2xl border border-border bg-card p-2 pl-4 text-left shadow-sm">
          <span className="select-none text-accent">$</span>
          <code className="min-w-0 flex-1 truncate font-mono text-sm">{INSTALL}</code>
          <CopyButton value={INSTALL} />
        </div>
        <p className="mt-2 text-xs text-muted-foreground">Installs the <code className="text-accent">dwvault</code> CLI — verified against published checksums.</p>

        <div className="mt-8 flex flex-wrap items-center justify-center gap-3">
          <Button size="lg" onClick={enter}>{authed ? 'Open the app' : 'Log in'} <ArrowRight className="size-4" /></Button>
          <Button size="lg" variant="outline" asChild>
            <a href={DOCS} target="_blank" rel="noreferrer"><BookOpen className="size-4" /> Read the docs</a>
          </Button>
          <Button size="lg" variant="outline" asChild>
            <a href={REPO} target="_blank" rel="noreferrer"><Github className="size-4" /> View on GitHub</a>
          </Button>
        </div>
      </section>

      {/* features */}
      <section className="mx-auto max-w-6xl px-4 pb-20 sm:px-6">
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((f) => (
            <div key={f.title} className="rounded-2xl border border-border bg-card p-5 shadow-sm transition-all duration-200 hover:border-accent/50">
              <div className="flex size-10 items-center justify-center rounded-xl bg-accent/10 text-accent">
                <f.icon className="size-5" />
              </div>
              <h3 className="mt-4 font-medium">{f.title}</h3>
              <p className="mt-1.5 text-sm text-muted-foreground">{f.body}</p>
            </div>
          ))}
        </div>
      </section>

      <footer className="border-t border-border">
        <div className="mx-auto flex max-w-6xl flex-col items-center justify-between gap-2 px-4 py-6 text-xs text-muted-foreground sm:flex-row sm:px-6">
          <div className="text-center sm:text-left">
            <div>DonkeyWork Vault — self-hosted secrets &amp; OAuth for agents.</div>
            <div className="mt-1 text-[11px] text-muted-foreground/75">Fueled by caffeine and token spending addictions.</div>
          </div>
          <div className="flex items-center gap-4">
            <a href={DOCS} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-foreground"><BookOpen className="size-3.5" /> Documentation</a>
            <a href={REPO} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-foreground"><Github className="size-3.5" /> andyjmorgan/DonkeyWork-Vault</a>
          </div>
        </div>
      </footer>
    </div>
  )
}
