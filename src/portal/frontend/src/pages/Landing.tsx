import { Github, BookOpen, LogIn, ArrowRight, Timer, ShieldCheck, Terminal, RefreshCw, Boxes, Zap, Check, Menu } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Button } from '../ui/components/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '../ui/components/dropdown-menu'
import { CopyButton } from '../components/CopyButton'
import { isAuthed, login } from '../auth'

// Brand marks for the testimonial cards. OpenAI rides on currentColor so it
// flips with the theme; Claude keeps its signature clay-orange in both modes.
function OpenAIMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden className={className}>
      <path d="M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.4997-2.6067-1.4997Z" />
    </svg>
  )
}

function ClaudeMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="#D97757" aria-hidden className={className}>
      <path d="m4.7144 15.9555 4.7174-2.6471.079-.2307-.079-.1275h-.2307l-.7893-.0486-2.6956-.0729-2.3375-.0971-2.2646-.1214-.5707-.1215-.5343-.7042.0546-.3522.4797-.3218.686.0608 1.5179.1032 2.2767.1578 1.6514.0972 2.4468.255h.3886l.0546-.1579-.1336-.0971-.1032-.0972L6.973 9.8356l-2.55-1.6879-1.3356-.9714-.7225-.4918-.3643-.4614-.1578-1.0078.6557-.7225.8803.0607.2246.0607.8925.686 1.9064 1.4754 2.4893 1.8336.3643.3035.1457-.1032.0182-.0728-.164-.2733-1.3539-2.4467-1.445-2.4893-.6435-1.032-.17-.6194c-.0607-.255-.1032-.4674-.1032-.7285L6.287.1335 6.6997 0l.9957.1336.419.3642.6192 1.4147 1.0018 2.2282 1.5543 3.0296.4553.8985.2429.8318.091.255h.1579v-.1457l.1275-1.706.2368-2.0947.2307-2.6957.0789-.7589.3764-.9107.7468-.4918.5828.2793.4797.686-.0668.4433-.2853 1.8517-.5586 2.9021-.3643 1.9429h.2125l.2429-.2429.9835-1.3053 1.6514-2.0643.7286-.8196.85-.9046.5464-.4311h1.0321l.759 1.1293-.34 1.1657-1.0625 1.3478-.8804 1.1414-1.2628 1.7-.7893 1.36.0729.1093.1882-.0183 2.8535-.607 1.5421-.2794 1.8396-.3157.8318.3886.091.3946-.3278.8075-1.967.4857-2.3072.4614-3.4364.8136-.0425.0304.0486.0607 1.5482.1457.6618.0364h1.621l3.0175.2247.7892.522.4736.6376-.079.4857-1.2142.6193-1.6393-.3886-3.825-.9107-1.3113-.3279h-.1822v.1093l1.0929 1.0686 2.0035 1.8092 2.5075 2.3314.1275.5768-.3218.4554-.34-.0486-2.2039-1.6575-.85-.7468-1.9246-1.621h-.1275v.17l.4432.6496 2.3436 3.5214.1214 1.0807-.17.3521-.6071.2125-.6679-.1214-1.3721-1.9246L14.38 17.959l-1.1414-1.9428-.1397.079-.674 7.2552-.3156.3703-.7286.2793-.6071-.4614-.3218-.7468.3218-1.4753.3886-1.9246.3157-1.53.2853-1.9004.17-.6314-.0121-.0425-.1397.0182-1.4328 1.9672-2.1796 2.9446-1.7243 1.8456-.4128.164-.7164-.3704.0667-.6618.4008-.5889 2.386-3.0357 1.4389-1.882.929-1.0868-.0062-.1579h-.0546l-6.3385 4.1164-1.1293.1457-.4857-.4554.0608-.7467.2307-.2429 1.9064-1.3114Z" />
    </svg>
  )
}

const testimonials = [
  {
    Mark: OpenAIMark,
    tile: 'bg-foreground/5 text-foreground',
    name: 'OpenAI Codex',
    role: 'on the credential model',
    lead:
      'A solid agent-facing credential model. The strongest part is that credentials are discoverable and self-describing: list for routing, shape for usage metadata, then get/header/oauth only at the point of use — that maps well to how agents actually work and avoids hardcoded secret names or auth conventions.',
    points: [
      'The “secret to stdout only” contract is simple and Unix-friendly.',
      'dwvault skill bundling the live skill with the binary reduces drift between docs and implementation.',
      'Credential kind is useful — it lets an agent distinguish header keys, Basic auth, SSH, DSNs and opaque HMAC secrets.',
    ],
  },
  {
    Mark: ClaudeMark,
    tile: 'bg-[#D97757]/10 text-foreground',
    name: 'Anthropic Claude Code',
    role: 'on the design',
    lead:
      'Genuinely well-designed. The kind discriminator is the key idea: most secret stores hand you an opaque blob and leave “how do I send this?” to tribal knowledge. Encoding kind/header/prefix/username in the credential itself means an agent goes from list → correct curl with zero guessing. That’s the whole ballgame for agent-driven use.',
    points: [
      'Output discipline is enforced by shape, not just docs — get is stdout-only, header assembles the line for you, so the natural path is also the safe path.',
      'OAuth auto-refresh behind oauth token is the right abstraction — the token is the credential, the caller never touches refresh logic.',
      'create as upsert with env-var secrets keeps secrets off the command line and out of shell history.',
    ],
  },
]

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
          {/* full nav — inline on ≥sm, folded into the menu below that */}
          <div className="hidden items-center gap-2 sm:flex">
            <Button variant="ghost" asChild>
              <a href={DOCS} target="_blank" rel="noreferrer"><BookOpen className="size-4" /> Docs</a>
            </Button>
            <Button variant="ghost" size="icon" asChild aria-label="GitHub">
              <a href={REPO} target="_blank" rel="noreferrer"><Github /></a>
            </Button>
            <Button onClick={enter}><LogIn className="size-4" /> {authed ? 'Open app' : 'Log in'}</Button>
          </div>
          {/* mobile-only overflow menu collapsing the whole nav */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild className="sm:hidden">
              <Button variant="ghost" size="icon" aria-label="Menu"><Menu /></Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onSelect={enter}>
                <LogIn className="size-4" /> {authed ? 'Open app' : 'Log in'}
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <a href={DOCS} target="_blank" rel="noreferrer"><BookOpen className="size-4" /> Docs</a>
              </DropdownMenuItem>
              <DropdownMenuItem asChild>
                <a href={REPO} target="_blank" rel="noreferrer"><Github className="size-4" /> GitHub</a>
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
      </header>

      {/* hero */}
      <section className="mx-auto max-w-4xl px-4 pb-10 pt-12 text-center sm:px-6 sm:pt-20">
        <h1 className="text-4xl font-semibold tracking-tight sm:text-6xl">
          The secrets &amp; OAuth broker<br />
          <span className="bg-gradient-to-r from-cyan-500 to-blue-600 bg-clip-text text-transparent">built for agents</span>
        </h1>
        <p className="mx-auto mt-5 max-w-2xl text-balance text-base text-muted-foreground sm:text-lg">
          One vault for your API keys and OAuth connections. Stores them encrypted, hands agents
          short-lived tokens on demand, and refreshes them for you — so credentials never live in skills or code.
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

      {/* testimonials — the agents reviewing the thing built for them */}
      <section className="mx-auto max-w-6xl px-4 pb-20 sm:px-6">
        <div className="mb-8 text-center">
          <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">Don&apos;t take our word for it</h2>
          <p className="mt-2 text-sm text-muted-foreground">We asked the agents that actually use it.</p>
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          {testimonials.map((t) => (
            <figure key={t.name} className="flex flex-col rounded-2xl border border-border bg-card p-6 shadow-sm">
              <figcaption className="flex items-center gap-3">
                <div className={`grid size-11 shrink-0 place-items-center rounded-xl ${t.tile}`}>
                  <t.Mark className="size-6" />
                </div>
                <div className="min-w-0">
                  <div className="font-medium">{t.name}</div>
                  <div className="text-xs text-muted-foreground">{t.role}</div>
                </div>
              </figcaption>
              <blockquote className="mt-4 text-pretty text-sm leading-relaxed text-foreground/90">
                &ldquo;{t.lead}&rdquo;
              </blockquote>
              <ul className="mt-4 space-y-2 border-t border-border pt-4">
                {t.points.map((p) => (
                  <li key={p} className="flex gap-2 text-sm text-muted-foreground">
                    <Check className="mt-0.5 size-4 shrink-0 text-accent" />
                    <span>{p}</span>
                  </li>
                ))}
              </ul>
            </figure>
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
