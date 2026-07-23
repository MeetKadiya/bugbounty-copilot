import { useState } from 'react'
import { Search, AlertTriangle, Loader2 } from 'lucide-react'
import { startScan, validateScope } from '../api/client'

interface Props {
  onScanStarted: (scanId: string) => void
}

export default function TargetInput({ onScanStarted }: Props) {
  const [domain, setDomain] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError(null)
    if (!domain.trim()) return

    setLoading(true)
    try {
      await validateScope(domain)
      const scan = await startScan(domain)
      onScanStarted(scan.id)
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? 'Failed to validate or start scan.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-6 card-glow">
      <form onSubmit={handleSubmit} className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-cyber-muted" size={18} />
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com or *.example.com"
            className="w-full bg-cyber-bg border border-cyber-border rounded-lg pl-10 pr-4 py-3 font-mono text-sm
                       focus:outline-none focus:ring-2 focus:ring-cyber-accent/50 focus:border-cyber-accent"
          />
        </div>
        <button
          type="submit"
          disabled={loading}
          className="bg-cyber-accent text-cyber-bg font-semibold px-6 py-3 rounded-lg hover:opacity-90
                     disabled:opacity-50 flex items-center gap-2 justify-center min-w-[160px]"
        >
          {loading ? <Loader2 className="animate-spin" size={18} /> : null}
          {loading ? 'Starting…' : 'Start Recon Scan'}
        </button>
      </form>
      {error && (
        <div className="mt-3 flex items-center gap-2 text-cyber-danger text-sm">
          <AlertTriangle size={16} />
          {error}
        </div>
      )}
      <p className="mt-3 text-xs text-cyber-muted">
        Only scan domains you own or are authorized to test under a bug bounty program. This tool performs
        passive/active reconnaissance and AI triage only — it never exploits anything automatically.
      </p>
    </div>
  )
}
