import type { TakeoverCandidate } from '../types'
import { AlertOctagon } from 'lucide-react'

const confidenceStyle: Record<string, string> = {
  High: 'border-cyber-danger/40 bg-cyber-danger/10 text-cyber-danger',
  Medium: 'border-cyber-warning/40 bg-cyber-warning/10 text-cyber-warning',
  Low: 'border-cyber-border bg-cyber-border/20 text-cyber-muted',
}

export default function TakeoverPanel({ candidates }: { candidates: TakeoverCandidate[] }) {
  if (candidates.length === 0) return null

  return (
    <div className="bg-cyber-panel border border-cyber-danger/40 rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <AlertOctagon className="text-cyber-danger" size={18} />
        <h2 className="font-semibold text-white">
          Potential Subdomain Takeovers ({candidates.length})
        </h2>
      </div>
      <div className="grid sm:grid-cols-2 gap-3">
        {candidates.map((tc, idx) => (
          <div key={idx} className={`border rounded-lg p-3 text-xs ${confidenceStyle[tc.confidence]}`}>
            <div className="flex items-center justify-between font-semibold">
              <span className="font-mono">{tc.hostname}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-black/20">{tc.confidence}</span>
            </div>
            <div className="mt-1 text-slate-300">{tc.service}</div>
            <div className="font-mono mt-1 text-slate-400 truncate" title={tc.cname}>→ {tc.cname}</div>
            <div className="mt-1 opacity-80">{tc.evidence}</div>
          </div>
        ))}
      </div>
      <p className="text-[11px] text-cyber-muted mt-3">
        Passive DNS/HTTP signal only — no cloud resource was claimed or modified. Manually confirm
        before doing anything, and report through the program's disclosure channel.
      </p>
    </div>
  )
}
