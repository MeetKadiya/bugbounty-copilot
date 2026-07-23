import type { Secret } from '../types'
import { ShieldAlert } from 'lucide-react'

const severityColor: Record<string, string> = {
  High: 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/30',
  Medium: 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/30',
  Low: 'text-cyber-muted bg-cyber-border/30 border-cyber-border',
}

export default function SecretsPanel({ secrets }: { secrets: Secret[] }) {
  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <ShieldAlert className="text-cyber-warning" size={18} />
        <h2 className="font-semibold text-white">Secrets Panel ({secrets.length})</h2>
      </div>
      {secrets.length === 0 ? (
        <p className="text-sm text-cyber-muted">No exposed secrets detected in crawled JavaScript.</p>
      ) : (
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {secrets.map((s, idx) => (
            <div key={idx} className={`border rounded-lg p-3 text-xs ${severityColor[s.severity]}`}>
              <div className="flex items-center justify-between font-semibold">
                <span>{s.secret_type}</span>
                <span className="text-[10px]">{s.severity}</span>
              </div>
              <div className="font-mono mt-1 text-slate-300 truncate" title={s.source_url}>{s.source_url}</div>
              <div className="font-mono mt-1 opacity-80">{s.match_redacted}</div>
            </div>
          ))}
        </div>
      )}
      <p className="text-[11px] text-cyber-muted mt-3">
        Matches are redacted. Manually confirm and validity-check before reporting through the program's disclosure channel.
      </p>
    </div>
  )
}
