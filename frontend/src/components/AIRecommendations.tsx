import { useState } from 'react'
import type { Finding } from '../types'
import { Sparkles, ChevronDown, ChevronUp } from 'lucide-react'

const confidenceColor: Record<string, string> = {
  High: 'border-l-cyber-danger',
  Medium: 'border-l-cyber-warning',
  Low: 'border-l-cyber-muted',
}

export default function AIRecommendations({ findings }: { findings: Finding[] }) {
  const [expanded, setExpanded] = useState<number | null>(0)
  const sorted = [...findings].sort((a, b) => {
    const order = { High: 0, Medium: 1, Low: 2 }
    return order[a.confidence] - order[b.confidence]
  })

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5">
      <div className="flex items-center gap-2 mb-3">
        <Sparkles className="text-cyber-accent" size={18} />
        <h2 className="font-semibold text-white">AI Recommendations ({findings.length})</h2>
      </div>
      {sorted.length === 0 ? (
        <p className="text-sm text-cyber-muted">No plausible vulnerability classes flagged from current evidence.</p>
      ) : (
        <div className="space-y-2">
          {sorted.map((f, idx) => (
            <div key={idx} className={`border-l-4 ${confidenceColor[f.confidence]} bg-cyber-bg rounded-r-lg`}>
              <button
                onClick={() => setExpanded(expanded === idx ? null : idx)}
                className="w-full flex items-center justify-between px-4 py-2.5 text-left"
              >
                <div className="flex items-center gap-3">
                  <span className="font-semibold text-sm text-white">{f.vulnerability_class}</span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyber-border text-cyber-muted">{f.confidence}</span>
                </div>
                {expanded === idx ? <ChevronUp size={16} className="text-cyber-muted" /> : <ChevronDown size={16} className="text-cyber-muted" />}
              </button>
              {expanded === idx && (
                <div className="px-4 pb-3 text-xs text-slate-300 space-y-1.5">
                  <div className="font-mono text-cyber-accent truncate" title={f.related_asset}>{f.related_asset}</div>
                  <div><span className="text-cyber-muted">Why:</span> {f.reasoning}</div>
                  <div><span className="text-cyber-muted">Next step (manual, non-destructive):</span> {f.recommended_next_step}</div>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
