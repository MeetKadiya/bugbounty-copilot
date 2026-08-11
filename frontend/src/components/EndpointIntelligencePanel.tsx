import { useEffect, useMemo, useState } from 'react'
import { Radar } from 'lucide-react'
import { getEndpointIntelligence } from '../api/client'
import type { EndpointIntelligence } from '../types'

interface Props {
  scanId: string
  ready: boolean
}

const riskColor: Record<string, string> = {
  High: 'text-cyber-danger bg-cyber-danger/10 border-cyber-danger/30',
  Medium: 'text-cyber-warning bg-cyber-warning/10 border-cyber-warning/30',
  Low: 'text-cyber-muted bg-cyber-border/30 border-cyber-border',
}

const CONCERN_LABELS: { key: keyof EndpointIntelligence; label: string; value: string }[] = [
  { key: 'potential_bola', label: 'BOLA / IDOR review', value: 'bola' },
  { key: 'potential_broken_function_auth', label: 'Broken function-level auth', value: 'broken_function_auth' },
  { key: 'potential_excessive_data_exposure', label: 'Excessive data exposure', value: 'excessive_data_exposure' },
  { key: 'potential_ssrf', label: 'SSRF-related input', value: 'ssrf' },
  { key: 'potential_open_redirect', label: 'Open redirect', value: 'open_redirect' },
  { key: 'potential_mass_assignment', label: 'Mass assignment', value: 'mass_assignment' },
  { key: 'potential_file_upload', label: 'File upload surface', value: 'file_upload' },
  { key: 'potential_debug_internal', label: 'Debug/internal surface', value: 'debug_internal' },
]

export default function EndpointIntelligencePanel({ scanId, ready }: Props) {
  const [records, setRecords] = useState<EndpointIntelligence[]>([])
  const [loading, setLoading] = useState(false)
  const [hostname, setHostname] = useState('')
  const [method, setMethod] = useState('')
  const [risk, setRisk] = useState('')
  const [vulnClass, setVulnClass] = useState('')
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => {
    if (!ready) return
    setLoading(true)
    getEndpointIntelligence(scanId, {
      hostname: hostname || undefined,
      method: method || undefined,
      risk: risk || undefined,
      vulnerability_class: vulnClass || undefined,
    })
      .then(setRecords)
      .finally(() => setLoading(false))
  }, [scanId, ready, hostname, method, risk, vulnClass])

  const hostnames = useMemo(
    () => Array.from(new Set(records.map((r) => r.hostname))).sort(),
    [records],
  )

  if (!ready) return null

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
        <div className="flex items-center gap-2">
          <Radar size={18} className="text-cyber-accent" />
          <h2 className="font-semibold text-white">Endpoint Intelligence ({records.length})</h2>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <select
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            className="bg-cyber-bg border border-cyber-border rounded px-2 py-1 text-xs font-mono"
          >
            <option value="">All hosts</option>
            {hostnames.map((h) => (
              <option key={h} value={h}>{h}</option>
            ))}
          </select>
          <select
            value={method}
            onChange={(e) => setMethod(e.target.value)}
            className="bg-cyber-bg border border-cyber-border rounded px-2 py-1 text-xs font-mono"
          >
            <option value="">All methods</option>
            {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => (
              <option key={m} value={m}>{m}</option>
            ))}
          </select>
          <select
            value={risk}
            onChange={(e) => setRisk(e.target.value)}
            className="bg-cyber-bg border border-cyber-border rounded px-2 py-1 text-xs font-mono"
          >
            <option value="">All risk levels</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>
          <select
            value={vulnClass}
            onChange={(e) => setVulnClass(e.target.value)}
            className="bg-cyber-bg border border-cyber-border rounded px-2 py-1 text-xs font-mono"
          >
            <option value="">All concerns</option>
            {CONCERN_LABELS.map((c) => (
              <option key={c.value} value={c.value}>{c.label}</option>
            ))}
          </select>
        </div>
      </div>

      {loading && <p className="text-xs text-cyber-muted">Analyzing endpoints…</p>}

      {!loading && records.length === 0 && (
        <p className="text-sm text-cyber-muted py-4 text-center">
          No endpoint intelligence matches the current filters.
        </p>
      )}

      {!loading && records.length > 0 && (
        <div className="space-y-2 max-h-[32rem] overflow-auto">
          {records.map((r) => {
            const id = r.id
            const isOpen = expanded === id
            const concerns = CONCERN_LABELS.filter((c) => Boolean(r[c.key]))
            return (
              <div key={id} className="border border-cyber-border/60 rounded-lg overflow-hidden">
                <button
                  onClick={() => setExpanded(isOpen ? null : id)}
                  className="w-full text-left p-3 hover:bg-cyber-border/20 transition-colors"
                >
                  <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-cyber-accent2/20 text-cyber-accent2">
                      {r.method}
                    </span>
                    <span className="text-slate-300 truncate">{r.normalized_path}</span>
                    <span className="text-cyber-muted">· {r.hostname}</span>
                    <span className={`ml-auto px-1.5 py-0.5 rounded border text-[10px] font-semibold ${riskColor[r.risk_level]}`}>
                      {r.risk_level} risk
                    </span>
                    <span className="text-cyber-muted text-[10px]">{r.confidence_score}% confidence</span>
                  </div>
                  <div className="flex items-center gap-1.5 flex-wrap mt-1.5">
                    {r.endpoint_categories?.map((cat) => (
                      <span key={cat} className="text-[10px] px-1.5 py-0.5 rounded bg-cyber-border/40 text-cyber-muted">
                        {cat}
                      </span>
                    ))}
                  </div>
                  {concerns.length > 0 && (
                    <div className="flex items-center gap-1.5 flex-wrap mt-1.5">
                      {concerns.map((c) => (
                        <span key={c.value} className="text-[10px] px-1.5 py-0.5 rounded bg-cyber-danger/10 text-cyber-danger border border-cyber-danger/30">
                          {c.label}
                        </span>
                      ))}
                    </div>
                  )}
                </button>

                {isOpen && (
                  <div className="p-3 border-t border-cyber-border/60 bg-cyber-bg/40 text-xs space-y-2">
                    <div>
                      <span className="text-cyber-muted">Example URL: </span>
                      <span className="font-mono text-slate-300 break-all">{r.url}</span>
                    </div>
                    <div>
                      <span className="text-cyber-muted">API classification: </span>
                      <span className="text-slate-300">{r.api_classification}</span>
                    </div>
                    {r.path_parameters && r.path_parameters.length > 0 && (
                      <div>
                        <span className="text-cyber-muted">Path parameters: </span>
                        <span className="font-mono text-slate-300">
                          {r.path_parameters.map((p) => `${p.placeholder} (${p.kind}, e.g. ${p.example_value})`).join(', ')}
                        </span>
                      </div>
                    )}
                    {r.query_parameters && r.query_parameters.length > 0 && (
                      <div>
                        <span className="text-cyber-muted">Query parameters: </span>
                        <span className="font-mono text-slate-300">{r.query_parameters.join(', ')}</span>
                      </div>
                    )}
                    {r.interesting_parameters && r.interesting_parameters.length > 0 && (
                      <div>
                        <span className="text-cyber-muted">Interesting parameters:</span>
                        <div className="mt-1 space-y-1">
                          {r.interesting_parameters.map((ip) => (
                            <div key={ip.name} className="font-mono text-slate-300">
                              {ip.name} — <span className="text-cyber-warning">{ip.sensitivity}</span> ({ip.categories.join(', ')})
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {r.occurrence_count > 1 && (
                      <div className="text-cyber-muted">
                        Normalized from {r.occurrence_count} discovered URLs matching this pattern.
                      </div>
                    )}
                    {r.reasons && r.reasons.length > 0 && (
                      <div>
                        <span className="text-cyber-muted">Reason:</span>
                        <ul className="list-disc list-inside mt-1 text-slate-300 space-y-0.5">
                          {r.reasons.map((reason, idx) => (
                            <li key={idx}>{reason}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}

      <p className="text-[11px] text-cyber-muted mt-3">
        All categories and concerns are heuristics for manual review, not confirmed vulnerabilities.
        No requests beyond normal recon were made to generate this analysis.
      </p>
    </div>
  )
}
