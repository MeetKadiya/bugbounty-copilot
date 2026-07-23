import { useEffect, useMemo, useState } from 'react'
import { GitCompare, TrendingDown, TrendingUp } from 'lucide-react'
import { getScanDiff, getScanHistory } from '../api/client'
import type { ScanDiff, ScanHistory } from '../types'

interface Props {
  targetId: string
  currentScanId: string
}

function DiffList({ title, items, tone }: { title: string; items: string[]; tone: 'add' | 'remove' | 'warn' }) {
  if (items.length === 0) return null
  const color = tone === 'add' ? 'text-cyber-success' : tone === 'remove' ? 'text-cyber-muted' : 'text-cyber-danger'
  const prefix = tone === 'add' ? '+' : tone === 'remove' ? '-' : '⚠'
  return (
    <div>
      <div className={`text-xs font-semibold mb-1 ${color}`}>{title} ({items.length})</div>
      <div className="space-y-0.5 max-h-32 overflow-auto">
        {items.map((item) => (
          <div key={item} className={`text-[11px] font-mono ${color} truncate`} title={item}>
            {prefix} {item}
          </div>
        ))}
      </div>
    </div>
  )
}

export default function ScanHistoryDiff({ targetId, currentScanId }: Props) {
  const [history, setHistory] = useState<ScanHistory | null>(null)
  const [baselineId, setBaselineId] = useState<string>('')
  const [diff, setDiff] = useState<ScanDiff | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    getScanHistory(targetId).then((h) => {
      setHistory(h)
      const priorScans = h.scans.filter((s) => s.id !== currentScanId)
      if (priorScans.length > 0) {
        setBaselineId(priorScans[priorScans.length - 1].id)
      }
    })
  }, [targetId, currentScanId])

  const priorScans = useMemo(
    () => history?.scans.filter((s) => s.id !== currentScanId) ?? [],
    [history, currentScanId],
  )

  useEffect(() => {
    if (!baselineId) return
    setLoading(true)
    getScanDiff(targetId, baselineId, currentScanId)
      .then(setDiff)
      .finally(() => setLoading(false))
  }, [targetId, baselineId, currentScanId])

  if (!history || priorScans.length === 0) {
    return (
      <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5">
        <div className="flex items-center gap-2 mb-1">
          <GitCompare size={18} className="text-cyber-accent" />
          <h2 className="font-semibold text-white">Scan History &amp; Diffing</h2>
        </div>
        <p className="text-sm text-cyber-muted">
          This is the first completed scan for this target. Run it again later to see what changed.
        </p>
      </div>
    )
  }

  const delta = diff?.risk_score_delta ?? null
  const hasChanges = diff && (
    diff.new_subdomains.length || diff.removed_subdomains.length ||
    diff.new_endpoints.length || diff.removed_endpoints.length ||
    diff.new_technologies.length || diff.removed_technologies.length ||
    diff.new_takeover_candidates.length || diff.rotated_secrets.length
  )

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <GitCompare size={18} className="text-cyber-accent" />
          <h2 className="font-semibold text-white">Scan History &amp; Diffing</h2>
        </div>
        <select
          value={baselineId}
          onChange={(e) => setBaselineId(e.target.value)}
          className="bg-cyber-bg border border-cyber-border rounded px-2 py-1 text-xs font-mono"
        >
          {priorScans.map((s) => (
            <option key={s.id} value={s.id}>
              vs. {new Date(s.created_at).toLocaleString()} (risk {s.risk_score ?? '-'})
            </option>
          ))}
        </select>
      </div>

      {loading && <p className="text-xs text-cyber-muted">Computing diff…</p>}

      {!loading && diff && (
        <>
          <div className="flex items-center gap-2 mb-4 text-sm">
            <span className="text-cyber-muted">Risk score:</span>
            <span className="font-mono">{diff.baseline_risk_score ?? '-'}</span>
            <span className="text-cyber-muted">→</span>
            <span className="font-mono font-semibold">{diff.current_risk_score ?? '-'}</span>
            {delta !== null && delta !== 0 && (
              <span className={`flex items-center gap-1 text-xs font-semibold ${delta > 0 ? 'text-cyber-danger' : 'text-cyber-success'}`}>
                {delta > 0 ? <TrendingUp size={14} /> : <TrendingDown size={14} />}
                {delta > 0 ? '+' : ''}{delta}
              </span>
            )}
          </div>

          {!hasChanges ? (
            <p className="text-sm text-cyber-muted">No changes detected between these two scans.</p>
          ) : (
            <div className="grid sm:grid-cols-2 gap-4">
              <DiffList title="New subdomains" items={diff.new_subdomains} tone="add" />
              <DiffList title="Removed subdomains" items={diff.removed_subdomains} tone="remove" />
              <DiffList title="New endpoints" items={diff.new_endpoints} tone="add" />
              <DiffList title="Removed endpoints" items={diff.removed_endpoints} tone="remove" />
              <DiffList title="New technologies" items={diff.new_technologies} tone="add" />
              <DiffList title="Removed technologies" items={diff.removed_technologies} tone="remove" />
              <DiffList title="New takeover candidates" items={diff.new_takeover_candidates} tone="warn" />
              <DiffList title="Rotated secrets" items={diff.rotated_secrets} tone="warn" />
            </div>
          )}
        </>
      )}
    </div>
  )
}
