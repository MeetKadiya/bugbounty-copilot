import type { Technology } from '../types'

export default function TechStackPanel({ technologies }: { technologies: Technology[] }) {
  const byCategory = technologies.reduce<Record<string, Technology[]>>((acc, t) => {
    acc[t.category] = acc[t.category] || []
    acc[t.category].push(t)
    return acc
  }, {})

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5">
      <h2 className="font-semibold text-white mb-3">Technology Stack ({technologies.length})</h2>
      <div className="overflow-auto max-h-80 space-y-3">
        {Object.entries(byCategory).map(([category, items]) => (
          <div key={category}>
            <div className="text-[11px] uppercase text-cyber-muted mb-1">{category}</div>
            <div className="flex flex-wrap gap-1.5">
              {items.map((t, idx) => (
                <span key={idx} title={t.evidence ?? ''}
                      className="text-xs font-mono px-2 py-1 rounded bg-cyber-bg border border-cyber-border text-slate-300">
                  {t.name} <span className="text-cyber-muted">· {t.hostname}</span>
                </span>
              ))}
            </div>
          </div>
        ))}
        {technologies.length === 0 && <p className="text-sm text-cyber-muted">No technology signals detected.</p>}
      </div>
    </div>
  )
}
