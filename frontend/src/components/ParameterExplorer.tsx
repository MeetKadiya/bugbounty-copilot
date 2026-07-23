import type { Parameter } from '../types'

export default function ParameterExplorer({ parameters }: { parameters: Parameter[] }) {
  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5">
      <h2 className="font-semibold text-white mb-3">Parameter Explorer ({parameters.length})</h2>
      <div className="overflow-auto max-h-80 space-y-1.5">
        {parameters.map((p) => (
          <div key={p.name + p.example_url} className="text-xs border-b border-cyber-border/40 py-1.5">
            <div className="flex items-center justify-between">
              <span className="font-mono text-cyber-accent">{p.name}</span>
              {p.reflected_context && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyber-warning/15 text-cyber-warning">
                  {p.reflected_context}
                </span>
              )}
            </div>
            <div className="text-slate-400 truncate font-mono" title={p.example_url}>{p.example_url}</div>
          </div>
        ))}
        {parameters.length === 0 && <p className="text-sm text-cyber-muted py-4 text-center">No parameters found.</p>}
      </div>
    </div>
  )
}
