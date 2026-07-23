import { useState } from 'react'
import type { Endpoint } from '../types'

export default function EndpointExplorer({ endpoints }: { endpoints: Endpoint[] }) {
  const [onlyApi, setOnlyApi] = useState(false)
  const rows = onlyApi ? endpoints.filter((e) => e.is_api) : endpoints

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <h2 className="font-semibold text-white">Endpoint Explorer ({endpoints.length})</h2>
        <label className="flex items-center gap-1.5 text-xs text-cyber-muted cursor-pointer">
          <input type="checkbox" checked={onlyApi} onChange={(e) => setOnlyApi(e.target.checked)} />
          API only
        </label>
      </div>
      <div className="overflow-auto max-h-80 space-y-1">
        {rows.map((e) => (
          <div key={e.url} className="flex items-center gap-2 text-xs font-mono border-b border-cyber-border/40 py-1.5">
            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold
              ${e.is_api ? 'bg-cyber-accent2/20 text-cyber-accent2' : 'bg-cyber-border text-cyber-muted'}`}>
              {e.is_api ? 'API' : e.method}
            </span>
            <span className="truncate flex-1 text-slate-300" title={e.url}>{e.url}</span>
            {e.status_code && <span className="text-cyber-muted">{e.status_code}</span>}
          </div>
        ))}
        {rows.length === 0 && <p className="text-sm text-cyber-muted py-4 text-center">No endpoints found.</p>}
      </div>
    </div>
  )
}
