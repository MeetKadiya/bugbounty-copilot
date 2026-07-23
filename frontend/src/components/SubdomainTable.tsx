import { useState } from 'react'
import type { Subdomain } from '../types'

export default function SubdomainTable({ subdomains }: { subdomains: Subdomain[] }) {
  const [filter, setFilter] = useState('')
  const rows = subdomains.filter((s) => s.hostname.includes(filter.toLowerCase()))

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5 flex flex-col">
      <div className="flex items-center justify-between mb-3">
        <h2 className="font-semibold text-white">Subdomains ({subdomains.length})</h2>
        <input
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="filter…"
          className="bg-cyber-bg border border-cyber-border rounded px-2 py-1 text-xs font-mono w-32
                     focus:outline-none focus:ring-1 focus:ring-cyber-accent/50"
        />
      </div>
      <div className="overflow-auto max-h-80">
        <table className="w-full text-xs">
          <thead className="text-cyber-muted text-left sticky top-0 bg-cyber-panel">
            <tr>
              <th className="py-1 pr-2">Host</th>
              <th className="py-1 pr-2">Status</th>
              <th className="py-1 pr-2">Title</th>
              <th className="py-1 pr-2">WAF/CDN</th>
              <th className="py-1 pr-2">Source</th>
              <th className="py-1">Scope</th>
            </tr>
          </thead>
          <tbody className="font-mono">
            {rows.map((s) => (
              <tr key={s.hostname} className="border-t border-cyber-border/60 hover:bg-cyber-bg/50">
                <td className="py-1.5 pr-2 truncate max-w-[160px]" title={s.hostname}>
                  <span className={`inline-block w-1.5 h-1.5 rounded-full mr-1.5 ${s.is_alive ? 'bg-cyber-success' : 'bg-cyber-muted'}`} />
                  {s.hostname}
                </td>
                <td className="py-1.5 pr-2">{s.status_code ?? '-'}</td>
                <td className="py-1.5 pr-2 truncate max-w-[140px] text-slate-400" title={s.title ?? ''}>{s.title ?? '-'}</td>
                <td className="py-1.5 pr-2 text-cyber-accent2">{s.cdn_or_waf ?? '-'}</td>
                <td className="py-1.5 pr-2 text-cyber-muted">{s.source}</td>
                <td className="py-1.5">
                  {s.in_scope ? (
                    <span className="text-cyber-success">in-scope</span>
                  ) : (
                    <span className="text-cyber-danger">out-of-scope</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
