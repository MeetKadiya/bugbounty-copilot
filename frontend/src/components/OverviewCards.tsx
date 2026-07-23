import type { ScanFullReport } from '../types'
import { Globe, Link2, KeyRound, Cpu } from 'lucide-react'

export default function OverviewCards({ report }: { report: ScanFullReport }) {
  const aliveHosts = report.subdomains.filter((s) => s.is_alive).length
  const apiEndpoints = report.endpoints.filter((e) => e.is_api).length

  const cards = [
    { label: 'Live Subdomains', value: aliveHosts, total: report.subdomains.length, icon: Globe, color: 'text-cyber-accent' },
    { label: 'Endpoints Found', value: report.endpoints.length, sub: `${apiEndpoints} API-like`, icon: Link2, color: 'text-cyber-accent2' },
    { label: 'Secrets Flagged', value: report.secrets.length, sub: 'redacted', icon: KeyRound, color: 'text-cyber-warning' },
    { label: 'Technologies', value: report.technologies.length, sub: 'signals detected', icon: Cpu, color: 'text-cyber-success' },
  ]

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 h-full">
      {cards.map(({ label, value, total, sub, icon: Icon, color }) => (
        <div key={label} className="bg-cyber-panel border border-cyber-border rounded-xl p-4 card-glow">
          <Icon className={color} size={20} />
          <div className="mt-2 text-2xl font-bold text-white font-mono">
            {value}
            {total !== undefined && <span className="text-sm text-cyber-muted">/{total}</span>}
          </div>
          <div className="text-xs text-cyber-muted mt-1">{label}</div>
          {sub && <div className="text-[10px] text-cyber-muted mt-0.5">{sub}</div>}
        </div>
      ))}
    </div>
  )
}
