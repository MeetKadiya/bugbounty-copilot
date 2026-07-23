import type { ScanFullReport } from '../types'
import { useMemo, useState } from 'react'

export default function AssetGraph({ report }: { report: ScanFullReport }) {
  const [hovered, setHovered] = useState<string | null>(null)
  const aliveHosts = useMemo(() => report.subdomains.filter((s) => s.is_alive).slice(0, 16), [report])

  const centerX = 400
  const centerY = 200
  const radius = 150

  const nodes = aliveHosts.map((host, i) => {
    const angle = (i / aliveHosts.length) * 2 * Math.PI
    return {
      hostname: host.hostname,
      x: centerX + radius * Math.cos(angle),
      y: centerY + radius * Math.sin(angle),
      cdn: host.cdn_or_waf,
    }
  })

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5">
      <h2 className="font-semibold text-white mb-3">Asset Graph</h2>
      {aliveHosts.length === 0 ? (
        <p className="text-sm text-cyber-muted">No live hosts to graph yet.</p>
      ) : (
        <svg viewBox="0 0 800 400" className="w-full h-[320px]">
          {nodes.map((n) => (
            <line key={`line-${n.hostname}`} x1={centerX} y1={centerY} x2={n.x} y2={n.y}
                  stroke="#1c2733" strokeWidth={1.5} />
          ))}

          <circle cx={centerX} cy={centerY} r={26} fill="#0f1621" stroke="#00f5d4" strokeWidth={2} />
          <text x={centerX} y={centerY + 4} textAnchor="middle" fontSize="10" fill="#00f5d4" fontFamily="monospace">
            TARGET
          </text>

          {nodes.map((n) => (
            <g key={n.hostname}
               onMouseEnter={() => setHovered(n.hostname)}
               onMouseLeave={() => setHovered(null)}
               style={{ cursor: 'pointer' }}>
              <circle cx={n.x} cy={n.y} r={hovered === n.hostname ? 10 : 7}
                      fill={n.cdn ? '#7c3aed' : '#0f1621'}
                      stroke={n.cdn ? '#7c3aed' : '#00f5d4'} strokeWidth={2} />
              {hovered === n.hostname && (
                <text x={n.x} y={n.y - 14} textAnchor="middle" fontSize="10" fill="#fff" fontFamily="monospace">
                  {n.hostname}
                </text>
              )}
            </g>
          ))}
        </svg>
      )}
      <div className="flex gap-4 mt-2 text-[11px] text-cyber-muted">
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-cyber-accent inline-block" /> No WAF/CDN</span>
        <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-cyber-accent2 inline-block" /> Behind WAF/CDN</span>
      </div>
    </div>
  )
}
