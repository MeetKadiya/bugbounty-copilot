export default function RiskScoreGauge({ score }: { score: number }) {
  const pct = Math.min(Math.max(score, 0), 100)
  const color = pct >= 70 ? '#ff3860' : pct >= 40 ? '#ffb020' : '#22c55e'
  const label = pct >= 70 ? 'High Risk' : pct >= 40 ? 'Medium Risk' : 'Low Risk'

  const radius = 60
  const circumference = 2 * Math.PI * radius
  const offset = circumference - (pct / 100) * circumference

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5 flex flex-col items-center justify-center">
      <h3 className="text-sm font-semibold text-white mb-2 self-start">Attack Surface Risk Score</h3>
      <svg width="160" height="160" viewBox="0 0 160 160">
        <circle cx="80" cy="80" r={radius} fill="none" stroke="#1c2733" strokeWidth="12" />
        <circle
          cx="80" cy="80" r={radius} fill="none" stroke={color} strokeWidth="12"
          strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round"
          transform="rotate(-90 80 80)" style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
        <text x="80" y="76" textAnchor="middle" fontSize="28" fontWeight="bold" fill="#fff" fontFamily="monospace">
          {pct.toFixed(0)}
        </text>
        <text x="80" y="98" textAnchor="middle" fontSize="11" fill="#64748b">
          / 100
        </text>
      </svg>
      <span className="text-sm font-semibold mt-1" style={{ color }}>{label}</span>
      <p className="text-[11px] text-cyber-muted text-center mt-2">
        A transparent triage heuristic, not a verdict — always verify manually.
      </p>
    </div>
  )
}
