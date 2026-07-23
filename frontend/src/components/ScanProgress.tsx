import type { Scan } from '../types'
import { Loader2, CheckCircle2, XCircle } from 'lucide-react'

const STAGE_ORDER = [
  'Enumerating subdomains',
  'Probing live hosts',
  'Detecting WAF/CDN',
  'Collecting headers & tech',
  'Discovering directories/endpoints',
  'Crawling JavaScript & URLs',
  'Extracting API endpoints',
  'Fingerprinting frameworks',
  'Extracting parameters',
  'Scanning for secrets',
  'Running AI analysis',
]

export default function ScanProgress({ scan }: { scan: Scan }) {
  const isDone = scan.status === 'completed'
  const isFailed = scan.status === 'failed'

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          {isDone ? (
            <CheckCircle2 className="text-cyber-success" size={20} />
          ) : isFailed ? (
            <XCircle className="text-cyber-danger" size={20} />
          ) : (
            <Loader2 className="animate-spin text-cyber-accent" size={20} />
          )}
          <span className="font-semibold text-white">
            {isFailed ? 'Scan failed' : isDone ? 'Scan complete' : scan.current_stage}
          </span>
        </div>
        <span className="text-xs font-mono text-cyber-muted">{scan.progress_percent.toFixed(0)}%</span>
      </div>

      <div className="w-full h-2 bg-cyber-bg rounded-full overflow-hidden border border-cyber-border">
        <div
          className={`h-full transition-all duration-500 ${isFailed ? 'bg-cyber-danger' : 'bg-cyber-accent'}`}
          style={{ width: `${scan.progress_percent}%` }}
        />
      </div>

      {scan.error_message && (
        <p className="mt-3 text-xs text-cyber-danger font-mono">{scan.error_message}</p>
      )}

      <div className="mt-4 flex flex-wrap gap-2">
        {STAGE_ORDER.map((stage) => {
          const stageIndex = STAGE_ORDER.indexOf(stage)
          const currentIndex = STAGE_ORDER.indexOf(scan.current_stage)
          const passed = isDone || stageIndex < currentIndex
          const active = stage === scan.current_stage && !isDone
          return (
            <span
              key={stage}
              className={`text-[10px] px-2 py-1 rounded-full border font-mono
                ${passed ? 'border-cyber-success/40 text-cyber-success bg-cyber-success/10' : ''}
                ${active ? 'border-cyber-accent text-cyber-accent bg-cyber-accent/10' : ''}
                ${!passed && !active ? 'border-cyber-border text-cyber-muted' : ''}`}
            >
              {stage}
            </span>
          )
        })}
      </div>
    </div>
  )
}
