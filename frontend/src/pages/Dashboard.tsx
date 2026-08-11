import { useEffect, useState } from 'react'
import { getScan, getReport, getTarget } from '../api/client'
import type { Scan, ScanFullReport, Target } from '../types'
import ScanProgress from '../components/ScanProgress'
import OverviewCards from '../components/OverviewCards'
import RiskScoreGauge from '../components/RiskScoreGauge'
import AssetGraph from '../components/AssetGraph'
import SubdomainTable from '../components/SubdomainTable'
import EndpointExplorer from '../components/EndpointExplorer'
import EndpointIntelligencePanel from '../components/EndpointIntelligencePanel'
import ParameterExplorer from '../components/ParameterExplorer'
import SecretsPanel from '../components/SecretsPanel'
import TechStackPanel from '../components/TechStackPanel'
import AIRecommendations from '../components/AIRecommendations'
import ExportButtons from '../components/ExportButtons'
import TakeoverPanel from '../components/TakeoverPanel'
import ScopeUpload from '../components/ScopeUpload'
import ScanHistoryDiff from '../components/ScanHistoryDiff'

export default function Dashboard({ scanId }: { scanId: string }) {
  const [scan, setScan] = useState<Scan | null>(null)
  const [report, setReport] = useState<ScanFullReport | null>(null)
  const [target, setTarget] = useState<Target | null>(null)

  useEffect(() => {
    let cancelled = false
    let interval: ReturnType<typeof setInterval>

    async function poll() {
      const s = await getScan(scanId)
      if (cancelled) return
      setScan(s)

      if (!target) {
        getTarget(s.target_id).then((t) => !cancelled && setTarget(t))
      }

      if (s.status === 'completed') {
        const r = await getReport(scanId)
        if (!cancelled) setReport(r)
        clearInterval(interval)
      } else if (s.status === 'failed' || s.status === 'cancelled') {
        clearInterval(interval)
      }
    }

    poll()
    interval = setInterval(poll, 2000)
    return () => {
      cancelled = true
      clearInterval(interval)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanId])

  if (!scan) return <div className="mt-8 text-cyber-muted">Loading scan…</div>

  return (
    <div className="mt-8 space-y-6">
      <ScanProgress scan={scan} />

      <ScopeUpload target={target} onTargetUpdated={setTarget} />

      {report && (
        <>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <OverviewCards report={report} />
            </div>
            <RiskScoreGauge score={report.risk_score} />
          </div>

          <TakeoverPanel candidates={report.takeover_candidates} />

          <AssetGraph report={report} />

          <div className="bg-cyber-panel border border-cyber-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-2">
              <h2 className="font-semibold text-white">AI Summary</h2>
              <ExportButtons scanId={scanId} />
            </div>
            <p className="text-sm text-slate-300 leading-relaxed">{report.ai_summary}</p>
          </div>

          <AIRecommendations findings={report.findings} />

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <SubdomainTable subdomains={report.subdomains} />
            <TechStackPanel technologies={report.technologies} />
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <EndpointExplorer endpoints={report.endpoints} />
            <ParameterExplorer parameters={report.parameters} />
          </div>

          <EndpointIntelligencePanel scanId={scanId} ready={scan.status === 'completed'} />

          <SecretsPanel secrets={report.secrets} />

          {target && <ScanHistoryDiff targetId={target.id} currentScanId={scanId} />}
        </>
      )}
    </div>
  )
}
