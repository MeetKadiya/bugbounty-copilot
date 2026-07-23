import { useState } from 'react'
import Dashboard from './pages/Dashboard'
import TargetInput from './components/TargetInput'
import { Shield } from 'lucide-react'

export default function App() {
  const [scanId, setScanId] = useState<string | null>(null)

  return (
    <div className="min-h-screen bg-cyber-bg text-slate-200">
      <header className="border-b border-cyber-border bg-cyber-panel/60 backdrop-blur sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-6 py-4 flex items-center gap-3">
          <Shield className="text-cyber-accent" size={28} />
          <div>
            <h1 className="text-lg font-bold tracking-tight text-white">Bug Bounty Copilot</h1>
            <p className="text-xs text-cyber-muted">
              AI-assisted reconnaissance &amp; triage — assistant only, never autonomous exploitation
            </p>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        <TargetInput onScanStarted={setScanId} />
        {scanId && <Dashboard scanId={scanId} />}
      </main>

      <footer className="border-t border-cyber-border mt-16 py-6 text-center text-xs text-cyber-muted">
        For authorized security research only (bug bounty programs, owned assets, lab environments).
        No exploitation is ever performed automatically.
      </footer>
    </div>
  )
}
