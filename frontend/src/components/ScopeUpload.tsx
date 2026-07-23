import { useState } from 'react'
import { ListChecks, X, Loader2 } from 'lucide-react'
import { clearScope, uploadScope } from '../api/client'
import type { Target } from '../types'

interface Props {
  target: Target | null
  onTargetUpdated: (target: Target) => void
}

export default function ScopeUpload({ target, onTargetUpdated }: Props) {
  const [open, setOpen] = useState(false)
  const [rawText, setRawText] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  if (!target) return null

  async function handleUpload() {
    if (!rawText.trim()) return
    setLoading(true)
    setError(null)
    try {
      const updated = await uploadScope(target!.id, rawText)
      onTargetUpdated(updated)
      setOpen(false)
      setRawText('')
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? 'Failed to parse scope rules.')
    } finally {
      setLoading(false)
    }
  }

  async function handleClear() {
    setLoading(true)
    try {
      const updated = await clearScope(target!.id)
      onTargetUpdated(updated)
    } finally {
      setLoading(false)
    }
  }

  const ruleCount = target.scope_rules?.length ?? 0

  return (
    <div className="bg-cyber-panel border border-cyber-border rounded-xl p-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-sm">
          <ListChecks size={16} className="text-cyber-accent" />
          <span className="text-white font-medium">Program Scope</span>
          {ruleCount > 0 ? (
            <span className="text-xs text-cyber-muted">{ruleCount} rule(s) loaded</span>
          ) : (
            <span className="text-xs text-cyber-muted">using default root-domain scope</span>
          )}
        </div>
        <div className="flex gap-2">
          {ruleCount > 0 && (
            <button onClick={handleClear} disabled={loading}
                    className="text-xs text-cyber-muted hover:text-cyber-danger flex items-center gap-1">
              <X size={12} /> Clear
            </button>
          )}
          <button onClick={() => setOpen((o) => !o)}
                  className="text-xs text-cyber-accent hover:underline">
            {open ? 'Cancel' : 'Upload scope doc'}
          </button>
        </div>
      </div>

      {open && (
        <div className="mt-3">
          <textarea
            value={rawText}
            onChange={(e) => setRawText(e.target.value)}
            placeholder={'Paste the program\'s scope, one rule per line, e.g.\n*.example.com\napi.example.com\n!internal.example.com'}
            rows={5}
            className="w-full bg-cyber-bg border border-cyber-border rounded-lg p-3 text-xs font-mono
                       focus:outline-none focus:ring-2 focus:ring-cyber-accent/50 focus:border-cyber-accent"
          />
          <div className="flex items-center justify-between mt-2">
            <p className="text-[11px] text-cyber-muted">
              Lines starting with <span className="font-mono">!</span> exclude a host even if a wildcard
              rule would otherwise include it.
            </p>
            <button onClick={handleUpload} disabled={loading || !rawText.trim()}
                    className="bg-cyber-accent text-cyber-bg text-xs font-semibold px-4 py-1.5 rounded
                               disabled:opacity-50 flex items-center gap-1.5">
              {loading && <Loader2 className="animate-spin" size={12} />}
              Save Scope
            </button>
          </div>
          {error && <p className="text-xs text-cyber-danger mt-1">{error}</p>}
        </div>
      )}
    </div>
  )
}
