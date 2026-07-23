import { Download, FileJson, FileText } from 'lucide-react'
import { exportUrl } from '../api/client'

export default function ExportButtons({ scanId }: { scanId: string }) {
  return (
    <div className="flex gap-2">
      <a href={exportUrl(scanId, 'json')} download
         className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border border-cyber-border
                    hover:border-cyber-accent hover:text-cyber-accent transition-colors">
        <FileJson size={14} /> JSON
      </a>
      <a href={exportUrl(scanId, 'markdown')} download
         className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded border border-cyber-border
                    hover:border-cyber-accent hover:text-cyber-accent transition-colors">
        <FileText size={14} /> Markdown
      </a>
    </div>
  )
}
