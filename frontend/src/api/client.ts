import axios from 'axios'
import type { Scan, ScanDiff, ScanFullReport, ScanHistory, Target } from '../types'

const API_BASE = '/api/v1'

export const api = axios.create({ baseURL: API_BASE })

export async function validateScope(domain: string) {
  const res = await api.post<{ valid: boolean; normalized_domain: string; is_wildcard: boolean }>(
    '/targets/validate',
    { domain },
  )
  return res.data
}

export async function startScan(domain: string, activeRecon = true) {
  const res = await api.post<Scan>('/scans', { domain, active_recon: activeRecon })
  return res.data
}

export async function getScan(scanId: string) {
  const res = await api.get<Scan>(`/scans/${scanId}`)
  return res.data
}

export async function listScans() {
  const res = await api.get<Scan[]>('/scans')
  return res.data
}

export async function getReport(scanId: string) {
  const res = await api.get<ScanFullReport>(`/scans/${scanId}/report`)
  return res.data
}

export async function cancelScan(scanId: string) {
  const res = await api.post(`/scans/${scanId}/cancel`)
  return res.data
}

export function exportUrl(scanId: string, format: 'json' | 'markdown') {
  return `${API_BASE}/scans/${scanId}/export/${format}`
}

export async function getTarget(targetId: string) {
  const res = await api.get<Target>(`/targets/${targetId}`)
  return res.data
}

export async function uploadScope(targetId: string, rawText: string) {
  const res = await api.post<Target>(`/targets/${targetId}/scope`, { raw_text: rawText })
  return res.data
}

export async function clearScope(targetId: string) {
  const res = await api.delete<Target>(`/targets/${targetId}/scope`)
  return res.data
}

export async function getScanHistory(targetId: string) {
  const res = await api.get<ScanHistory>(`/targets/${targetId}/scans/history`)
  return res.data
}

export async function getScanDiff(targetId: string, baselineScanId: string, currentScanId: string) {
  const res = await api.get<ScanDiff>(`/targets/${targetId}/diff`, {
    params: { baseline_scan_id: baselineScanId, current_scan_id: currentScanId },
  })
  return res.data
}
