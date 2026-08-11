export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
export type Confidence = 'High' | 'Medium' | 'Low'

export interface Scan {
  id: string
  target_id: string
  status: ScanStatus
  current_stage: string
  progress_percent: number
  risk_score: number | null
  error_message: string | null
  started_at: string | null
  finished_at: string | null
  created_at: string
}

export interface Subdomain {
  hostname: string
  is_alive: boolean
  status_code: number | null
  ip_addresses: string[] | null
  server_header: string | null
  title: string | null
  cdn_or_waf: string | null
  source: string
  in_scope: boolean
}

export interface Endpoint {
  url: string
  method: string
  status_code: number | null
  content_type: string | null
  source: string
  is_api: boolean
}

export interface Parameter {
  name: string
  example_url: string
  reflected_context: string | null
}

export interface Secret {
  secret_type: string
  source_url: string
  match_redacted: string
  severity: Confidence
}

export interface Technology {
  hostname: string
  name: string
  category: string
  evidence: string | null
}

export interface Finding {
  vulnerability_class: string
  confidence: Confidence
  related_asset: string
  reasoning: string
  recommended_next_step: string
}

export interface TakeoverCandidate {
  hostname: string
  cname: string
  service: string
  confidence: Confidence
  evidence: string
}

export interface ScanFullReport {
  scan: Scan
  subdomains: Subdomain[]
  endpoints: Endpoint[]
  parameters: Parameter[]
  secrets: Secret[]
  technologies: Technology[]
  findings: Finding[]
  takeover_candidates: TakeoverCandidate[]
  risk_score: number
  ai_summary: string
}

export interface Target {
  id: string
  domain: string
  is_wildcard: boolean
  scope_rules: string[] | null
  created_at: string
}

export interface ScanHistoryItem {
  id: string
  created_at: string
  status: ScanStatus
  risk_score: number | null
}

export interface ScanHistory {
  target_id: string
  domain: string
  scans: ScanHistoryItem[]
}

export interface ScanDiff {
  target_id: string
  domain: string
  baseline_scan_id: string
  current_scan_id: string
  baseline_created_at: string
  current_created_at: string
  new_subdomains: string[]
  removed_subdomains: string[]
  new_endpoints: string[]
  removed_endpoints: string[]
  new_technologies: string[]
  removed_technologies: string[]
  new_takeover_candidates: string[]
  rotated_secrets: string[]
  baseline_risk_score: number | null
  current_risk_score: number | null
  risk_score_delta: number | null
}

export interface PathParameter {
  placeholder: string
  example_value: string
  kind: string
}

export interface InterestingParameter {
  name: string
  categories: string[]
  sensitivity: 'interesting' | 'potentially sensitive' | 'requires review'
  owasp_hints: string[]
}

export interface EndpointIntelligence {
  id: string
  hostname: string
  method: string
  normalized_path: string
  url: string
  example_urls: string[] | null
  occurrence_count: number
  query_parameters: string[] | null
  path_parameters: PathParameter[] | null
  interesting_parameters: InterestingParameter[] | null
  api_classification: string
  endpoint_categories: string[] | null
  sensitive_resource_indicators: string[] | null
  administrative: boolean
  auth_related: boolean
  potential_bola: boolean
  potential_broken_function_auth: boolean
  potential_excessive_data_exposure: boolean
  potential_ssrf: boolean
  potential_open_redirect: boolean
  potential_mass_assignment: boolean
  potential_file_upload: boolean
  potential_debug_internal: boolean
  confidence_score: number
  risk_level: 'High' | 'Medium' | 'Low'
  reasons: string[] | null
  created_at: string
}
