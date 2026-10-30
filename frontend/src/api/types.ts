// Shapes returned by the TraceForge API (see backend/app/api/serializers.py).

export type Role = "viewer" | "investigator" | "admin";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Classification = "confirmed_rule_match" | "suspicious" | "informational" | "inconclusive" | "hypothesis";

export interface User {
  id: number;
  username: string;
  display_name: string;
  role: Role;
  is_active: boolean;
  created_at: string | null;
  last_login_at: string | null;
}

export interface CaseCounts {
  evidence: number;
  findings: number;
  correlations: number;
  iocs: number;
}

export interface Case {
  id: number;
  case_number: string;
  title: string;
  organization: string;
  description: string;
  status: "open" | "analysis" | "reporting" | "closed";
  priority: "low" | "medium" | "high" | "critical";
  is_synthetic: boolean;
  lead_investigator: string | null;
  conclusions: string;
  created_at: string | null;
  updated_at: string | null;
  counts?: CaseCounts;
}

export interface Evidence {
  id: string;
  case_id: number;
  original_filename: string;
  size_bytes: number;
  sha256: string;
  sha1: string;
  md5: string;
  declared_mime: string;
  detected_type: string;
  artifact_type: string;
  source_description: string;
  source_host: string;
  acquired_at: string | null;
  acquired_by: string | null;
  duplicate_of: string | null;
  analysis_status: "pending" | "running" | "complete" | "error" | string;
  integrity_status: "verified" | "mismatch" | "missing" | string;
  last_verified_at: string | null;
}

export interface Finding {
  id: number;
  case_id: number;
  evidence_id: string | null;
  source: string;
  rule_id: string;
  title: string;
  classification: Classification;
  severity: Severity;
  confidence: string;
  description: string;
  rationale: string;
  event_time: string | null;
  source_ref: Record<string, unknown>;
}

export interface AnalysisRun {
  id: number;
  evidence_id: string;
  analyzer: string;
  engine_version: string;
  started_at: string | null;
  finished_at: string | null;
  status: string;
  is_current: boolean;
  input_sha256: string;
  error_count: number;
  errors: Record<string, unknown>[];
  summary?: Record<string, any>;
}

export interface IntegrityCheck {
  id: number;
  evidence_id: string;
  checked_at: string | null;
  checked_by: string;
  expected_sha256: string;
  observed_sha256: string | null;
  result: "match" | "mismatch" | "missing";
  trigger: string;
}

export interface AuditRecord {
  seq: number;
  record_id: string;
  timestamp: string;
  actor: string;
  action: string;
  case_id: number | null;
  evidence_id: string | null;
  details: Record<string, unknown>;
  prev_hash: string;
  record_hash: string;
}

export interface CorrelationStep {
  name: string;
  description: string;
  timeline_event_id: number;
  timestamp_utc: string;
  summary: string;
  source_type: string;
  evidence_id: string;
  link_strength: "root" | "entity" | "temporal";
  links: string[];
  gap_seconds: number | null;
}

export interface Correlation {
  id: number;
  rule_id: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: string;
  classification: string;
  start_time: string | null;
  end_time: string | null;
  steps: CorrelationStep[];
  explanation: string;
  caveats: string[];
}

export interface TimelineEvent {
  id: number;
  evidence_id: string;
  evidence_name?: string;
  timestamp_utc: string;
  original_timestamp: string;
  timezone_assumed: boolean;
  source_type: string;
  event_type: string;
  summary: string;
  severity: Severity;
  confidence: string;
  host: string;
  entities: Record<string, unknown>;
  source_ref: Record<string, unknown>;
  tags: string[];
  correlations?: string[];
}

export interface IocOccurrence {
  evidence_id?: string;
  evidence_name?: string;
  source?: string;
  field?: string;
  context?: string;
  timestamp_utc?: string | null;
  truncated?: number;
}

export interface Ioc {
  id: number;
  ioc_type: string;
  value: string;
  normalized: string;
  classification: string;
  assessment: "watchlist_match" | "suspicious" | "observed" | "benign_context" | string;
  assessment_reason: string;
  first_seen: string | null;
  last_seen: string | null;
  occurrences: IocOccurrence[];
  occurrence_count: number;
}

export interface Report {
  id: string;
  case_id: number;
  format: "pdf" | "json";
  generated_at: string | null;
  generated_by: string;
  size_bytes: number;
  sha256: string;
  content_sha256: string;
}

export interface WindowsEvent {
  id: number;
  evidence_id: string;
  record_number: number;
  event_id: number;
  provider: string;
  channel: string;
  computer: string;
  level: number | null;
  timestamp_utc: string;
  original_timestamp: string;
  user_sid: string | null;
  description: string;
  data: Record<string, string>;
  detections: { rule_id: string; severity: Severity; classification: Classification; title: string }[];
}

export interface BrowserArtifact {
  id: number;
  evidence_id: string;
  kind: "visit" | "download";
  url: string;
  title: string;
  timestamp_utc: string | null;
  original_timestamp: string;
  visit_count: number | null;
  target_path: string;
  referrer: string;
  total_bytes: number | null;
  extra: Record<string, any>;
  detections: { rule_id: string; severity: Severity; title: string; classification: Classification }[];
}

export interface Dashboard {
  case: Case;
  evidence_total: number;
  evidence_bytes: number;
  evidence_by_type: Record<string, number>;
  evidence_integrity: Record<string, number>;
  analysis_status: Record<string, number>;
  findings_by_classification: Record<string, number>;
  findings_by_severity: Record<Severity, number>;
  findings_by_source: Record<string, number>;
  timeline_total: number;
  timeline_range: [string, string] | null;
  activity: ({ bucket: string } & Record<Severity, number>)[];
  correlations: Correlation[];
  iocs_by_assessment: Record<string, number>;
  iocs_by_type: Record<string, number>;
  top_findings: Finding[];
  integrity_checks: number;
}
