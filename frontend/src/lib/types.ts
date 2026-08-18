export type Severity = "informational" | "low" | "medium" | "high" | "critical";

export interface RecommendedAction {
  action_type: "diagnostic" | "remediation";
  title: string;
  description: string;
  enabled: boolean;
  phase: string;
}

export interface Incident {
  incident_id: string;
  title: string;
  status: string;
  severity: Severity;
  confidence: number;
  affected_hosts: string[];
  created_at: string;
  updated_at: string;
  first_event_at: string;
  last_event_at: string;
  event_count: number;
  probable_cause: string;
  correlation_reasons: string[];
  recommended_actions: RecommendedAction[];
}

export interface EventRecord {
  event_id: string;
  source: string;
  source_version: string | null;
  host_id: string;
  host_name: string;
  timestamp: string;
  event_type: string;
  category: string | null;
  severity: Severity;
  confidence: number;
  summary: string;
  incident_id: string | null;
  received_at: string;
  evidence: Record<string, unknown>;
  process: Record<string, unknown> | null;
  file: Record<string, unknown> | null;
  network: Record<string, unknown> | null;
  persistence: Record<string, unknown> | null;
  metadata: Record<string, unknown>;
}

export interface TimelineEntry {
  event_id: string;
  timestamp: string;
  event_type: string;
  summary: string;
  severity: Severity;
  evidence: Record<string, unknown>;
}

export interface AuditEntry {
  audit_id: string;
  timestamp: string;
  actor_type: string;
  actor_id: string;
  action: string;
  resource_type: string;
  resource_id: string;
  details: Record<string, unknown>;
}

export interface IncidentDetail extends Incident {
  timeline: TimelineEntry[];
  events: EventRecord[];
  audit_trail: AuditEntry[];
}

export interface Host {
  host_id: string;
  hostname: string;
  operating_system: string | null;
  agent: string;
  agent_version: string | null;
  first_seen: string;
  last_seen: string;
  status: string;
  event_count: number;
  incident_count: number;
}

export interface Overview {
  active_incidents: number;
  critical_incidents: number;
  high_incidents: number;
  hosts_reporting: number;
  events_last_24h: number;
  recent_incidents: Incident[];
  remediation_enabled: boolean;
}
