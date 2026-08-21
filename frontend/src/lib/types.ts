export type Severity = "informational" | "low" | "medium" | "high" | "critical";

export interface RecommendedAction {
  action_type: "diagnostic" | "remediation";
  title: string;
  description: string;
  enabled: boolean;
  phase: string;
  registry_action_type?: string | null;
  requires_approval?: boolean;
}

export type ResponsePlanPriority = "routine" | "elevated" | "high" | "critical";
export type ResponsePlanStepState = "available" | "manual" | "planned" | "blocked";

export interface ResponsePlanStep {
  step_id: string;
  title: string;
  description: string;
  state: ResponsePlanStepState;
  destructive: boolean;
  requires_approval: boolean;
  executable_action_type: string | null;
}

export interface ResponsePlan {
  schema_version: "1.0" | "1.1";
  plan_id: string;
  incident_id: string;
  mode: "advisory_with_controlled_actions";
  priority: ResponsePlanPriority;
  attack_families: string[];
  objectives: string[];
  investigation_steps: ResponsePlanStep[];
  containment_steps: ResponsePlanStep[];
  recovery_steps: ResponsePlanStep[];
  escalation_conditions: string[];
  executable_actions: string[];
  limitations: string[];
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

export interface Agent {
  agent_id: string;
  host_id: string;
  display_name: string;
  key_id: string;
  created_at: string;
  last_seen: string | null;
  enabled: boolean;
  agent_version: string | null;
  supported_actions: string[];
  enabled_actions: string[];
  capabilities_updated_at: string | null;
}

export type ResponseActionStatus =
  | "pending"
  | "approved"
  | "rejected"
  | "dispatching"
  | "executing"
  | "succeeded"
  | "failed"
  | "expired"
  | "cancelled";

export interface ResponseAction {
  schema_version: string;
  action_id: string;
  incident_id: string;
  target_agent_id: string;
  target_host_id: string;
  action_type: string;
  parameters: Record<string, unknown>;
  requested_at: string;
  requested_by: string;
  approval_id: string | null;
  expires_at: string;
  status: ResponseActionStatus;
  policy_allowed: boolean | null;
  policy_reasons: string[];
  dispatched_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  result: Record<string, unknown> | null;
  error: string | null;
  evidence: Record<string, unknown> | null;
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
