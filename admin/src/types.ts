export interface PolicyValues {
  version: string;
  base_iterations: string;
  base_render_rounds: number;
  quiet_window_seconds: number;
  base_lifetime_seconds: number;
  iteration_allowance: string;
  round_allowance_seconds: number;
  max_lifetime_seconds: number;
}

export interface PolicyDocument {
  tenant: string;
  site_key: string;
  action: string;
  policy: PolicyValues;
}

export interface DiscoveryDocument {
  keys?: Array<{ kid: string }>;
  modulus_ids?: string[];
}

export interface LiveStatus {
  metrics: Record<string, number>;
  healthy: boolean;
  keyCount: number | null;
  modulusCount: number | null;
}

export interface AuditEvent {
  version: "audit-v1";
  kind: string;
  occurred_at: number;
  tenant: string;
  site_key: string;
  action: string;
  tier?: number;
  backend?: "webgpu" | "webgl2" | "css";
  code?: string;
}

export interface AuditDocument {
  tenant: string;
  site_key: string;
  action: string;
  events: AuditEvent[];
}
