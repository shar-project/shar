import type {
  AuditDocument,
  DiscoveryDocument,
  LiveStatus,
  PolicyDocument,
} from "./types";

export class AdminApiError extends Error {
  constructor(
    readonly code: string,
    readonly status: number,
  ) {
    super(code);
  }
}

async function responseError(response: Response): Promise<never> {
  let code = `http_${response.status}`;
  try {
    const body = (await response.json()) as { code?: unknown };
    if (typeof body.code === "string") code = body.code;
  } catch {}
  throw new AdminApiError(code, response.status);
}

export async function getPolicy(
  token: string,
  scope: Omit<PolicyDocument, "policy">,
): Promise<PolicyDocument> {
  const query = new URLSearchParams({
    tenant: scope.tenant,
    site_key: scope.site_key,
    action: scope.action,
  });
  const response = await fetch(`/v1/admin/policy?${query}`, {
    headers: { authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (!response.ok) return responseError(response);
  return response.json() as Promise<PolicyDocument>;
}

export async function putPolicy(
  token: string,
  document: PolicyDocument,
): Promise<PolicyDocument> {
  const response = await fetch("/v1/admin/policy", {
    method: "PUT",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(document),
  });
  if (!response.ok) return responseError(response);
  return response.json() as Promise<PolicyDocument>;
}

export async function getAudit(
  token: string,
  scope: Omit<PolicyDocument, "policy">,
  limit = 100,
): Promise<AuditDocument> {
  const query = new URLSearchParams({
    tenant: scope.tenant,
    site_key: scope.site_key,
    action: scope.action,
    limit: String(limit),
  });
  const response = await fetch(`/v1/admin/audit?${query}`, {
    headers: { authorization: `Bearer ${token}` },
    cache: "no-store",
  });
  if (!response.ok) return responseError(response);
  return response.json() as Promise<AuditDocument>;
}

export async function liveStatus(): Promise<LiveStatus> {
  const [metricsResponse, discoveryResponse, healthResponse] =
    await Promise.all([
      fetch("/metrics", { cache: "no-store" }),
      fetch("/.well-known/shar/v1", { cache: "no-store" }),
      fetch("/healthz", { cache: "no-store" }),
    ]);
  const metrics: Record<string, number> = {};
  if (metricsResponse.ok) {
    for (const line of (await metricsResponse.text()).split("\n")) {
      const match = /^(shar_[a-z_]+)\s+(\d+)$/.exec(line);
      if (match) metrics[match[1]!] = Number(match[2]);
    }
  }
  let keyCount: number | null = null,
    modulusCount: number | null = null;
  if (discoveryResponse.ok) {
    const discovery = (await discoveryResponse.json()) as DiscoveryDocument;
    keyCount = Array.isArray(discovery.keys) ? discovery.keys.length : null;
    modulusCount = Array.isArray(discovery.modulus_ids)
      ? discovery.modulus_ids.length
      : null;
  }
  return { metrics, healthy: healthResponse.ok, keyCount, modulusCount };
}
