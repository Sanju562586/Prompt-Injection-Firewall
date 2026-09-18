export const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export type Decision = "BLOCK" | "WARN" | "ALLOW";

export type AttackCategory =
  | "direct_injection"
  | "jailbreak"
  | "role_hijack"
  | "indirect_injection"
  | "token_smuggling"
  | "pii_exfiltration"
  | "rag_poisoning"
  | "unknown";

export type DetectorLayer = "pattern" | "semantic" | "classifier" | "pii";

export interface DetectorResult {
  layer: DetectorLayer;
  triggered: boolean;
  score: number;
  attack_category: AttackCategory;
  reason: string;
  matched?: string | null;
}

export interface ScanResult {
  request_id?: string | null;
  text_snippet: string;
  decision: Decision;
  score: number;
  attack_category: AttackCategory;
  reason: string;
  latency_ms: number;
  detector_results: DetectorResult[];
}

export interface RagDocument {
  doc_id: string;
  content: string;
  source?: string | null;
}

export interface RagScanResult {
  poisoned_count: number;
  clean_count: number;
  results: Array<{
    doc_id: string;
    decision: Decision;
    score: number;
    reason: string;
    source?: string | null;
  }>;
}

export interface AuditEntry {
  id?: number;
  request_id?: string;
  timestamp: string;
  scan_type: "input" | "output" | "rag";
  decision: Decision;
  attack_category: AttackCategory;
  score: number;
  reason: string;
  latency_ms: number;
  text_snippet: string;
}

export interface AuditStats {
  total: number;
  blocked: number;
  warned: number;
  allowed: number;
  by_category: Record<string, number>;
  by_layer: Record<string, number>;
  avg_latency_ms: number;
}

export interface AttackVector {
  id: string;
  category: AttackCategory;
  prompt: string;
  description: string;
  expected_decision: Decision;
}

export interface RedTeamRunItem {
  id: string;
  category: string;
  description: string;
  prompt: string;
  expected_decision: string;
  actual_decision: string;
  score: number;
  latency_ms: number;
  passed: boolean;
  reason: string;
}

export interface RedTeamResponse {
  total: number;
  passed: number;
  failed: number;
  detection_rate: number;
  category_stats: Record<string, { total: number; passed: number; failed: number }>;
  results: RedTeamRunItem[];
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${endpoint}`;
  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {}),
  };

  const res = await fetch(url, { ...options, headers });
  if (!res.ok) {
    const errorBody = await res.text().catch(() => "");
    throw new Error(`API error ${res.status}: ${errorBody || res.statusText}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  async health(): Promise<{ status: string; service: string }> {
    return request("/v1/health");
  },

  async scanInput(text: string, context?: string, requestId?: string): Promise<ScanResult> {
    return request("/v1/scan/input", {
      method: "POST",
      body: JSON.stringify({ text, context, request_id: requestId }),
    });
  },

  async scanOutput(text: string, requestId?: string): Promise<ScanResult> {
    return request("/v1/scan/output", {
      method: "POST",
      body: JSON.stringify({ text, request_id: requestId }),
    });
  },

  async scanRag(documents: RagDocument[]): Promise<RagScanResult> {
    return request("/v1/scan/rag", {
      method: "POST",
      body: JSON.stringify({ documents }),
    });
  },

  async getAudit(params?: {
    limit?: number;
    offset?: number;
    decision?: string;
    attack_category?: string;
  }): Promise<{ entries: AuditEntry[]; count: number }> {
    const q = new URLSearchParams();
    if (params?.limit) q.set("limit", String(params.limit));
    if (params?.offset) q.set("offset", String(params.offset));
    if (params?.decision && params.decision !== "ALL") q.set("decision", params.decision);
    if (params?.attack_category && params.attack_category !== "ALL") {
      q.set("attack_category", params.attack_category);
    }
    const queryStr = q.toString() ? `?${q.toString()}` : "";
    return request(`/v1/audit${queryStr}`);
  },

  async getStats(): Promise<AuditStats> {
    return request("/v1/audit/stats");
  },

  async getRedTeamAttacks(): Promise<{
    total: number;
    categories: Record<string, number>;
    attacks: AttackVector[];
  }> {
    return request("/v1/redteam/attacks");
  },

  async runRedTeam(category?: string, attackIds?: string[]): Promise<RedTeamResponse> {
    return request("/v1/redteam/run", {
      method: "POST",
      body: JSON.stringify({ category, attack_ids: attackIds }),
    });
  },
};
