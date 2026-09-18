"use client";

import React, { useEffect, useState } from "react";
import {
  Activity,
  RefreshCw,
  Search,
  Filter,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Clock,
  Eye,
  FileText,
  X,
} from "lucide-react";
import { api, AuditEntry } from "../lib/api";

export const AuditTab: React.FC = () => {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [decisionFilter, setDecisionFilter] = useState("ALL");
  const [categoryFilter, setCategoryFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [limit, setLimit] = useState(50);
  const [selectedEntry, setSelectedEntry] = useState<AuditEntry | null>(null);

  const fetchAudit = async () => {
    setLoading(true);
    try {
      const data = await api.getAudit({
        limit,
        decision: decisionFilter,
        attack_category: categoryFilter,
      });
      setEntries(data.entries);
    } catch (err) {
      console.error("Failed to fetch audit log:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAudit();
  }, [decisionFilter, categoryFilter, limit]);

  const filteredEntries = entries.filter((e) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    return (
      e.text_snippet.toLowerCase().includes(q) ||
      e.reason.toLowerCase().includes(q) ||
      e.attack_category.toLowerCase().includes(q)
    );
  });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      {/* Header & Controls */}
      <div
        className="card"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "1rem",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Activity size={20} color="var(--color-indigo)" />
            <h2 style={{ fontSize: "1.3rem", fontWeight: 800, color: "#ffffff" }}>
              Forensic Audit Stream
            </h2>
          </div>
          <p style={{ fontSize: "0.82rem", color: "var(--text-secondary)", marginTop: "0.2rem" }}>
            Every incoming prompt, LLM response, and RAG document is recorded in the SQLite audit ledger with privacy redactions.
          </p>
        </div>

        <button
          onClick={fetchAudit}
          disabled={loading}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "0.5rem",
            padding: "0.55rem 1.1rem",
            background: "rgba(255, 255, 255, 0.05)",
            border: "1px solid var(--border-medium)",
            borderRadius: "var(--radius-md)",
            color: "#ffffff",
            fontSize: "0.82rem",
            fontWeight: 600,
            cursor: "pointer",
            transition: "all var(--transition-fast)",
          }}
        >
          <RefreshCw size={15} className={loading ? "spin" : ""} />
          <span>Refresh Ledger</span>
        </button>
      </div>

      {/* Filter Toolbar */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "1rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", flexWrap: "wrap" }}>
          {/* Decision Filter */}
          <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 600 }}>Decision:</span>
            <select
              value={decisionFilter}
              onChange={(e) => setDecisionFilter(e.target.value)}
              style={{
                background: "var(--bg-input)",
                color: "#ffffff",
                border: "1px solid var(--border-subtle)",
                borderRadius: "var(--radius-sm)",
                padding: "0.35rem 0.65rem",
                fontSize: "0.78rem",
                outline: "none",
              }}
            >
              <option value="ALL">All Decisions</option>
              <option value="BLOCK">BLOCK 🚫</option>
              <option value="WARN">WARN ⚠️</option>
              <option value="ALLOW">ALLOW ✅</option>
            </select>
          </div>

          {/* Category Filter */}
          <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 600 }}>Category:</span>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              style={{
                background: "var(--bg-input)",
                color: "#ffffff",
                border: "1px solid var(--border-subtle)",
                borderRadius: "var(--radius-sm)",
                padding: "0.35rem 0.65rem",
                fontSize: "0.78rem",
                outline: "none",
              }}
            >
              <option value="ALL">All Categories</option>
              <option value="direct_injection">Direct Injection</option>
              <option value="jailbreak">Jailbreak</option>
              <option value="role_hijack">Role Hijack</option>
              <option value="indirect_injection">Indirect Injection</option>
              <option value="token_smuggling">Token Smuggling</option>
              <option value="pii_exfiltration">PII Exfiltration</option>
              <option value="rag_poisoning">RAG Poisoning</option>
            </select>
          </div>

          {/* Rows Limit */}
          <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
            <span style={{ fontSize: "0.75rem", color: "var(--text-muted)", fontWeight: 600 }}>Limit:</span>
            <select
              value={limit}
              onChange={(e) => setLimit(Number(e.target.value))}
              style={{
                background: "var(--bg-input)",
                color: "#ffffff",
                border: "1px solid var(--border-subtle)",
                borderRadius: "var(--radius-sm)",
                padding: "0.35rem 0.65rem",
                fontSize: "0.78rem",
                outline: "none",
              }}
            >
              <option value={25}>25 rows</option>
              <option value={50}>50 rows</option>
              <option value={100}>100 rows</option>
              <option value={250}>250 rows</option>
            </select>
          </div>
        </div>

        {/* Search */}
        <div style={{ position: "relative", minWidth: 260 }}>
          <Search size={15} style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)" }} />
          <input
            type="text"
            placeholder="Search snippet or reason..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: "100%",
              padding: "0.45rem 0.75rem 0.45rem 2.2rem",
              borderRadius: "var(--radius-md)",
              border: "1px solid var(--border-subtle)",
              background: "var(--bg-input)",
              color: "#ffffff",
              fontSize: "0.8rem",
              outline: "none",
            }}
          />
        </div>
      </div>

      {/* Audit Table */}
      <div className="card" style={{ padding: 0, overflow: "hidden" }}>
        <div style={{ overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", textAlign: "left", fontSize: "0.82rem" }}>
            <thead>
              <tr style={{ background: "rgba(255, 255, 255, 0.02)", borderBottom: "1px solid var(--border-subtle)", color: "var(--text-muted)", textTransform: "uppercase", fontSize: "0.7rem", letterSpacing: "0.05em" }}>
                <th style={{ padding: "0.85rem 1rem" }}>Time</th>
                <th style={{ padding: "0.85rem 1rem" }}>Verdict</th>
                <th style={{ padding: "0.85rem 1rem" }}>Stage</th>
                <th style={{ padding: "0.85rem 1rem" }}>Category</th>
                <th style={{ padding: "0.85rem 1rem" }}>Score</th>
                <th style={{ padding: "0.85rem 1rem" }}>Latency</th>
                <th style={{ padding: "0.85rem 1rem" }}>Snippet</th>
                <th style={{ padding: "0.85rem 1rem", textAlign: "center" }}>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {filteredEntries.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
                    No audit records match your filters. Run tests in the Threat Scanner or Red-Team tab to generate logs.
                  </td>
                </tr>
              ) : (
                filteredEntries.map((e, idx) => (
                  <tr
                    key={e.id || idx}
                    style={{
                      borderBottom: "1px solid var(--border-subtle)",
                      transition: "background var(--transition-fast)",
                    }}
                    onMouseEnter={(ev) => (ev.currentTarget.style.background = "rgba(255, 255, 255, 0.02)")}
                    onMouseLeave={(ev) => (ev.currentTarget.style.background = "transparent")}
                  >
                    <td style={{ padding: "0.75rem 1rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)", fontSize: "0.78rem" }}>
                      {e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : "--"}
                    </td>

                    <td style={{ padding: "0.75rem 1rem" }}>
                      <span className={e.decision === "BLOCK" ? "badge badge-block" : e.decision === "WARN" ? "badge badge-warn" : "badge badge-allow"}>
                        {e.decision}
                      </span>
                    </td>

                    <td style={{ padding: "0.75rem 1rem", textTransform: "uppercase", fontFamily: "var(--font-mono)", fontSize: "0.75rem", color: "var(--text-secondary)" }}>
                      {e.scan_type}
                    </td>

                    <td style={{ padding: "0.75rem 1rem", color: "#ffffff", fontWeight: 500 }}>
                      {e.attack_category.replace("_", " ")}
                    </td>

                    <td style={{ padding: "0.75rem 1rem", fontFamily: "var(--font-mono)" }}>
                      {(e.score * 100).toFixed(1)}%
                    </td>

                    <td style={{ padding: "0.75rem 1rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                      {e.latency_ms.toFixed(1)}ms
                    </td>

                    <td style={{ padding: "0.75rem 1rem", maxWidth: 300, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", color: "var(--text-secondary)" }}>
                      {e.text_snippet}
                    </td>

                    <td style={{ padding: "0.75rem 1rem", textAlign: "center" }}>
                      <button
                        onClick={() => setSelectedEntry(e)}
                        style={{
                          background: "none",
                          border: "none",
                          color: "var(--color-cyan)",
                          cursor: "pointer",
                          padding: "0.2rem 0.5rem",
                          borderRadius: 4,
                        }}
                        title="Inspect full record"
                      >
                        <Eye size={16} />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Inspection Modal / Drawer */}
      {selectedEntry && (
        <div
          style={{
            position: "fixed",
            top: 0,
            left: 0,
            width: "100vw",
            height: "100vh",
            background: "rgba(0, 0, 0, 0.75)",
            backdropFilter: "blur(6px)",
            zIndex: 1000,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "1.5rem",
          }}
          onClick={() => setSelectedEntry(null)}
        >
          <div
            className="card"
            style={{
              maxWidth: 650,
              width: "100%",
              background: "var(--bg-card)",
              border: "1px solid var(--border-medium)",
              boxShadow: "0 10px 40px rgba(0, 0, 0, 0.6)",
              display: "flex",
              flexDirection: "column",
              gap: "1.25rem",
            }}
            onClick={(e) => e.stopPropagation()}
          >
            <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                <span className={selectedEntry.decision === "BLOCK" ? "badge badge-block" : selectedEntry.decision === "WARN" ? "badge badge-warn" : "badge badge-allow"}>
                  {selectedEntry.decision}
                </span>
                <h3 style={{ fontSize: "1.1rem", fontWeight: 700, color: "#ffffff" }}>
                  Audit Forensic Snapshot #{selectedEntry.id || "LOG"}
                </h3>
              </div>
              <button
                onClick={() => setSelectedEntry(null)}
                style={{ background: "none", border: "none", color: "var(--text-muted)", cursor: "pointer" }}
              >
                <X size={20} />
              </button>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem", fontSize: "0.82rem" }}>
              <div style={{ background: "rgba(255, 255, 255, 0.02)", padding: "0.75rem", borderRadius: "var(--radius-md)" }}>
                <span style={{ color: "var(--text-muted)" }}>Threat Category:</span>
                <div style={{ fontWeight: 600, color: "#ffffff", marginTop: "0.2rem" }}>{selectedEntry.attack_category}</div>
              </div>
              <div style={{ background: "rgba(255, 255, 255, 0.02)", padding: "0.75rem", borderRadius: "var(--radius-md)" }}>
                <span style={{ color: "var(--text-muted)" }}>Pipeline Latency:</span>
                <div style={{ fontWeight: 600, color: "#ffffff", marginTop: "0.2rem", fontFamily: "var(--font-mono)" }}>{selectedEntry.latency_ms.toFixed(2)} ms</div>
              </div>
              <div style={{ background: "rgba(255, 255, 255, 0.02)", padding: "0.75rem", borderRadius: "var(--radius-md)" }}>
                <span style={{ color: "var(--text-muted)" }}>Confidence Score:</span>
                <div style={{ fontWeight: 600, color: "#ffffff", marginTop: "0.2rem", fontFamily: "var(--font-mono)" }}>{(selectedEntry.score * 100).toFixed(2)}%</div>
              </div>
              <div style={{ background: "rgba(255, 255, 255, 0.02)", padding: "0.75rem", borderRadius: "var(--radius-md)" }}>
                <span style={{ color: "var(--text-muted)" }}>Trace Request ID:</span>
                <div style={{ fontWeight: 600, color: "#ffffff", marginTop: "0.2rem", fontFamily: "var(--font-mono)" }}>{selectedEntry.request_id || "anonymous"}</div>
              </div>
            </div>

            <div>
              <div style={{ fontSize: "0.75rem", fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "0.3rem" }}>
                Defense Verdict Rationale
              </div>
              <p style={{ fontSize: "0.88rem", color: "#ffffff", lineHeight: 1.5 }}>
                {selectedEntry.reason}
              </p>
            </div>

            <div>
              <div style={{ fontSize: "0.75rem", fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "0.3rem" }}>
                Recorded Text Snippet
              </div>
              <pre className="code-block" style={{ whiteSpace: "pre-wrap" }}>
                {selectedEntry.text_snippet}
              </pre>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
