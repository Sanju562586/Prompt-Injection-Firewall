"use client";

import React, { useEffect, useState } from "react";
import {
  BarChart3,
  Shield,
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Clock,
  RefreshCw,
  Layers,
  PieChart,
} from "lucide-react";
import { api, AuditStats } from "../lib/api";

export const StatsTab: React.FC = () => {
  const [stats, setStats] = useState<AuditStats | null>(null);
  const [loading, setLoading] = useState(false);

  const fetchStats = async () => {
    setLoading(true);
    try {
      const data = await api.getStats();
      setStats(data);
    } catch (err) {
      console.error("Failed to fetch detection statistics:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  if (!stats) {
    return (
      <div className="card" style={{ padding: "3rem", textAlign: "center", color: "var(--text-muted)" }}>
        Loading firewall telemetry...
      </div>
    );
  }

  const total = stats.total || 0;
  const blockPct = total > 0 ? (stats.blocked / total) * 100 : 0;
  const warnPct = total > 0 ? (stats.warned / total) * 100 : 0;
  const allowPct = total > 0 ? (stats.allowed / total) * 100 : 0;

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      {/* Header */}
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
            <BarChart3 size={20} color="var(--color-cyan)" />
            <h2 style={{ fontSize: "1.3rem", fontWeight: 800, color: "#ffffff" }}>
              Firewall Threat Intelligence &amp; Analytics
            </h2>
          </div>
          <p style={{ fontSize: "0.82rem", color: "var(--text-secondary)", marginTop: "0.2rem" }}>
            Aggregate telemetry on prompt injection block rates, layer triggers, and adversary vectors.
          </p>
        </div>

        <button
          onClick={fetchStats}
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
          }}
        >
          <RefreshCw size={15} className={loading ? "spin" : ""} />
          <span>Refresh Analytics</span>
        </button>
      </div>

      {/* KPI Cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "1rem" }}>
        <div className="card" style={{ padding: "1.25rem" }}>
          <div style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--text-muted)", fontWeight: 700 }}>
            Total Pipeline Scans
          </div>
          <div style={{ fontSize: "2.2rem", fontWeight: 800, color: "#ffffff", marginTop: "0.2rem" }}>
            {total}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.4rem" }}>
            Audit log entries recorded
          </div>
        </div>

        <div className="card" style={{ padding: "1.25rem", borderLeft: "4px solid var(--color-block)" }}>
          <div style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--color-block)", fontWeight: 700 }}>
            🚫 Injections Blocked
          </div>
          <div style={{ fontSize: "2.2rem", fontWeight: 800, color: "var(--color-block)", marginTop: "0.2rem" }}>
            {stats.blocked}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.4rem" }}>
            {blockPct.toFixed(1)}% of all traffic
          </div>
        </div>

        <div className="card" style={{ padding: "1.25rem", borderLeft: "4px solid var(--color-warn)" }}>
          <div style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--color-warn)", fontWeight: 700 }}>
            ⚠️ Suspicious Warned
          </div>
          <div style={{ fontSize: "2.2rem", fontWeight: 800, color: "var(--color-warn)", marginTop: "0.2rem" }}>
            {stats.warned}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.4rem" }}>
            {warnPct.toFixed(1)}% of all traffic
          </div>
        </div>

        <div className="card" style={{ padding: "1.25rem", borderLeft: "4px solid var(--color-allow)" }}>
          <div style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--color-allow)", fontWeight: 700 }}>
            ✅ Clean Traffic Allowed
          </div>
          <div style={{ fontSize: "2.2rem", fontWeight: 800, color: "var(--color-allow)", marginTop: "0.2rem" }}>
            {stats.allowed}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.4rem" }}>
            {allowPct.toFixed(1)}% pass-through rate
          </div>
        </div>
      </div>

      {/* Visual Charts Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
        {/* Decision Breakdown Chart */}
        <div className="card" style={{ padding: "1.5rem" }}>
          <h4 style={{ fontSize: "0.95rem", fontWeight: 700, color: "#ffffff", marginBottom: "1.25rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <PieChart size={18} color="var(--color-cyan)" />
            Verdict Traffic Distribution
          </h4>

          {total === 0 ? (
            <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", padding: "2rem 0", textAlign: "center" }}>
              No scan data recorded yet.
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
              <div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", marginBottom: "0.3rem" }}>
                  <span style={{ color: "var(--color-block)", fontWeight: 600 }}>BLOCK (Malicious)</span>
                  <span style={{ fontFamily: "var(--font-mono)", color: "#ffffff" }}>{stats.blocked} ({blockPct.toFixed(1)}%)</span>
                </div>
                <div style={{ height: 8, backgroundColor: "rgba(255, 255, 255, 0.08)", borderRadius: 4, overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${blockPct}%`, backgroundColor: "var(--color-block)", borderRadius: 4 }} />
                </div>
              </div>

              <div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", marginBottom: "0.3rem" }}>
                  <span style={{ color: "var(--color-warn)", fontWeight: 600 }}>WARN (Suspicious)</span>
                  <span style={{ fontFamily: "var(--font-mono)", color: "#ffffff" }}>{stats.warned} ({warnPct.toFixed(1)}%)</span>
                </div>
                <div style={{ height: 8, backgroundColor: "rgba(255, 255, 255, 0.08)", borderRadius: 4, overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${warnPct}%`, backgroundColor: "var(--color-warn)", borderRadius: 4 }} />
                </div>
              </div>

              <div>
                <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", marginBottom: "0.3rem" }}>
                  <span style={{ color: "var(--color-allow)", fontWeight: 600 }}>ALLOW (Clean)</span>
                  <span style={{ fontFamily: "var(--font-mono)", color: "#ffffff" }}>{stats.allowed} ({allowPct.toFixed(1)}%)</span>
                </div>
                <div style={{ height: 8, backgroundColor: "rgba(255, 255, 255, 0.08)", borderRadius: 4, overflow: "hidden" }}>
                  <div style={{ height: "100%", width: `${allowPct}%`, backgroundColor: "var(--color-allow)", borderRadius: 4 }} />
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Attacks by Category */}
        <div className="card" style={{ padding: "1.5rem" }}>
          <h4 style={{ fontSize: "0.95rem", fontWeight: 700, color: "#ffffff", marginBottom: "1.25rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <ShieldAlert size={18} color="var(--color-indigo)" />
            Detections by Attack Category
          </h4>

          {stats.by_category && Object.keys(stats.by_category).length > 0 ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
              {Object.entries(stats.by_category)
                .sort((a, b) => b[1] - a[1])
                .map(([cat, count]) => {
                  const maxCount = Math.max(...Object.values(stats.by_category));
                  const widthPct = maxCount > 0 ? (count / maxCount) * 100 : 0;
                  return (
                    <div key={cat}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.78rem", marginBottom: "0.25rem" }}>
                        <span style={{ color: "#ffffff", textTransform: "capitalize", fontWeight: 500 }}>
                          {cat.replace("_", " ")}
                        </span>
                        <span style={{ fontFamily: "var(--font-mono)", color: "var(--text-secondary)" }}>
                          {count} attacks
                        </span>
                      </div>
                      <div style={{ height: 6, backgroundColor: "rgba(255, 255, 255, 0.08)", borderRadius: 3, overflow: "hidden" }}>
                        <div style={{ height: "100%", width: `${widthPct}%`, background: "linear-gradient(90deg, #6366f1, #06b6d4)", borderRadius: 3 }} />
                      </div>
                    </div>
                  );
                })}
            </div>
          ) : (
            <div style={{ color: "var(--text-muted)", fontSize: "0.85rem", padding: "2rem 0", textAlign: "center" }}>
              No threat detections recorded yet. Run tests to populate attack telemetry.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
