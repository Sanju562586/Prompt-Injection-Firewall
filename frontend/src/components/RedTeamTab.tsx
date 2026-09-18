"use client";

import React, { useEffect, useState } from "react";
import {
  ShieldAlert,
  Play,
  CheckCircle2,
  XCircle,
  Search,
  Filter,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Zap,
  Target,
  BarChart2,
  Terminal,
} from "lucide-react";
import { api, AttackVector, RedTeamResponse, RedTeamRunItem } from "../lib/api";

export const RedTeamTab: React.FC = () => {
  const [attacks, setAttacks] = useState<AttackVector[]>([]);
  const [categories, setCategories] = useState<Record<string, number>>({});
  const [selectedCategory, setSelectedCategory] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<number>(0);
  const [results, setResults] = useState<RedTeamResponse | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<string | null>(null);

  // Load attack list on mount
  useEffect(() => {
    async function loadAttacks() {
      try {
        const data = await api.getRedTeamAttacks();
        setAttacks(data.attacks);
        setCategories(data.categories);
      } catch (err: any) {
        console.error("Failed to load red-team catalog:", err);
      }
    }
    loadAttacks();
  }, []);

  const handleRunAll = async () => {
    setRunning(true);
    setErrorMsg(null);
    setProgress(10);

    try {
      // Simulate visual progress while backend executes the suite
      const timer = setInterval(() => {
        setProgress((prev) => (prev < 90 ? prev + 15 : prev));
      }, 300);

      const data = await api.runRedTeam(selectedCategory === "all" ? undefined : selectedCategory);
      clearInterval(timer);
      setProgress(100);
      setResults(data);
    } catch (err: any) {
      setErrorMsg(err.message || "Failed to execute red-team suite.");
    } finally {
      setRunning(false);
    }
  };

  // Filter results or attacks for display
  const itemsToDisplay = results
    ? results.results.filter((item) => {
        const matchesCategory =
          selectedCategory === "all" || item.category === selectedCategory;
        const matchesSearch =
          item.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
          item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
          item.prompt.toLowerCase().includes(searchQuery.toLowerCase());
        return matchesCategory && matchesSearch;
      })
    : attacks.filter((item) => {
        const matchesCategory =
          selectedCategory === "all" || item.category === selectedCategory;
        const matchesSearch =
          item.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
          item.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
          item.prompt.toLowerCase().includes(searchQuery.toLowerCase());
        return matchesCategory && matchesSearch;
      });

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      {/* Header Banner */}
      <div
        className="card"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          flexWrap: "wrap",
          gap: "1.5rem",
          background: "linear-gradient(135deg, rgba(239, 68, 68, 0.08) 0%, rgba(99, 102, 241, 0.06) 100%)",
          border: "1px solid rgba(239, 68, 68, 0.2)",
        }}
      >
        <div>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.4rem" }}>
            <span style={{ color: "var(--color-block)" }}><ShieldAlert size={22} /></span>
            <h2 style={{ fontSize: "1.4rem", fontWeight: 800, color: "#ffffff" }}>
              Red-Team Adversarial Suite
            </h2>
          </div>
          <p style={{ fontSize: "0.85rem", color: "var(--text-secondary)", maxWidth: 650 }}>
            Automated evaluation across 50 attack vectors covering direct injection, jailbreaks, role hijacking, indirect prompts, token smuggling, PII exfiltration, and RAG poisoning.
          </p>
        </div>

        <button
          onClick={handleRunAll}
          disabled={running}
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "0.6rem",
            padding: "0.85rem 1.85rem",
            borderRadius: "var(--radius-md)",
            border: "none",
            background: running
              ? "rgba(239, 68, 68, 0.3)"
              : "linear-gradient(135deg, #ef4444 0%, #f43f5e 50%, #e11d48 100%)",
            color: "#ffffff",
            fontWeight: 700,
            fontSize: "0.95rem",
            cursor: running ? "not-allowed" : "pointer",
            boxShadow: running ? "none" : "0 0 25px rgba(239, 68, 68, 0.4)",
            transition: "all var(--transition-normal)",
          }}
        >
          {running ? (
            <>
              <div style={{ width: 18, height: 18, border: "2px solid #ffffff", borderTopColor: "transparent", borderRadius: "50%", animation: "spin 0.8s linear infinite" }} />
              <span>Simulating Attacks...</span>
            </>
          ) : (
            <>
              <Play size={18} fill="#ffffff" />
              <span>Run Red-Team Evaluation</span>
            </>
          )}
        </button>
      </div>

      {/* Progress Bar when Running */}
      {running && (
        <div className="card" style={{ padding: "1rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", marginBottom: "0.4rem" }}>
            <span style={{ color: "var(--text-secondary)" }}>Executing neural firewall scans...</span>
            <span style={{ fontFamily: "var(--font-mono)", color: "var(--color-block)", fontWeight: 700 }}>{progress}%</span>
          </div>
          <div style={{ height: 6, backgroundColor: "rgba(255, 255, 255, 0.08)", borderRadius: 3, overflow: "hidden" }}>
            <div
              style={{
                height: "100%",
                width: `${progress}%`,
                background: "linear-gradient(90deg, #ef4444, #f59e0b, #10b981)",
                transition: "width 0.3s ease",
              }}
            />
          </div>
        </div>
      )}

      {errorMsg && (
        <div style={{ padding: "1rem", background: "var(--color-block-bg)", border: "1px solid var(--color-block-border)", borderRadius: "var(--radius-md)", color: "var(--color-block)", fontSize: "0.85rem" }}>
          {errorMsg}
        </div>
      )}

      {/* Scorecard Metrics (Shown after results or loaded) */}
      {results && (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "1rem" }}>
            <div className="card" style={{ padding: "1.25rem" }}>
              <div style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--text-muted)", fontWeight: 700 }}>Total Attacks Tested</div>
              <div style={{ fontSize: "2rem", fontWeight: 800, color: "#ffffff", marginTop: "0.2rem" }}>{results.total}</div>
            </div>

            <div className="card" style={{ padding: "1.25rem", borderLeft: "4px solid var(--color-allow)" }}>
              <div style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--color-allow)", fontWeight: 700 }}>✅ Detected &amp; Blocked</div>
              <div style={{ fontSize: "2rem", fontWeight: 800, color: "var(--color-allow)", marginTop: "0.2rem" }}>{results.passed}</div>
            </div>

            <div className="card" style={{ padding: "1.25rem", borderLeft: "4px solid var(--color-block)" }}>
              <div style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--color-block)", fontWeight: 700 }}>❌ Missed / Allowed</div>
              <div style={{ fontSize: "2rem", fontWeight: 800, color: "var(--color-block)", marginTop: "0.2rem" }}>{results.failed}</div>
            </div>

            <div className="card" style={{ padding: "1.25rem", background: "linear-gradient(135deg, rgba(16, 185, 129, 0.1) 0%, rgba(6, 182, 212, 0.1) 100%)", borderColor: "rgba(16, 185, 129, 0.3)" }}>
              <div style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "var(--color-cyan)", fontWeight: 700 }}>Overall Detection Rate</div>
              <div style={{ fontSize: "2rem", fontWeight: 800, color: results.detection_rate >= 80 ? "var(--color-allow)" : "var(--color-warn)", marginTop: "0.2rem" }}>
                {results.detection_rate.toFixed(1)}%
              </div>
            </div>
          </div>

          {/* Per-Category Detection Bar Breakdown */}
          {results.category_stats && (
            <div className="card" style={{ padding: "1.5rem" }}>
              <h4 style={{ fontSize: "0.95rem", fontWeight: 700, color: "#ffffff", marginBottom: "1rem" }}>
                Detection Rate by Threat Category
              </h4>
              <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: "1rem" }}>
                {Object.entries(results.category_stats).map(([cat, stat]: any) => {
                  const rate = stat.total > 0 ? (stat.passed / stat.total) * 100 : 0;
                  return (
                    <div key={cat} style={{ background: "rgba(255, 255, 255, 0.02)", padding: "0.85rem", borderRadius: "var(--radius-md)", border: "1px solid var(--border-subtle)" }}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", marginBottom: "0.4rem" }}>
                        <span style={{ fontWeight: 600, color: "#ffffff", textTransform: "capitalize" }}>{cat.replace("_", " ")}</span>
                        <span style={{ fontFamily: "var(--font-mono)", color: rate >= 80 ? "var(--color-allow)" : "var(--color-warn)", fontWeight: 700 }}>
                          {stat.passed}/{stat.total} ({rate.toFixed(0)}%)
                        </span>
                      </div>
                      <div style={{ height: 6, backgroundColor: "rgba(255, 255, 255, 0.08)", borderRadius: 3, overflow: "hidden" }}>
                        <div
                          style={{
                            height: "100%",
                            width: `${rate}%`,
                            backgroundColor: rate >= 80 ? "var(--color-allow)" : "var(--color-warn)",
                            borderRadius: 3,
                          }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </>
      )}

      {/* Filters & Search Toolbar */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "1rem" }}>
        {/* Category Pills */}
        <div style={{ display: "flex", flexWrap: "wrap", gap: "0.4rem" }}>
          <button
            onClick={() => setSelectedCategory("all")}
            style={{
              padding: "0.35rem 0.75rem",
              borderRadius: "var(--radius-full)",
              fontSize: "0.75rem",
              fontWeight: 600,
              cursor: "pointer",
              border: selectedCategory === "all" ? "1px solid var(--color-cyan)" : "1px solid var(--border-subtle)",
              background: selectedCategory === "all" ? "rgba(6, 182, 212, 0.15)" : "rgba(255, 255, 255, 0.03)",
              color: selectedCategory === "all" ? "#ffffff" : "var(--text-secondary)",
            }}
          >
            All Categories ({attacks.length})
          </button>

          {Object.entries(categories).map(([cat, count]) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              style={{
                padding: "0.35rem 0.75rem",
                borderRadius: "var(--radius-full)",
                fontSize: "0.75rem",
                fontWeight: 600,
                cursor: "pointer",
                border: selectedCategory === cat ? "1px solid var(--color-indigo)" : "1px solid var(--border-subtle)",
                background: selectedCategory === cat ? "rgba(99, 102, 241, 0.15)" : "rgba(255, 255, 255, 0.03)",
                color: selectedCategory === cat ? "#ffffff" : "var(--text-secondary)",
                textTransform: "capitalize",
              }}
            >
              {cat.replace("_", " ")} ({count})
            </button>
          ))}
        </div>

        {/* Search */}
        <div style={{ position: "relative", minWidth: 260 }}>
          <Search size={15} style={{ position: "absolute", left: 12, top: "50%", transform: "translateY(-50%)", color: "var(--text-muted)" }} />
          <input
            type="text"
            placeholder="Search attack ID, keyword..."
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

      {/* Attack Vectors List */}
      <div style={{ display: "flex", flexDirection: "column", gap: "0.6rem" }}>
        {itemsToDisplay.map((item: any) => {
          const isResult = results !== null;
          const isExpanded = expandedId === item.id;

          return (
            <div
              key={item.id}
              className="card"
              style={{
                padding: "1rem 1.25rem",
                cursor: "pointer",
                borderLeft: isResult
                  ? item.passed
                    ? "4px solid var(--color-allow)"
                    : "4px solid var(--color-block)"
                  : "1px solid var(--border-subtle)",
              }}
              onClick={() => setExpandedId(isExpanded ? null : item.id)}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: "0.75rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: "0.85rem", fontWeight: 700, color: "var(--color-cyan)" }}>
                    {item.id}
                  </span>
                  <span className="badge badge-neutral">{item.category.replace("_", " ")}</span>
                  <span style={{ fontSize: "0.88rem", fontWeight: 600, color: "#ffffff" }}>
                    {item.description}
                  </span>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
                  {isResult ? (
                    <>
                      <span className={item.passed ? "badge badge-allow" : "badge badge-block"}>
                        {item.passed ? <CheckCircle2 size={14} /> : <XCircle size={14} />}
                        {item.passed ? "DETECTED" : "MISSED"}
                      </span>
                      <span style={{ fontSize: "0.75rem", fontFamily: "var(--font-mono)", color: "var(--text-muted)" }}>
                        {(item.score * 100).toFixed(1)}% score · {item.latency_ms}ms
                      </span>
                    </>
                  ) : (
                    <span className="badge badge-neutral">Expected: {item.expected_decision}</span>
                  )}
                  {isExpanded ? <ChevronUp size={16} color="var(--text-muted)" /> : <ChevronDown size={16} color="var(--text-muted)" />}
                </div>
              </div>

              {/* Expandable Details */}
              {isExpanded && (
                <div style={{ marginTop: "1rem", paddingTop: "0.85rem", borderTop: "1px solid var(--border-subtle)", display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                  <div>
                    <div style={{ fontSize: "0.75rem", fontWeight: 700, textTransform: "uppercase", color: "var(--text-muted)", marginBottom: "0.3rem" }}>
                      Adversarial Prompt Payload
                    </div>
                    <pre className="code-block" style={{ whiteSpace: "pre-wrap" }}>
                      {item.prompt}
                    </pre>
                  </div>

                  {isResult && (
                    <div style={{ display: "flex", gap: "1.5rem", fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                      <div><b>Expected:</b> <span style={{ color: "var(--color-block)" }}>{item.expected_decision}</span></div>
                      <div><b>Firewall Verdict:</b> <span style={{ color: item.passed ? "var(--color-allow)" : "var(--color-block)" }}>{item.actual_decision}</span></div>
                      <div><b>Defense Diagnosis:</b> {item.reason}</div>
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
