"use client";

import React, { useEffect, useState } from "react";
import {
  ShieldAlert,
  Flame,
  Terminal,
  Activity,
  BarChart3,
  Code2,
  ExternalLink,
  Shield,
  Zap,
} from "lucide-react";
import { api, API_BASE } from "../lib/api";

export type NavTab = "scanner" | "redteam" | "audit" | "stats" | "developer";

interface NavbarProps {
  activeTab: NavTab;
  onTabChange: (tab: NavTab) => void;
}

export const Navbar: React.FC<NavbarProps> = ({ activeTab, onTabChange }) => {
  const [gatewayStatus, setGatewayStatus] = useState<"online" | "offline" | "checking">("checking");
  const [latency, setLatency] = useState<number | null>(null);

  useEffect(() => {
    let isMounted = true;

    async function pingGateway() {
      const start = performance.now();
      try {
        await api.health();
        const duration = Math.round(performance.now() - start);
        if (isMounted) {
          setGatewayStatus("online");
          setLatency(duration);
        }
      } catch (err) {
        if (isMounted) {
          setGatewayStatus("offline");
          setLatency(null);
        }
      }
    }

    pingGateway();
    const interval = setInterval(pingGateway, 10000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  return (
    <header style={{
      borderBottom: "1px solid var(--border-subtle)",
      background: "rgba(10, 14, 23, 0.85)",
      backdropFilter: "blur(16px)",
      position: "sticky",
      top: 0,
      zIndex: 100,
      padding: "0.75rem 2rem",
    }}>
      <div style={{
        maxWidth: 1400,
        margin: "0 auto",
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        flexWrap: "wrap",
        gap: "1rem",
      }}>
        {/* Brand */}
        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          <div style={{
            width: 42,
            height: 42,
            borderRadius: "var(--radius-md)",
            background: "linear-gradient(135deg, #ef4444 0%, #f97316 50%, #eab308 100%)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            boxShadow: "0 0 20px rgba(239, 68, 68, 0.4)",
          }}>
            <Flame size={24} color="#ffffff" />
          </div>
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <span style={{ fontSize: "1.2rem", fontWeight: 800, letterSpacing: "-0.02em", color: "#ffffff" }}>
                LLM FIREWALL
              </span>
              <span style={{
                fontSize: "0.65rem",
                padding: "0.15rem 0.45rem",
                background: "rgba(99, 102, 241, 0.15)",
                color: "var(--color-indigo)",
                borderRadius: "var(--radius-full)",
                border: "1px solid rgba(99, 102, 241, 0.3)",
                fontWeight: 700,
                fontFamily: "var(--font-mono)",
              }}>
                v0.1 PROXY
              </span>
            </div>
            <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.1rem" }}>
              Neural Prompt Guardrail &amp; RAG Defense
            </p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{
          display: "flex",
          alignItems: "center",
          gap: "0.4rem",
          background: "rgba(255, 255, 255, 0.03)",
          padding: "0.3rem",
          borderRadius: "var(--radius-full)",
          border: "1px solid var(--border-subtle)",
        }}>
          <TabButton
            active={activeTab === "scanner"}
            onClick={() => onTabChange("scanner")}
            icon={<Shield size={16} />}
            label="Threat Scanner"
          />
          <TabButton
            active={activeTab === "redteam"}
            onClick={() => onTabChange("redteam")}
            icon={<ShieldAlert size={16} />}
            label="Red-Team Suite"
          />
          <TabButton
            active={activeTab === "audit"}
            onClick={() => onTabChange("audit")}
            icon={<Activity size={16} />}
            label="Audit Log"
          />
          <TabButton
            active={activeTab === "stats"}
            onClick={() => onTabChange("stats")}
            icon={<BarChart3 size={16} />}
            label="Statistics"
          />
          <TabButton
            active={activeTab === "developer"}
            onClick={() => onTabChange("developer")}
            icon={<Code2 size={16} />}
            label="API & Docs"
          />
        </nav>

        {/* Right Side: Gateway Status & Swagger Link */}
        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          {/* Status Indicator */}
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: "0.6rem",
            background: "rgba(255, 255, 255, 0.04)",
            border: "1px solid var(--border-subtle)",
            padding: "0.4rem 0.8rem",
            borderRadius: "var(--radius-full)",
            fontSize: "0.75rem",
            fontFamily: "var(--font-mono)",
          }}>
            <span
              className={`pulsing-dot ${
                gatewayStatus === "online" ? "online" : gatewayStatus === "offline" ? "offline" : ""
              }`}
              style={{
                backgroundColor:
                  gatewayStatus === "online"
                    ? "var(--color-allow)"
                    : gatewayStatus === "offline"
                    ? "var(--color-block)"
                    : "var(--color-warn)",
              }}
            />
            <span style={{ color: gatewayStatus === "online" ? "var(--color-allow)" : "var(--text-secondary)" }}>
              {gatewayStatus === "online" ? "GATEWAY LIVE" : gatewayStatus === "offline" ? "BACKEND OFFLINE" : "CONNECTING..."}
            </span>
            {latency !== null && (
              <span style={{ color: "var(--text-muted)" }}>{latency}ms</span>
            )}
          </div>

          <a
            href={`${API_BASE}/docs`}
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
              padding: "0.45rem 0.85rem",
              fontSize: "0.8rem",
              fontWeight: 500,
              color: "var(--text-secondary)",
              background: "rgba(255, 255, 255, 0.05)",
              border: "1px solid var(--border-subtle)",
              borderRadius: "var(--radius-md)",
              transition: "all var(--transition-fast)",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "rgba(255, 255, 255, 0.1)";
              e.currentTarget.style.color = "#ffffff";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)";
              e.currentTarget.style.color = "var(--text-secondary)";
            }}
          >
            <span>FastAPI Docs</span>
            <ExternalLink size={14} />
          </a>
        </div>
      </div>
    </header>
  );
};

interface TabButtonProps {
  active: boolean;
  onClick: () => void;
  icon: React.ReactNode;
  label: string;
}

const TabButton: React.FC<TabButtonProps> = ({ active, onClick, icon, label }) => {
  return (
    <button
      onClick={onClick}
      style={{
        display: "flex",
        alignItems: "center",
        gap: "0.5rem",
        padding: "0.45rem 0.95rem",
        borderRadius: "var(--radius-full)",
        border: "none",
        cursor: "pointer",
        fontSize: "0.82rem",
        fontWeight: active ? 600 : 500,
        color: active ? "#ffffff" : "var(--text-secondary)",
        background: active
          ? "linear-gradient(135deg, rgba(99, 102, 241, 0.35) 0%, rgba(6, 182, 212, 0.25) 100%)"
          : "transparent",
        boxShadow: active ? "0 0 12px rgba(99, 102, 241, 0.25), inset 0 0 0 1px rgba(255, 255, 255, 0.15)" : "none",
        transition: "all var(--transition-fast)",
      }}
      onMouseEnter={(e) => {
        if (!active) {
          e.currentTarget.style.color = "#ffffff";
          e.currentTarget.style.background = "rgba(255, 255, 255, 0.05)";
        }
      }}
      onMouseLeave={(e) => {
        if (!active) {
          e.currentTarget.style.color = "var(--text-secondary)";
          e.currentTarget.style.background = "transparent";
        }
      }}
    >
      {icon}
      <span>{label}</span>
    </button>
  );
};
