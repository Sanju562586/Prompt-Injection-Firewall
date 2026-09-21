'use client';

import React from 'react';
import { ShieldCheck, ShieldAlert, Zap, Layers } from 'lucide-react';

interface StatsProps {
  totalRequests: number;
  totalBlocked: number;
  blockRate: number;
  avgLatencyMs: number;
  activeRulesCount: number;
}

export default function MetricsOverview({
  totalRequests,
  totalBlocked,
  blockRate,
  avgLatencyMs,
  activeRulesCount,
}: StatsProps) {
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))',
      gap: '16px',
      marginBottom: '24px',
    }}>
      <div style={cardStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={labelStyle}>Guarded Requests</span>
          <ShieldCheck size={18} color="var(--primary-light)" />
        </div>
        <div style={valStyle}>{totalRequests}</div>
        <div style={subStyle}>Scanned by 5 security layers</div>
      </div>

      <div style={cardStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={labelStyle}>Threat Block Rate</span>
          <ShieldAlert size={18} color="var(--danger)" />
        </div>
        <div style={{ ...valStyle, color: 'var(--danger)' }}>{blockRate.toFixed(1)}%</div>
        <div style={subStyle}>{totalBlocked} malicious payloads halted</div>
      </div>

      <div style={cardStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={labelStyle}>Pipeline Latency</span>
          <Zap size={18} color="var(--cyan)" />
        </div>
        <div style={{ ...valStyle, color: 'var(--cyan)' }}>{avgLatencyMs.toFixed(1)} ms</div>
        <div style={subStyle}>DeBERTa ML + Regex + RAG + Output</div>
      </div>

      <div style={cardStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={labelStyle}>Active Threat Signatures</span>
          <Layers size={18} color="var(--success)" />
        </div>
        <div style={{ ...valStyle, color: 'var(--success)' }}>{activeRulesCount}</div>
        <div style={subStyle}>High-precision rules & heuristics</div>
      </div>
    </div>
  );
}

const cardStyle: React.CSSProperties = {
  background: 'var(--bg-card)',
  backdropFilter: 'blur(14px)',
  border: '1px solid var(--border-subtle)',
  borderRadius: '14px',
  padding: '18px 22px',
  transition: 'all 0.2s ease',
};

const labelStyle: React.CSSProperties = {
  fontSize: '0.82rem',
  color: 'var(--text-muted)',
  fontWeight: 500,
  marginBottom: '4px',
};

const valStyle: React.CSSProperties = {
  fontSize: '1.9rem',
  fontWeight: 800,
  letterSpacing: '-0.02em',
};

const subStyle: React.CSSProperties = {
  fontSize: '0.75rem',
  color: 'var(--text-dim)',
  marginTop: '4px',
};
