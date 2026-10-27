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
          <div style={iconBoxStyle}>
            <ShieldCheck size={18} color="var(--primary)" />
          </div>
        </div>
        <div style={valStyle}>{totalRequests}</div>
        <div style={subStyle}>Scanned by 5 security layers</div>
      </div>

      <div style={cardStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={labelStyle}>Threat Block Rate</span>
          <div style={{ ...iconBoxStyle, background: 'var(--danger-bg)' }}>
            <ShieldAlert size={18} color="var(--danger)" />
          </div>
        </div>
        <div style={{ ...valStyle, color: 'var(--danger)' }}>{blockRate.toFixed(1)}%</div>
        <div style={subStyle}>{totalBlocked} malicious payloads halted</div>
      </div>

      <div style={cardStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={labelStyle}>Pipeline Latency</span>
          <div style={iconBoxStyle}>
            <Zap size={18} color="var(--primary)" />
          </div>
        </div>
        <div style={{ ...valStyle, color: 'var(--primary)' }}>{avgLatencyMs.toFixed(1)} ms</div>
        <div style={subStyle}>DeBERTa ML + Heuristics + RAG</div>
      </div>

      <div style={cardStyle}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={labelStyle}>Active Threat Signatures</span>
          <div style={{ ...iconBoxStyle, background: 'var(--success-bg)' }}>
            <Layers size={18} color="var(--success)" />
          </div>
        </div>
        <div style={{ ...valStyle, color: 'var(--success)' }}>{activeRulesCount}</div>
        <div style={subStyle}>High-precision rules & heuristics</div>
      </div>
    </div>
  );
}

const cardStyle: React.CSSProperties = {
  background: '#ffffff',
  border: '1px solid var(--border-card)',
  borderRadius: '16px',
  padding: '18px 22px',
  boxShadow: 'var(--shadow-sm)',
  transition: 'all 0.2s ease',
};

const iconBoxStyle: React.CSSProperties = {
  width: '32px',
  height: '32px',
  borderRadius: '8px',
  background: 'var(--primary-bg)',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'center',
};

const labelStyle: React.CSSProperties = {
  fontSize: '0.82rem',
  color: 'var(--text-muted)',
  fontWeight: 600,
  marginBottom: '4px',
};

const valStyle: React.CSSProperties = {
  fontSize: '1.9rem',
  fontWeight: 800,
  letterSpacing: '-0.02em',
  color: 'var(--text-main)',
  marginTop: '4px',
};

const subStyle: React.CSSProperties = {
  fontSize: '0.75rem',
  color: 'var(--text-dim)',
  marginTop: '4px',
};
