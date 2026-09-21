'use client';

import React, { useState, useEffect } from 'react';
import { Code2, ShieldAlert } from 'lucide-react';

interface RuleItem {
  rule_id: string;
  name: string;
  attack_type: string;
  severity: string;
  description: string;
  pattern: string;
  confidence: number;
}

export default function RulesExplorer() {
  const [rules, setRules] = useState<RuleItem[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const fetchRules = async () => {
      setLoading(true);
      try {
        const res = await fetch('/api/dashboard/rules');
        if (res.ok) {
          const data = await res.json();
          setRules(data);
        }
      } catch (e) {
        console.error('Rules fetch error', e);
      } finally {
        setLoading(false);
      }
    };
    fetchRules();
  }, []);

  return (
    <div style={cardStyle}>
      <div style={titleStyle}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Code2 size={20} color="var(--primary-light)" />
          <span>Active Threat Signatures & Heuristics (Module 1)</span>
        </div>
        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem', color: 'var(--text-muted)' }}>
          {rules.length} Signatures Active
        </span>
      </div>

      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-muted)' }}>
              <th style={{ padding: '10px 14px' }}>Rule ID</th>
              <th style={{ padding: '10px 14px' }}>Threat Name & Description</th>
              <th style={{ padding: '10px 14px' }}>Attack Type</th>
              <th style={{ padding: '10px 14px' }}>Severity</th>
              <th style={{ padding: '10px 14px' }}>Confidence</th>
              <th style={{ padding: '10px 14px' }}>Regex Signature Pattern</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => {
              const isCrit = r.severity === 'CRITICAL';
              return (
                <tr key={r.rule_id} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                  <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', color: 'var(--primary-light)', fontWeight: 600 }}>
                    {r.rule_id}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <strong>{r.name}</strong>
                    <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)' }}>{r.description}</div>
                  </td>
                  <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', color: 'var(--cyan)', fontSize: '0.78rem' }}>
                    {r.attack_type}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: '6px',
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      background: isCrit ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                      color: isCrit ? '#f87171' : '#fbbf24',
                      border: `1px solid ${isCrit ? 'rgba(239, 68, 68, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`,
                    }}>
                      {r.severity}
                    </span>
                  </td>
                  <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)' }}>
                    {(r.confidence * 100).toFixed(0)}%
                  </td>
                  <td style={{
                    padding: '10px 14px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.74rem',
                    color: 'var(--text-dim)',
                    maxWidth: '320px',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}>
                    {r.pattern}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const cardStyle: React.CSSProperties = {
  background: 'var(--bg-card)',
  backdropFilter: 'blur(14px)',
  border: '1px solid var(--border-subtle)',
  borderRadius: '16px',
  padding: '22px',
};

const titleStyle: React.CSSProperties = {
  fontSize: '1.12rem',
  fontWeight: 700,
  marginBottom: '14px',
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
};
