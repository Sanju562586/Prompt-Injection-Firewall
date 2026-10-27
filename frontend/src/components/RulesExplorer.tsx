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
          <Code2 size={20} color="var(--primary)" />
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
              <th style={{ padding: '12px 14px', fontWeight: 600 }}>Rule ID</th>
              <th style={{ padding: '12px 14px', fontWeight: 600 }}>Threat Name & Description</th>
              <th style={{ padding: '12px 14px', fontWeight: 600 }}>Attack Type</th>
              <th style={{ padding: '12px 14px', fontWeight: 600 }}>Severity</th>
              <th style={{ padding: '12px 14px', fontWeight: 600 }}>Confidence</th>
              <th style={{ padding: '12px 14px', fontWeight: 600 }}>Regex Signature Pattern</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((r) => {
              const isCrit = r.severity === 'CRITICAL';
              return (
                <tr key={r.rule_id} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                  <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)', color: 'var(--primary)', fontWeight: 600 }}>
                    {r.rule_id}
                  </td>
                  <td style={{ padding: '12px 14px' }}>
                    <strong style={{ color: 'var(--text-main)' }}>{r.name}</strong>
                    <div style={{ fontSize: '0.74rem', color: 'var(--text-muted)', marginTop: '2px' }}>{r.description}</div>
                  </td>
                  <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)', color: 'var(--primary)', fontSize: '0.78rem', fontWeight: 600 }}>
                    {r.attack_type}
                  </td>
                  <td style={{ padding: '12px 14px' }}>
                    <span style={{
                      padding: '3px 8px',
                      borderRadius: '6px',
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      background: isCrit ? 'var(--danger-bg)' : 'var(--warning-bg)',
                      color: isCrit ? 'var(--danger)' : 'var(--warning)',
                      border: `1px solid ${isCrit ? 'var(--danger-border)' : 'var(--warning-border)'}`,
                    }}>
                      {r.severity}
                    </span>
                  </td>
                  <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)', color: 'var(--text-main)', fontWeight: 600 }}>
                    {(r.confidence * 100).toFixed(0)}%
                  </td>
                  <td style={{
                    padding: '12px 14px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.74rem',
                    color: 'var(--text-muted)',
                    maxWidth: '320px',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}>
                    <code style={{ background: 'var(--bg-subtle)', padding: '2px 6px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                      {r.pattern}
                    </code>
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
  background: '#ffffff',
  border: '1px solid var(--border-card)',
  borderRadius: '16px',
  padding: '24px',
  boxShadow: 'var(--shadow-sm)',
};

const titleStyle: React.CSSProperties = {
  fontSize: '1.12rem',
  fontWeight: 700,
  marginBottom: '16px',
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  color: 'var(--text-main)',
};
