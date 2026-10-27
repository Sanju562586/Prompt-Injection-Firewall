'use client';

import React from 'react';
import { ShieldAlert, AlertTriangle, X, ArrowRight, ShieldCheck, FileWarning, Eye } from 'lucide-react';

export interface SecurityAlertData {
  has_threat: boolean;
  alert_title: string;
  threat_category: string;
  severity: string;
  risk_score: number;
  decision: string;
  violations: string[];
  quarantined_count: number;
  quarantined_titles: string[];
  action_taken: string;
}

interface SecurityAlertModalProps {
  alert: SecurityAlertData | null;
  onClose: () => void;
  onInspectTelemetry?: () => void;
}

export const SecurityAlertModal: React.FC<SecurityAlertModalProps> = ({
  alert,
  onClose,
  onInspectTelemetry,
}) => {
  if (!alert) return null;

  const isCritical = alert.severity.toUpperCase() === 'CRITICAL' || alert.severity.toUpperCase() === 'HIGH';
  const themeColor = isCritical ? '#e11d48' : '#d97706';
  const themeBg = isCritical ? 'var(--danger-bg)' : 'var(--warning-bg)';
  const themeBorder = isCritical ? 'var(--danger-border)' : 'var(--warning-border)';

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      zIndex: 9999,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'rgba(29, 25, 43, 0.45)',
      backdropFilter: 'blur(8px)',
      padding: '1.5rem',
      animation: 'fadeIn 0.2s ease-out'
    }}>
      <div style={{
        background: '#ffffff',
        border: `1px solid ${themeBorder}`,
        borderRadius: '18px',
        width: '100%',
        maxWidth: '560px',
        boxShadow: `0 20px 40px -10px rgba(124, 92, 252, 0.15), 0 0 30px ${isCritical ? 'rgba(225, 29, 72, 0.15)' : 'rgba(217, 119, 6, 0.15)'}`,
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column'
      }}>
        {/* Header Bar */}
        <div style={{
          padding: '1.25rem 1.5rem',
          background: themeBg,
          borderBottom: `1px solid ${themeBorder}`,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              width: '40px',
              height: '40px',
              borderRadius: '10px',
              background: '#ffffff',
              border: `1px solid ${themeBorder}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: themeColor
            }}>
              <ShieldAlert size={22} />
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 800, letterSpacing: '0.08em', color: themeColor, textTransform: 'uppercase' }}>
                LLM Firewall Threat Interception
              </div>
              <h3 style={{ margin: 0, fontSize: '1.15rem', color: 'var(--text-main)', fontWeight: 700 }}>
                {alert.alert_title}
              </h3>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '0.5rem',
              borderRadius: '8px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'color 0.15s'
            }}
            aria-label="Close modal"
          >
            <X size={20} />
          </button>
        </div>

        {/* Body Content */}
        <div style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {/* Key Metrics Row */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(3, 1fr)',
            gap: '0.75rem',
            background: 'var(--bg-subtle)',
            padding: '1rem',
            borderRadius: '12px',
            border: '1px solid var(--border-subtle)'
          }}>
            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.25rem' }}>Threat Level</div>
              <span style={{
                display: 'inline-block',
                padding: '0.2rem 0.6rem',
                borderRadius: '6px',
                fontSize: '0.8rem',
                fontWeight: 700,
                background: themeBg,
                color: themeColor,
                border: `1px solid ${themeBorder}`
              }}>
                {alert.severity}
              </span>
            </div>

            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.25rem' }}>Overall Risk</div>
              <div style={{ fontSize: '1.1rem', fontWeight: 800, color: themeColor, fontFamily: 'var(--font-mono)' }}>
                {alert.risk_score.toFixed(3)}
              </div>
            </div>

            <div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.25rem' }}>Firewall Action</div>
              <span style={{
                display: 'inline-block',
                padding: '0.2rem 0.6rem',
                borderRadius: '6px',
                fontSize: '0.8rem',
                fontWeight: 700,
                background: alert.decision === 'BLOCK' ? 'var(--danger-bg)' : 'var(--primary-bg)',
                color: alert.decision === 'BLOCK' ? 'var(--danger)' : 'var(--primary)',
                border: `1px solid ${alert.decision === 'BLOCK' ? 'var(--danger-border)' : 'var(--border-subtle)'}`
              }}>
                {alert.decision}
              </span>
            </div>
          </div>

          {/* Quarantined Documents Box (if RAG attack) */}
          {alert.quarantined_count > 0 && (
            <div style={{
              background: 'var(--danger-bg)',
              border: '1px solid var(--danger-border)',
              borderRadius: '10px',
              padding: '0.9rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.4rem'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--danger)', fontWeight: 700, fontSize: '0.85rem' }}>
                <FileWarning size={16} />
                Quarantined Malicious Documents ({alert.quarantined_count})
              </div>
              <div style={{ fontSize: '0.82rem', color: 'var(--text-main)', fontWeight: 500 }}>
                {alert.quarantined_titles.join(', ')}
              </div>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontStyle: 'italic', marginTop: '0.2rem' }}>
                Shield protected the LLM by stripping the trojan instruction before response generation.
              </div>
            </div>
          )}

          {/* Triggered Violations */}
          <div>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--text-main)', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <AlertTriangle size={15} color={themeColor} />
              Detected Security Violations:
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '140px', overflowY: 'auto' }}>
              {alert.violations.length > 0 ? (
                alert.violations.map((v, i) => (
                  <div key={i} style={{
                    fontSize: '0.78rem',
                    padding: '0.55rem 0.8rem',
                    borderRadius: '8px',
                    background: '#ffffff',
                    border: '1px solid var(--border-subtle)',
                    borderLeft: `3px solid ${themeColor}`,
                    color: 'var(--text-main)',
                    fontFamily: 'var(--font-mono)'
                  }}>
                    {v}
                  </div>
                ))
              ) : (
                <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Heuristic risk score elevated based on context.</div>
              )}
            </div>
          </div>

          {/* Action Taken Summary */}
          <div style={{
            background: 'var(--primary-bg)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '10px',
            padding: '0.85rem',
            fontSize: '0.82rem',
            color: 'var(--text-main)',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.6rem'
          }}>
            <ShieldCheck size={18} color="var(--primary)" style={{ marginTop: '0.1rem', flexShrink: 0 }} />
            <div>
              <strong style={{ color: 'var(--primary)' }}>Firewall Mitigation: </strong>
              {alert.action_taken}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div style={{
          padding: '1rem 1.5rem',
          background: 'var(--bg-subtle)',
          borderTop: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'flex-end',
          gap: '0.75rem'
        }}>
          {onInspectTelemetry && (
            <button
              onClick={() => {
                onClose();
                onInspectTelemetry();
              }}
              style={{
                background: '#ffffff',
                color: 'var(--text-muted)',
                border: '1px solid var(--border-card)',
                padding: '0.55rem 1rem',
                borderRadius: '8px',
                fontSize: '0.82rem',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                transition: 'all 0.15s'
              }}
            >
              <Eye size={15} />
              Inspect Telemetry
            </button>
          )}

          <button
            onClick={onClose}
            style={{
              background: themeColor,
              color: '#ffffff',
              border: 'none',
              padding: '0.55rem 1.25rem',
              borderRadius: '8px',
              fontSize: '0.82rem',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              boxShadow: `0 4px 12px ${isCritical ? 'rgba(225, 29, 72, 0.25)' : 'rgba(217, 119, 6, 0.25)'}`,
              transition: 'opacity 0.15s'
            }}
          >
            Acknowledge & Continue
            <ArrowRight size={15} />
          </button>
        </div>
      </div>
    </div>
  );
};
