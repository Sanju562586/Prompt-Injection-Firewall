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
  const themeColor = isCritical ? '#ef4444' : '#f59e0b';
  const themeBg = isCritical ? 'rgba(239, 68, 68, 0.12)' : 'rgba(245, 158, 11, 0.12)';
  const themeBorder = isCritical ? 'rgba(239, 68, 68, 0.4)' : 'rgba(245, 158, 11, 0.4)';

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      zIndex: 9999,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'rgba(5, 8, 14, 0.75)',
      backdropFilter: 'blur(8px)',
      padding: '1.5rem',
      animation: 'fadeIn 0.2s ease-out'
    }}>
      <div style={{
        background: '#0d1117',
        border: `1px solid ${themeBorder}`,
        borderRadius: '16px',
        width: '100%',
        maxWidth: '560px',
        boxShadow: `0 20px 40px -10px rgba(0, 0, 0, 0.8), 0 0 30px ${isCritical ? 'rgba(239, 68, 68, 0.25)' : 'rgba(245, 158, 11, 0.25)'}`,
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
              background: isCritical ? 'rgba(239, 68, 68, 0.2)' : 'rgba(245, 158, 11, 0.2)',
              border: `1px solid ${themeBorder}`,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: themeColor
            }}>
              <ShieldAlert size={22} />
            </div>
            <div>
              <div style={{ fontSize: '0.75rem', fontWeight: 700, letterSpacing: '0.08em', color: themeColor, textTransform: 'uppercase' }}>
                LLM Firewall Threat Interception
              </div>
              <h3 style={{ margin: 0, fontSize: '1.15rem', color: '#f0f6fc', fontWeight: 600 }}>
                {alert.alert_title}
              </h3>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: '#8b949e',
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
            background: 'rgba(22, 27, 34, 0.6)',
            padding: '1rem',
            borderRadius: '12px',
            border: '1px solid rgba(48, 54, 61, 0.6)'
          }}>
            <div>
              <div style={{ fontSize: '0.75rem', color: '#8b949e', marginBottom: '0.25rem' }}>Threat Level</div>
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
              <div style={{ fontSize: '0.75rem', color: '#8b949e', marginBottom: '0.25rem' }}>Overall Risk</div>
              <div style={{ fontSize: '1.1rem', fontWeight: 700, color: themeColor, fontFamily: 'monospace' }}>
                {alert.risk_score.toFixed(3)}
              </div>
            </div>

            <div>
              <div style={{ fontSize: '0.75rem', color: '#8b949e', marginBottom: '0.25rem' }}>Firewall Action</div>
              <span style={{
                display: 'inline-block',
                padding: '0.2rem 0.6rem',
                borderRadius: '6px',
                fontSize: '0.8rem',
                fontWeight: 700,
                background: alert.decision === 'BLOCK' ? 'rgba(239, 68, 68, 0.2)' : 'rgba(56, 189, 248, 0.15)',
                color: alert.decision === 'BLOCK' ? '#ef4444' : '#38bdf8',
                border: '1px solid rgba(48, 54, 61, 0.6)'
              }}>
                {alert.decision}
              </span>
            </div>
          </div>

          {/* Quarantined Documents Box (if RAG attack) */}
          {alert.quarantined_count > 0 && (
            <div style={{
              background: 'rgba(239, 68, 68, 0.08)',
              border: '1px solid rgba(239, 68, 68, 0.3)',
              borderRadius: '10px',
              padding: '0.9rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '0.4rem'
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', color: '#f87171', fontWeight: 600, fontSize: '0.85rem' }}>
                <FileWarning size={16} />
                Quarantined Malicious Documents ({alert.quarantined_count})
              </div>
              <div style={{ fontSize: '0.8rem', color: '#c9d1d9' }}>
                {alert.quarantined_titles.join(', ')}
              </div>
              <div style={{ fontSize: '0.75rem', color: '#8b949e', fontStyle: 'italic', marginTop: '0.2rem' }}>
                Shield protected the LLM by stripping the trojan instruction before response generation.
              </div>
            </div>
          )}

          {/* Triggered Violations */}
          <div>
            <div style={{ fontSize: '0.8rem', fontWeight: 600, color: '#c9d1d9', marginBottom: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <AlertTriangle size={15} color={themeColor} />
              Detected Security Violations:
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem', maxHeight: '140px', overflowY: 'auto' }}>
              {alert.violations.length > 0 ? (
                alert.violations.map((v, i) => (
                  <div key={i} style={{
                    fontSize: '0.78rem',
                    padding: '0.5rem 0.75rem',
                    borderRadius: '6px',
                    background: 'rgba(22, 27, 34, 0.8)',
                    borderLeft: `3px solid ${themeColor}`,
                    color: '#e6edf3',
                    fontFamily: 'monospace'
                  }}>
                    {v}
                  </div>
                ))
              ) : (
                <div style={{ fontSize: '0.8rem', color: '#8b949e' }}>Heuristic risk score elevated based on context.</div>
              )}
            </div>
          </div>

          {/* Action Taken Summary */}
          <div style={{
            background: 'rgba(56, 189, 248, 0.06)',
            border: '1px solid rgba(56, 189, 248, 0.2)',
            borderRadius: '10px',
            padding: '0.85rem',
            fontSize: '0.82rem',
            color: '#93c5fd',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.6rem'
          }}>
            <ShieldCheck size={18} style={{ marginTop: '0.1rem', flexShrink: 0 }} />
            <div>
              <strong style={{ color: '#e0f2fe' }}>Firewall Mitigation: </strong>
              {alert.action_taken}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div style={{
          padding: '1rem 1.5rem',
          background: 'rgba(22, 27, 34, 0.9)',
          borderTop: '1px solid rgba(48, 54, 61, 0.8)',
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
                background: 'rgba(33, 38, 45, 0.9)',
                color: '#c9d1d9',
                border: '1px solid rgba(48, 54, 61, 0.8)',
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