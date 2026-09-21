'use client';

import React, { useState, useEffect } from 'react';
import { Scale, Sparkles, AlertOctagon, CheckCircle } from 'lucide-react';

export default function RiskEnginePlayground() {
  const [ruleScore, setRuleScore] = useState(0.80);
  const [mlScore, setMlScore] = useState(0.91);
  const [docRisk, setDocRisk] = useState(0.70);
  const [piiScore, setPiiScore] = useState(0.00);
  const [severity, setSeverity] = useState('HIGH');

  const [overallRisk, setOverallRisk] = useState(0.868);
  const [riskLevel, setRiskLevel] = useState('CRITICAL');
  const [decision, setDecision] = useState('BLOCK');
  const [explanation, setExplanation] = useState('');

  const evaluateRisk = async (r: number, m: number, d: number, p: number, s: string) => {
    try {
      const res = await fetch('/v1/risk/evaluate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rule_score: r,
          ml_score: m,
          pii_score: p,
          document_risk: d,
          output_risk: p,
          attack_severity: s,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        setOverallRisk(data.overall_risk);
        setRiskLevel(data.risk_level);
        setDecision(data.decision);
        setExplanation(data.explanation);
      }
    } catch (e) {
      console.error('Risk eval error', e);
    }
  };

  useEffect(() => {
    evaluateRisk(ruleScore, mlScore, docRisk, piiScore, severity);
  }, [ruleScore, mlScore, docRisk, piiScore, severity]);

  const loadUserSpec = () => {
    setRuleScore(0.80);
    setMlScore(0.91);
    setDocRisk(0.70);
    setPiiScore(0.00);
    setSeverity('HIGH');
  };

  const testMLAlone = () => {
    setRuleScore(0.00);
    setMlScore(0.82);
    setDocRisk(0.00);
    setPiiScore(0.00);
    setSeverity('NONE');
  };

  const testClean = () => {
    setRuleScore(0.00);
    setMlScore(0.00);
    setDocRisk(0.00);
    setPiiScore(0.00);
    setSeverity('NONE');
  };

  const riskPct = Math.min(100, Math.max(0, overallRisk * 100));
  const isBlock = decision === 'BLOCK';

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 0.9fr', gap: '22px' }}>
      {/* Parameter Control Panel */}
      <div style={cardStyle}>
        <div style={titleStyle}>
          <span>Risk Engine Parameter Sliders (Module 3)</span>
          <button
            onClick={loadUserSpec}
            style={{
              background: 'linear-gradient(135deg, var(--primary), var(--cyan))',
              color: '#fff',
              border: 'none',
              padding: '6px 14px',
              borderRadius: '8px',
              fontSize: '0.78rem',
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Load User Test Case
          </button>
        </div>

        <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', marginBottom: '18px' }}>
          Synthesizes rule heuristics, ML confidence, context anomalies, document poisoning, and output risk.
          The ML classifier alone cannot trigger a block without corroboration.
        </p>

        {/* Rule Score Slider */}
        <div style={{ marginBottom: '14px' }}>
          <div style={sliderHeader}>
            <label style={labelStyle}>Rule Score (Heuristics & Pattern Signals)</label>
            <span style={sliderValStyle}>{ruleScore.toFixed(2)}</span>
          </div>
          <input
            type="range"
            min="0"
            max="1"
            step="0.01"
            value={ruleScore}
            onChange={(e) => setRuleScore(parseFloat(e.target.value))}
            style={rangeStyle}
          />
        </div>

        {/* ML Score Slider */}
        <div style={{ marginBottom: '14px' }}>
          <div style={sliderHeader}>
            <label style={labelStyle}>ML Score (DeBERTa Classifier Confidence)</label>
            <span style={sliderValStyle}>{mlScore.toFixed(2)}</span>
          </div>
          <input
            type="range"
            min="0"
            max="1"
            step="0.01"
            value={mlScore}
            onChange={(e) => setMlScore(parseFloat(e.target.value))}
            style={rangeStyle}
          />
        </div>

        {/* Document Risk Slider */}
        <div style={{ marginBottom: '14px' }}>
          <div style={sliderHeader}>
            <label style={labelStyle}>Document Risk (RAG Poisoning Score)</label>
            <span style={sliderValStyle}>{docRisk.toFixed(2)}</span>
          </div>
          <input
            type="range"
            min="0"
            max="1"
            step="0.01"
            value={docRisk}
            onChange={(e) => setDocRisk(parseFloat(e.target.value))}
            style={rangeStyle}
          />
        </div>

        {/* PII Score Slider */}
        <div style={{ marginBottom: '14px' }}>
          <div style={sliderHeader}>
            <label style={labelStyle}>PII / Output Risk</label>
            <span style={sliderValStyle}>{piiScore.toFixed(2)}</span>
          </div>
          <input
            type="range"
            min="0"
            max="1"
            step="0.01"
            value={piiScore}
            onChange={(e) => setPiiScore(parseFloat(e.target.value))}
            style={rangeStyle}
          />
        </div>

        {/* Attack Severity */}
        <div style={{ marginBottom: '18px' }}>
          <label style={labelStyle}>Attack Severity</label>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            style={{
              width: '100%',
              background: 'var(--bg-input)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '10px',
              color: 'var(--text-main)',
              padding: '10px',
              fontFamily: 'var(--font-mono)',
              fontSize: '0.86rem',
              outline: 'none',
            }}
          >
            <option value="NONE">NONE</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
            <option value="CRITICAL">CRITICAL</option>
          </select>
        </div>

        <div style={{ display: 'flex', gap: '10px', flexWrap: 'wrap' }}>
          <button onClick={testMLAlone} style={chipStyle}>
            Test ML Alone (ML=0.82) → Demonstrates ALLOW
          </button>
          <button onClick={testClean} style={chipStyle}>
            Test Clean Query (All 0.0) → LOW (0.00)
          </button>
        </div>
      </div>

      {/* Output / Visualization Side */}
      <div style={cardStyle}>
        <div style={titleStyle}>
          <span>Risk Synthesis Output</span>
          <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Real-Time Evaluator</span>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
          <div>
            <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>Enforcement Decision:</span>
            <div style={{
              display: 'inline-block',
              marginLeft: '8px',
              padding: '5px 12px',
              borderRadius: '8px',
              fontSize: '0.85rem',
              fontWeight: 800,
              textTransform: 'uppercase',
              background: isBlock ? 'rgba(239, 68, 68, 0.2)' : 'rgba(16, 185, 129, 0.2)',
              color: isBlock ? '#f87171' : '#34d399',
              border: `1px solid ${isBlock ? 'rgba(239, 68, 68, 0.4)' : 'rgba(16, 185, 129, 0.4)'}`,
            }}>
              {decision}
            </div>
          </div>
          <div style={{
            fontWeight: 800,
            fontSize: '1.1rem',
            color: riskLevel === 'CRITICAL' ? 'var(--critical)' : riskLevel === 'HIGH' ? 'var(--danger)' : riskLevel === 'MEDIUM' ? 'var(--warning)' : 'var(--success)',
          }}>
            {riskLevel} ({overallRisk.toFixed(3)})
          </div>
        </div>

        {/* Risk Gauge Bar */}
        <div style={{
          background: 'rgba(10, 15, 29, 0.85)',
          border: '1px solid var(--border-subtle)',
          borderRadius: '12px',
          padding: '16px',
          marginBottom: '16px',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem' }}>
            <span>Composite Calculated Risk</span>
            <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700 }}>
              {overallRisk.toFixed(3)} / 1.000
            </span>
          </div>
          <div style={{
            height: '16px',
            width: '100%',
            borderRadius: '8px',
            background: 'linear-gradient(to right, #10b981 0%, #10b981 30%, #f59e0b 30%, #f59e0b 60%, #ef4444 60%, #ef4444 80%, #dc2626 80%, #dc2626 100%)',
            position: 'relative',
            margin: '12px 0 6px 0',
          }}>
            <div style={{
              position: 'absolute',
              top: '-4px',
              width: '6px',
              height: '24px',
              background: '#fff',
              borderRadius: '2px',
              boxShadow: '0 0 10px #fff, 0 0 20px var(--primary-glow)',
              transform: 'translateX(-50%)',
              left: `${riskPct}%`,
              transition: 'left 0.4s cubic-bezier(0.34, 1.56, 0.64, 1)',
            }} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.7rem', fontWeight: 600 }}>
            <span style={{ color: '#10b981' }}>0.00 LOW</span>
            <span style={{ color: '#f59e0b' }}>0.30 MEDIUM</span>
            <span style={{ color: '#ef4444' }}>0.60 HIGH</span>
            <span style={{ color: '#dc2626' }}>0.80 CRITICAL</span>
          </div>
        </div>

        {/* Formula breakdown */}
        <div style={{ marginBottom: '14px' }}>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
            Mathematical Synthesis:
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)',
            background: 'rgba(0, 0, 0, 0.45)',
            padding: '12px',
            borderRadius: '8px',
            fontSize: '0.78rem',
            lineHeight: 1.6,
          }}>
            Risk = (ML × 0.30) + (Rule × 0.30) + (Doc × 0.25) + (Context × 0.10) + (Output × 0.05) + Corroboration Boost + Severity Boost
          </div>
        </div>

        {/* Forensic Justification */}
        <div>
          <div style={{ fontSize: '0.8rem', fontWeight: 600, color: 'var(--text-muted)', marginBottom: '6px' }}>
            Forensic Justification:
          </div>
          <div style={{
            fontFamily: 'var(--font-mono)',
            background: 'rgba(0, 0, 0, 0.45)',
            padding: '12px',
            borderRadius: '8px',
            fontSize: '0.78rem',
            lineHeight: 1.5,
          }}>
            {explanation || 'Calculating...'}
          </div>
        </div>
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

const sliderHeader: React.CSSProperties = {
  display: 'flex',
  justifyContent: 'space-between',
  alignItems: 'center',
  marginBottom: '4px',
};

const labelStyle: React.CSSProperties = {
  fontSize: '0.82rem',
  color: 'var(--text-muted)',
  fontWeight: 500,
};

const sliderValStyle: React.CSSProperties = {
  fontFamily: 'var(--font-mono)',
  fontWeight: 700,
  color: 'var(--primary-light)',
};

const rangeStyle: React.CSSProperties = {
  width: '100%',
  height: '6px',
  borderRadius: '3px',
  background: 'rgba(255, 255, 255, 0.1)',
  outline: 'none',
  cursor: 'pointer',
};

const chipStyle: React.CSSProperties = {
  background: 'rgba(255, 255, 255, 0.05)',
  border: '1px solid var(--border-subtle)',
  color: 'var(--text-muted)',
  padding: '6px 12px',
  borderRadius: '8px',
  fontSize: '0.75rem',
  cursor: 'pointer',
  fontWeight: 500,
};
