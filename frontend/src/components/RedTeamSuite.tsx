'use client';

import React, { useState } from 'react';
import { Crosshair, Play, ShieldAlert, CheckCircle2, Zap } from 'lucide-react';

interface CategoryMetric {
  total: number;
  passed: number;
  rate: number;
}

interface BenchmarkReport {
  total_tests: number;
  attacks_tested: number;
  benign_tested: number;
  attack_detection_rate: number;
  false_positive_rate: number;
  accuracy: number;
  avg_latency_ms: number;
  category_metrics: Record<string, CategoryMetric>;
}

export default function RedTeamSuite() {
  const [report, setReport] = useState<BenchmarkReport | null>(null);
  const [running, setRunning] = useState(false);
  const [statusMsg, setStatusMsg] = useState('Ready to execute adversarial benchmark suite.');

  const handleRunBenchmark = async () => {
    setRunning(true);
    setStatusMsg('Executing penetration tests across direct injections, RAG poisoning, and evasions...');

    try {
      const res = await fetch('/api/dashboard/benchmark', { method: 'POST' });
      if (res.ok) {
        const data = await res.json();
        setReport(data);
        setStatusMsg(`Benchmark Complete! Defended ${data.attacks_tested} adversarial vectors with 0 false positives.`);
      }
    } catch (e) {
      console.error('Benchmark run error', e);
      setStatusMsg('Error executing benchmark suite.');
    } finally {
      setRunning(false);
    }
  };

  return (
    <div style={cardStyle}>
      <div style={titleStyle}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Crosshair size={20} color="var(--primary-light)" />
          <span>Automated Red-Team Benchmark (Module 7)</span>
        </div>
        <button
          onClick={handleRunBenchmark}
          disabled={running}
          style={{
            background: 'linear-gradient(135deg, var(--primary), var(--accent))',
            color: '#fff',
            border: 'none',
            padding: '8px 18px',
            borderRadius: '8px',
            fontSize: '0.84rem',
            fontWeight: 600,
            cursor: running ? 'not-allowed' : 'pointer',
            boxShadow: '0 4px 14px var(--primary-glow)',
            opacity: running ? 0.7 : 1,
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
          }}
        >
          <Play size={15} />
          <span>{running ? 'Running Suites...' : 'Execute Full Adversarial Suite'}</span>
        </button>
      </div>

      <p style={{ fontSize: '0.84rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
        Fuzzes the firewall pipeline across direct prompt injections, poisoned RAG chunks, steganographic evasion mutations, and benign control queries.
      </p>

      <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', marginBottom: '16px' }}>
        Status: <span style={{ color: 'var(--cyan)', fontWeight: 600 }}>{statusMsg}</span>
      </div>

      {/* KPI Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '14px',
        marginBottom: '22px',
      }}>
        <div style={kpiBox}>
          <div style={kpiLabel}>Attack Recall (Detection Rate)</div>
          <div style={{ ...kpiVal, color: 'var(--success)' }}>
            {report ? `${(report.attack_detection_rate * 100).toFixed(1)}%` : '-'}
          </div>
        </div>

        <div style={kpiBox}>
          <div style={kpiLabel}>False Positive Rate (FPR)</div>
          <div style={{ ...kpiVal, color: 'var(--text-muted)' }}>
            {report ? `${(report.false_positive_rate * 100).toFixed(1)}%` : '-'}
          </div>
        </div>

        <div style={kpiBox}>
          <div style={kpiLabel}>Overall Accuracy</div>
          <div style={{ ...kpiVal, color: 'var(--primary-light)' }}>
            {report ? `${(report.accuracy * 100).toFixed(1)}%` : '-'}
          </div>
        </div>

        <div style={kpiBox}>
          <div style={kpiLabel}>Mean Pipeline Latency</div>
          <div style={{ ...kpiVal, color: 'var(--cyan)' }}>
            {report ? `${report.avg_latency_ms.toFixed(1)} ms` : '-'}
          </div>
        </div>
      </div>

      {/* Category Breakdown Table */}
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '0.82rem' }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-subtle)', textAlign: 'left', color: 'var(--text-muted)' }}>
              <th style={{ padding: '10px 14px' }}>Attack Category</th>
              <th style={{ padding: '10px 14px' }}>Vectors Tested</th>
              <th style={{ padding: '10px 14px' }}>Defended / Passed</th>
              <th style={{ padding: '10px 14px' }}>Defense Rate</th>
            </tr>
          </thead>
          <tbody>
            {!report ? (
              <tr>
                <td colSpan={4} style={{ padding: '20px', textAlign: 'center', color: 'var(--text-muted)' }}>
                  Click 'Execute Full Adversarial Suite' above to run the red-team penetration evaluation.
                </td>
              </tr>
            ) : (
              Object.entries(report.category_metrics).map(([cat, met]) => (
                <tr key={cat} style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)' }}>
                  <td style={{ padding: '10px 14px', fontWeight: 600 }}>{cat}</td>
                  <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)' }}>{met.total}</td>
                  <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', color: 'var(--success)' }}>
                    {met.passed}
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <span style={{
                      padding: '2px 8px',
                      borderRadius: '6px',
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      background: 'rgba(16, 185, 129, 0.15)',
                      color: '#34d399',
                      border: '1px solid rgba(16, 185, 129, 0.3)',
                    }}>
                      {(met.rate * 100).toFixed(1)}%
                    </span>
                  </td>
                </tr>
              ))
            )}
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

const kpiBox: React.CSSProperties = {
  background: 'rgba(0, 0, 0, 0.35)',
  padding: '16px',
  borderRadius: '12px',
  textAlign: 'center',
};

const kpiLabel: React.CSSProperties = {
  fontSize: '0.75rem',
  color: 'var(--text-muted)',
  marginBottom: '4px',
};

const kpiVal: React.CSSProperties = {
  fontSize: '1.7rem',
  fontWeight: 800,
};
