'use client';

import React, { useState, useEffect } from 'react';
import Header from '@/components/Header';
import MetricsOverview from '@/components/MetricsOverview';
import ThreatSandbox from '@/components/ThreatSandbox';
import RiskEnginePlayground from '@/components/RiskEnginePlayground';
import AuditTrail from '@/components/AuditTrail';
import RedTeamSuite from '@/components/RedTeamSuite';
import RulesExplorer from '@/components/RulesExplorer';

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState('sandbox');
  const [stats, setStats] = useState({
    total_requests: 0,
    total_blocked: 0,
    block_rate_percent: 0.0,
    avg_latency_ms: 0.0,
    active_rules_count: 15,
  });

  const fetchStats = async () => {
    try {
      const res = await fetch('/api/dashboard/stats');
      if (res.ok) {
        const data = await res.json();
        setStats(data);
      }
    } catch (e) {
      console.error('Stats fetch error', e);
    }
  };

  useEffect(() => {
    fetchStats();
    const interval = setInterval(fetchStats, 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <main className="container">
      <Header activeTab={activeTab} setActiveTab={setActiveTab} />

      <MetricsOverview
        totalRequests={stats.total_requests}
        totalBlocked={stats.total_blocked}
        blockRate={stats.block_rate_percent}
        avgLatencyMs={stats.avg_latency_ms}
        activeRulesCount={stats.active_rules_count}
      />

      <div style={{ marginTop: '10px' }}>
        {activeTab === 'sandbox' && <ThreatSandbox onSimulationComplete={fetchStats} />}
        {activeTab === 'risk' && <RiskEnginePlayground />}
        {activeTab === 'audit' && <AuditTrail />}
        {activeTab === 'redteam' && <RedTeamSuite />}
        {activeTab === 'rules' && <RulesExplorer />}
      </div>
    </main>
  );
}
