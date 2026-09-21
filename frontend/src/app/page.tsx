'use client';

import React, { useState, useEffect } from 'react';
import Header from '@/components/Header';
import MetricsOverview from '@/components/MetricsOverview';
import ThreatSandbox from '@/components/ThreatSandbox';
import RiskEnginePlayground from '@/components/RiskEnginePlayground';
import AuditTrail from '@/components/AuditTrail';
import RedTeamSuite from '@/components/RedTeamSuite';
import RulesExplorer from '@/components/RulesExplorer';
import { RAGChatbot } from '@/components/RAGChatbot';
import { KnowledgeBaseManager } from '@/components/KnowledgeBaseManager';
import { SecurityAlertModal, SecurityAlertData } from '@/components/SecurityAlertModal';

export default function DashboardPage() {
  const [activeTab, setActiveTab] = useState('assistant');
  const [telemetrySubTab, setTelemetrySubTab] = useState('sandbox');
  const [activeSecurityAlert, setActiveSecurityAlert] = useState<SecurityAlertData | null>(null);

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
      {/* Global Security Threat Interception Pop-up Window */}
      <SecurityAlertModal
        alert={activeSecurityAlert}
        onClose={() => setActiveSecurityAlert(null)}
        onInspectTelemetry={() => {
          setActiveTab('telemetry');
          setTelemetrySubTab('audit');
        }}
      />

      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        telemetrySubTab={telemetrySubTab}
        setTelemetrySubTab={setTelemetrySubTab}
      />

      {/* Primary View: AI Assistant (Complete RAG Chatbot) */}
      {activeTab === 'assistant' && (
        <RAGChatbot
          onTriggerAlert={(alert) => {
            setActiveSecurityAlert(alert);
            fetchStats();
          }}
          onNavigateToKnowledge={() => setActiveTab('knowledge')}
          onNavigateToTelemetry={() => {
            setActiveTab('telemetry');
            setTelemetrySubTab('sandbox');
          }}
        />
      )}

      {/* Secondary View: Knowledge Base Management */}
      {activeTab === 'knowledge' && (
        <KnowledgeBaseManager />
      )}

      {/* Tertiary View: Security Telemetry & Mission Control */}
      {activeTab === 'telemetry' && (
        <div>
          <MetricsOverview
            totalRequests={stats.total_requests}
            totalBlocked={stats.total_blocked}
            blockRate={stats.block_rate_percent}
            avgLatencyMs={stats.avg_latency_ms}
            activeRulesCount={stats.active_rules_count}
          />

          <div style={{ marginTop: '16px' }}>
            {telemetrySubTab === 'sandbox' && <ThreatSandbox onSimulationComplete={fetchStats} />}
            {telemetrySubTab === 'risk' && <RiskEnginePlayground />}
            {telemetrySubTab === 'audit' && <AuditTrail />}
            {telemetrySubTab === 'redteam' && <RedTeamSuite />}
            {telemetrySubTab === 'rules' && <RulesExplorer />}
          </div>
        </div>
      )}
    </main>
  );
}