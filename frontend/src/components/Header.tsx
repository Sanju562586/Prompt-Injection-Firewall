'use client';

import React from 'react';
import {
  Shield,
  Bot,
  Database,
  Activity,
  Scale,
  FileText,
  Crosshair,
  Code,
  Lock,
  Layers
} from 'lucide-react';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  telemetrySubTab: string;
  setTelemetrySubTab: (subTab: string) => void;
}

export default function Header({
  activeTab,
  setActiveTab,
  telemetrySubTab,
  setTelemetrySubTab
}: HeaderProps) {
  const mainTabs = [
    { id: 'assistant', label: 'AI Assistant (RAG)', icon: Bot, badge: 'Active' },
    { id: 'knowledge', label: 'Knowledge Base', icon: Database },
    { id: 'telemetry', label: 'Security Telemetry', icon: Shield, badge: '5 Modules' },
  ];

  const telemetryTabs = [
    { id: 'sandbox', label: 'Threat Monitor & Sandbox', icon: Shield },
    { id: 'risk', label: 'Risk Engine Playground (M3)', icon: Scale },
    { id: 'audit', label: 'Cryptographic Audit Trail (M6)', icon: FileText },
    { id: 'redteam', label: 'Red-Team Benchmark (M7)', icon: Crosshair },
    { id: 'rules', label: 'Rules & Signatures (M1)', icon: Code },
  ];

  return (
    <div>
      <header style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        paddingBottom: '16px',
        borderBottom: '1px solid var(--border-subtle)',
        marginBottom: '16px',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '46px',
            height: '46px',
            borderRadius: '12px',
            background: 'linear-gradient(135deg, var(--primary), var(--cyan))',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 0 24px var(--primary-glow)',
          }}>
            <Shield size={24} color="#fff" />
          </div>
          <div>
            <div style={{ fontSize: '1.35rem', fontWeight: 800, letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <span>Prompt Injection Firewall</span>
              <span style={{
                background: 'rgba(56, 189, 248, 0.15)',
                color: '#38bdf8',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                padding: '0.15rem 0.55rem',
                borderRadius: '999px',
                fontSize: '0.72rem',
                fontWeight: 700,
                textTransform: 'uppercase'
              }}>
                RAG Enterprise Gateway
              </span>
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Detect • Defend • Monitor • Benchmark (Full HLD Implementation)
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
          <div style={{
            display: 'flex',
            alignItems: 'center',
            gap: '8px',
            background: 'rgba(16, 185, 129, 0.12)',
            border: '1px solid rgba(16, 185, 129, 0.35)',
            color: 'var(--success)',
            padding: '6px 14px',
            borderRadius: '9999px',
            fontSize: '0.8rem',
            fontWeight: 600,
            textTransform: 'uppercase',
            letterSpacing: '0.05em',
          }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: 'var(--success)',
              boxShadow: '0 0 10px var(--success)',
            }} />
            Firewall Active & Protecting
          </div>
        </div>
      </header>

      {/* Main Navigation Tabs */}
      <nav style={{
        display: 'flex',
        gap: '8px',
        background: 'rgba(22, 27, 34, 0.6)',
        padding: '6px',
        borderRadius: '12px',
        border: '1px solid var(--border-subtle)',
        marginBottom: activeTab === 'telemetry' ? '12px' : '20px',
        overflowX: 'auto',
      }}>
        {mainTabs.map(tab => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '10px 18px',
                borderRadius: '8px',
                border: 'none',
                background: isActive ? 'var(--primary)' : 'transparent',
                color: isActive ? '#fff' : 'var(--text-muted)',
                fontWeight: isActive ? 600 : 500,
                fontSize: '0.88rem',
                cursor: 'pointer',
                transition: 'all 0.2s cubic-bezier(0.4, 0, 0.2, 1)',
                whiteSpace: 'nowrap',
                boxShadow: isActive ? '0 4px 14px var(--primary-glow)' : 'none',
              }}
            >
              <Icon size={17} />
              <span>{tab.label}</span>
              {tab.badge && (
                <span style={{
                  fontSize: '0.68rem',
                  padding: '1px 6px',
                  borderRadius: '999px',
                  background: isActive ? 'rgba(255,255,255,0.25)' : 'rgba(56, 189, 248, 0.15)',
                  color: isActive ? '#fff' : '#38bdf8',
                  fontWeight: 700
                }}>
                  {tab.badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Telemetry Sub-Navigation (Visible only when in Telemetry view) */}
      {activeTab === 'telemetry' && (
        <div style={{
          display: 'flex',
          gap: '6px',
          background: 'rgba(13, 17, 23, 0.5)',
          padding: '4px',
          borderRadius: '10px',
          border: '1px solid rgba(48, 54, 61, 0.5)',
          marginBottom: '20px',
          overflowX: 'auto',
          animation: 'fadeIn 0.15s ease-out'
        }}>
          {telemetryTabs.map(subTab => {
            const SubIcon = subTab.icon;
            const isSubActive = telemetrySubTab === subTab.id;
            return (
              <button
                key={subTab.id}
                onClick={() => setTelemetrySubTab(subTab.id)}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '6px',
                  padding: '7px 14px',
                  borderRadius: '6px',
                  border: 'none',
                  background: isSubActive ? 'rgba(56, 189, 248, 0.18)' : 'transparent',
                  color: isSubActive ? '#38bdf8' : '#8b949e',
                  fontWeight: isSubActive ? 600 : 500,
                  fontSize: '0.8rem',
                  cursor: 'pointer',
                  transition: 'all 0.15s',
                  whiteSpace: 'nowrap',
                }}
              >
                <SubIcon size={14} />
                <span>{subTab.label}</span>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}