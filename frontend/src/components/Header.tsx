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
        padding: '16px 20px',
        background: '#ffffff',
        border: '1px solid var(--border-card)',
        borderRadius: '16px',
        marginBottom: '18px',
        boxShadow: 'var(--shadow-sm)',
        flexWrap: 'wrap',
        gap: '16px'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          <div style={{
            width: '46px',
            height: '46px',
            borderRadius: '12px',
            background: 'linear-gradient(135deg, #7c5cfc, #9d85fc)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            boxShadow: '0 4px 14px rgba(124, 92, 252, 0.25)',
          }}>
            <Shield size={24} color="#ffffff" />
          </div>
          <div>
            <div style={{ fontSize: '1.35rem', fontWeight: 800, letterSpacing: '-0.02em', display: 'flex', alignItems: 'center', gap: '0.6rem', color: 'var(--text-main)' }}>
              <span>Prompt Injection Firewall</span>
              <span style={{
                background: 'var(--primary-bg)',
                color: 'var(--primary)',
                border: '1px solid var(--border-subtle)',
                padding: '0.18rem 0.6rem',
                borderRadius: '999px',
                fontSize: '0.72rem',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.04em'
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
            background: 'var(--success-bg)',
            border: '1px solid var(--success-border)',
            color: 'var(--success)',
            padding: '7px 16px',
            borderRadius: '9999px',
            fontSize: '0.78rem',
            fontWeight: 700,
            letterSpacing: '0.04em',
          }}>
            <div style={{
              width: '8px',
              height: '8px',
              borderRadius: '50%',
              background: 'var(--success)',
              boxShadow: '0 0 8px rgba(5, 150, 105, 0.4)',
            }} />
            Firewall Active & Protecting
          </div>
        </div>
      </header>

      {/* Main Navigation Tabs */}
      <nav style={{
        display: 'flex',
        gap: '8px',
        background: '#ffffff',
        padding: '6px',
        borderRadius: '14px',
        border: '1px solid var(--border-card)',
        marginBottom: activeTab === 'telemetry' ? '12px' : '20px',
        boxShadow: 'var(--shadow-sm)',
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
                borderRadius: '10px',
                border: 'none',
                background: isActive ? 'linear-gradient(135deg, #7c5cfc, #6a46f9)' : 'transparent',
                color: isActive ? '#ffffff' : 'var(--text-muted)',
                fontWeight: isActive ? 600 : 500,
                fontSize: '0.88rem',
                cursor: 'pointer',
                transition: 'all 0.18s ease',
                whiteSpace: 'nowrap',
                boxShadow: isActive ? '0 4px 14px rgba(124, 92, 252, 0.28)' : 'none',
              }}
            >
              <Icon size={17} />
              <span>{tab.label}</span>
              {tab.badge && (
                <span style={{
                  fontSize: '0.68rem',
                  padding: '2px 7px',
                  borderRadius: '999px',
                  background: isActive ? 'rgba(255, 255, 255, 0.25)' : 'var(--primary-bg)',
                  color: isActive ? '#ffffff' : 'var(--primary)',
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
          background: 'var(--bg-subtle)',
          padding: '5px',
          borderRadius: '12px',
          border: '1px solid var(--border-card)',
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
                  padding: '8px 14px',
                  borderRadius: '8px',
                  border: 'none',
                  background: isSubActive ? '#ffffff' : 'transparent',
                  color: isSubActive ? 'var(--primary)' : 'var(--text-muted)',
                  fontWeight: isSubActive ? 600 : 500,
                  fontSize: '0.8rem',
                  cursor: 'pointer',
                  transition: 'all 0.15s',
                  whiteSpace: 'nowrap',
                  boxShadow: isSubActive ? '0 2px 6px rgba(124, 92, 252, 0.1)' : 'none',
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
