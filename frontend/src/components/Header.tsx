'use client';

import React from 'react';
import { Shield, ShieldAlert, Cpu, Activity, Terminal, Scale, FileText, Crosshair, Code } from 'lucide-react';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export default function Header({ activeTab, setActiveTab }: HeaderProps) {
  const tabs = [
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
        paddingBottom: '20px',
        borderBottom: '1px solid var(--border-subtle)',
        marginBottom: '24px',
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
            <div style={{ fontSize: '1.35rem', fontWeight: 800, letterSpacing: '-0.02em' }}>
              Prompt Injection Firewall
            </div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)' }}>
              Next.js Mission Control & Multi-Layer LLM Defense Gateway
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
              background: 'var(--success)',
              borderRadius: '50%',
              boxShadow: '0 0 8px var(--success)',
              animation: 'pulse 2s infinite',
            }} />
            <span>Shield Active</span>
          </div>
        </div>
      </header>

      {/* Nav Tabs */}
      <div style={{
        display: 'flex',
        gap: '10px',
        marginBottom: '24px',
        borderBottom: '1px solid var(--border-subtle)',
        paddingBottom: '12px',
        flexWrap: 'wrap',
      }}>
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                background: isActive ? 'rgba(99, 102, 241, 0.18)' : 'transparent',
                border: `1px solid ${isActive ? 'var(--border-glow)' : 'transparent'}`,
                color: isActive ? '#fff' : 'var(--text-muted)',
                padding: '9px 18px',
                borderRadius: '10px',
                fontSize: '0.86rem',
                fontWeight: 600,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                transition: 'all 0.2s',
                boxShadow: isActive ? '0 0 16px var(--primary-glow)' : 'none',
              }}
            >
              <Icon size={16} />
              <span>{tab.label}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
