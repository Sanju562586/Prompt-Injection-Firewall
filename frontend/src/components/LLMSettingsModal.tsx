'use client';

import React, { useState, useEffect } from 'react';
import { Settings, X, Save, CheckCircle, Cpu, Key, Globe, Sparkles } from 'lucide-react';

interface LLMSettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSaved?: () => void;
}

export const LLMSettingsModal: React.FC<LLMSettingsModalProps> = ({ isOpen, onClose, onSaved }) => {
  const [provider, setProvider] = useState('local');
  const [apiKey, setApiKey] = useState('');
  const [baseUrl, setBaseUrl] = useState('');
  const [model, setModel] = useState('gpt-4o');
  const [hasApiKey, setHasApiKey] = useState(false);
  const [isSaving, setIsSaving] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  useEffect(() => {
    if (isOpen) {
      fetchSettings();
    }
  }, [isOpen]);

  const fetchSettings = async () => {
    try {
      const res = await fetch('/api/settings/llm');
      if (res.ok) {
        const data = await res.json();
        setProvider(data.provider || 'local');
        setModel(data.model || 'gpt-4o');
        setBaseUrl(data.base_url || '');
        setHasApiKey(data.has_api_key || false);
      }
    } catch (e) {
      console.error('Failed to fetch LLM settings', e);
    }
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    setStatusMsg(null);
    try {
      const res = await fetch('/api/settings/llm', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          provider,
          api_key: apiKey ? apiKey : undefined,
          base_url: baseUrl ? baseUrl : undefined,
          model: model ? model : undefined,
        }),
      });
      if (res.ok) {
        setStatusMsg('LLM Provider configuration updated successfully.');
        setApiKey('');
        fetchSettings();
        if (onSaved) onSaved();
        setTimeout(() => {
          onClose();
          setStatusMsg(null);
        }, 1200);
      }
    } catch (err: any) {
      setStatusMsg(`Error: ${err.message}`);
    } finally {
      setIsSaving(false);
    }
  };

  if (!isOpen) return null;

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
        border: '1px solid var(--border-card)',
        borderRadius: '18px',
        width: '100%',
        maxWidth: '520px',
        boxShadow: '0 20px 40px -10px rgba(124, 92, 252, 0.15)',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column'
      }}>
        {/* Header */}
        <div style={{
          padding: '1.25rem 1.5rem',
          background: 'var(--bg-subtle)',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <div style={{
              width: '38px',
              height: '38px',
              borderRadius: '10px',
              background: 'var(--primary-bg)',
              border: '1px solid var(--border-subtle)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--primary)'
            }}>
              <Settings size={20} />
            </div>
            <div>
              <h3 style={{ margin: 0, fontSize: '1.1rem', color: 'var(--text-main)', fontWeight: 700 }}>
                LLM Provider Configuration
              </h3>
              <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Connect live upstream models or use built-in semantic NLP
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent',
              border: 'none',
              color: 'var(--text-muted)',
              cursor: 'pointer',
              padding: '0.4rem',
              borderRadius: '6px'
            }}
          >
            <X size={18} />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSave} style={{ padding: '1.5rem', display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          {statusMsg && (
            <div style={{
              padding: '0.75rem 1rem',
              borderRadius: '8px',
              background: 'var(--success-bg)',
              border: '1px solid var(--success-border)',
              color: 'var(--success)',
              fontSize: '0.82rem',
              fontWeight: 600,
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              <CheckCircle size={15} />
              <span>{statusMsg}</span>
            </div>
          )}

          <div>
            <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.4rem' }}>
              Inference Engine / Provider
            </label>
            <select
              value={provider}
              onChange={(e) => setProvider(e.target.value)}
              style={{
                width: '100%',
                padding: '0.75rem 0.9rem',
                background: '#faf9fd',
                border: '1px solid var(--border-input)',
                borderRadius: '8px',
                color: 'var(--text-main)',
                fontSize: '0.88rem',
                outline: 'none'
              }}
            >
              <option value="local">Local Neural QA Synthesizer (No API Key needed)</option>
              <option value="openai">OpenAI API (GPT-4o, GPT-4o-mini, GPT-3.5-turbo)</option>
              <option value="ollama">Ollama (Local LLM - Llama 3, Mistral, Phi-3)</option>
              <option value="custom">Custom OpenAI-Compatible (Groq, Together, vLLM, DeepSeek)</option>
            </select>
          </div>

          {provider !== 'local' && (
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.4rem' }}>
                API Key {hasApiKey && <span style={{ color: 'var(--success)', fontSize: '0.75rem', fontWeight: 600 }}>(Configured in environment)</span>}
              </label>
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <Key size={16} color="var(--primary)" style={{ position: 'absolute', left: '0.8rem' }} />
                <input
                  type="password"
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder={hasApiKey ? '••••••••••••••••••••••••••••' : 'sk-...'}
                  style={{
                    width: '100%',
                    padding: '0.75rem 0.9rem 0.75rem 2.4rem',
                    background: '#faf9fd',
                    border: '1px solid var(--border-input)',
                    borderRadius: '8px',
                    color: 'var(--text-main)',
                    fontSize: '0.88rem',
                    outline: 'none'
                  }}
                />
              </div>
            </div>
          )}

          <div>
            <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.4rem' }}>
              Target Model Name
            </label>
            <input
              type="text"
              value={model}
              onChange={(e) => setModel(e.target.value)}
              placeholder="e.g. gpt-4o, llama3:latest, mistral"
              style={{
                width: '100%',
                padding: '0.75rem 0.9rem',
                background: '#faf9fd',
                border: '1px solid var(--border-input)',
                borderRadius: '8px',
                color: 'var(--text-main)',
                fontSize: '0.88rem',
                outline: 'none'
              }}
            />
          </div>

          {(provider === 'custom' || provider === 'ollama') && (
            <div>
              <label style={{ display: 'block', fontSize: '0.8rem', color: 'var(--text-muted)', fontWeight: 600, marginBottom: '0.4rem' }}>
                Base Endpoint URL
              </label>
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <Globe size={16} color="var(--primary)" style={{ position: 'absolute', left: '0.8rem' }} />
                <input
                  type="text"
                  value={baseUrl}
                  onChange={(e) => setBaseUrl(e.target.value)}
                  placeholder={provider === 'ollama' ? 'http://localhost:11434' : 'https://api.groq.com/openai/v1'}
                  style={{
                    width: '100%',
                    padding: '0.75rem 0.9rem 0.75rem 2.4rem',
                    background: '#faf9fd',
                    border: '1px solid var(--border-input)',
                    borderRadius: '8px',
                    color: 'var(--text-main)',
                    fontSize: '0.88rem',
                    outline: 'none'
                  }}
                />
              </div>
            </div>
          )}

          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'flex-end',
            gap: '0.75rem',
            paddingTop: '0.75rem',
            borderTop: '1px solid var(--border-subtle)'
          }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                background: '#ffffff',
                color: 'var(--text-muted)',
                border: '1px solid var(--border-card)',
                padding: '0.55rem 1rem',
                borderRadius: '8px',
                fontSize: '0.82rem',
                fontWeight: 600,
                cursor: 'pointer'
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSaving}
              style={{
                background: 'linear-gradient(135deg, #7c5cfc, #6a46f9)',
                color: '#ffffff',
                border: 'none',
                padding: '0.55rem 1.25rem',
                borderRadius: '8px',
                fontSize: '0.82rem',
                fontWeight: 600,
                cursor: isSaving ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
                boxShadow: '0 4px 12px rgba(124, 92, 252, 0.25)'
              }}
            >
              <Save size={15} />
              {isSaving ? 'Saving...' : 'Save Settings'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
