'use client';

import React, { useState, useRef, useEffect } from 'react';
import {
  Send,
  Bot,
  User,
  ShieldAlert,
  ShieldCheck,
  FileText,
  FileWarning,
  Sparkles,
  RefreshCw,
  Info,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Settings,
  Paperclip
} from 'lucide-react';
import { SecurityAlertData } from './SecurityAlertModal';
import { LLMSettingsModal } from './LLMSettingsModal';

interface ChatSource {
  chunk_id: string;
  doc_id: string;
  title: string;
  category: string;
  score: number;
  is_safe: boolean;
  quarantine_reason?: string;
  snippet: string;
}

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  sources?: ChatSource[];
  isBlocked?: boolean;
  quarantinedCount?: number;
}

interface RAGChatbotProps {
  onTriggerAlert: (alert: SecurityAlertData) => void;
  onNavigateToKnowledge: () => void;
  onNavigateToTelemetry: () => void;
}

export const RAGChatbot: React.FC<RAGChatbotProps> = ({
  onTriggerAlert,
  onNavigateToKnowledge,
  onNavigateToTelemetry,
}) => {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'msg-welcome',
      role: 'assistant',
      content: 'Welcome! I am your Enterprise AI Assistant, operating with continuous LLM Security Firewall protection.\n\nYou can ask any question grounded in the indexed knowledge base (corporate policies, engineering SOPs, finance, compliance) or test your own custom queries. Any injected malicious directives or poisoned retrieved documents will be intercepted and quarantined.',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [expandedSources, setExpandedSources] = useState<Record<string, boolean>>({});
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [activeModel, setActiveModel] = useState('Local Synthesizer');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const fetchModelInfo = async () => {
    try {
      const res = await fetch('/api/settings/llm');
      if (res.ok) {
        const data = await res.json();
        if (data.provider === 'openai') {
          setActiveModel(`OpenAI (${data.model})`);
        } else if (data.provider === 'ollama') {
          setActiveModel(`Ollama (${data.model})`);
        } else if (data.provider === 'custom') {
          setActiveModel(`Custom (${data.model})`);
        } else {
          setActiveModel('Local Neural QA');
        }
      }
    } catch (e) {
      console.error(e);
    }
  };

  useEffect(() => {
    fetchModelInfo();
  }, []);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading]);

  const toggleSourceExpand = (msgId: string) => {
    setExpandedSources(prev => ({ ...prev, [msgId]: !prev[msgId] }));
  };

  const handleSend = async (queryText?: string) => {
    const promptToSend = (queryText || inputValue).trim();
    if (!promptToSend || isLoading) return;

    const userMsg: Message = {
      id: `usr-${Date.now()}`,
      role: 'user',
      content: promptToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    };

    setMessages(prev => [...prev, userMsg]);
    setInputValue('');
    setIsLoading(true);

    try {
      const chatHistory = messages
        .filter(m => m.id !== 'msg-welcome')
        .map(m => ({ role: m.role, content: m.content }));

      const res = await fetch('/api/rag/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: promptToSend,
          chat_history: chatHistory,
          top_k: 3,
          temperature: 0.7,
        }),
      });

      if (!res.ok) {
        throw new Error(`Server returned HTTP ${res.status}`);
      }

      const data = await res.json();
      const quarantined = data.sources?.filter((s: ChatSource) => !s.is_safe).length || 0;

      const assistantMsg: Message = {
        id: `asst-${Date.now()}`,
        role: 'assistant',
        content: data.answer,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        sources: data.sources,
        isBlocked: data.telemetry?.action === 'BLOCKED',
        quarantinedCount: quarantined,
      };

      setMessages(prev => [...prev, assistantMsg]);

      // Pop-up window triggered whenever suspicious, malicious, or quarantined content is intercepted
      if (data.security_alert && data.security_alert.has_threat) {
        onTriggerAlert(data.security_alert);
      }
    } catch (err: any) {
      setMessages(prev => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          role: 'assistant',
          content: `⚠️ Failed to connect to RAG Gateway: ${err.message}. Please verify the backend gateway is running.`,
          timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        }
      ]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (event) => {
      const text = event.target?.result as string;
      if (text) {
        try {
          const res = await fetch('/api/rag/documents', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              title: file.name,
              category: 'User Upload',
              content: text,
              tags: ['uploaded', 'document'],
              is_trojan: false,
            }),
          });
          if (res.ok) {
            setMessages(prev => [
              ...prev,
              {
                id: `sys-${Date.now()}`,
                role: 'assistant',
                content: `📄 **Document Ingested**: Successfully indexed "${file.name}" (${text.length} characters) into the knowledge base. You can now ask questions about its content.`,
                timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
              }
            ]);
          }
        } catch (err) {
          console.error(err);
        }
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const clearChat = () => {
    setMessages([
      {
        id: 'msg-welcome',
        role: 'assistant',
        content: 'Chat reset. How can I assist you today? Ask questions about any knowledge documents or test custom queries.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      }
    ]);
  };

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: 'calc(100vh - 120px)',
      maxWidth: '1100px',
      margin: '0 auto',
      background: '#0d1117',
      border: '1px solid #30363d',
      borderRadius: '16px',
      overflow: 'hidden',
      boxShadow: '0 20px 40px -10px rgba(0,0,0,0.7)'
    }}>
      <LLMSettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        onSaved={fetchModelInfo}
      />

      <input
        type="file"
        ref={fileInputRef}
        onChange={handleFileUpload}
        accept=".txt,.md,.json,.csv"
        style={{ display: 'none' }}
      />

      {/* Chat Top Banner */}
      <div style={{
        padding: '1rem 1.5rem',
        background: 'rgba(22, 27, 34, 0.95)',
        borderBottom: '1px solid #30363d',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '0.75rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{
            width: '38px',
            height: '38px',
            borderRadius: '10px',
            background: 'rgba(56, 189, 248, 0.15)',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#38bdf8'
          }}>
            <Bot size={22} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <h2 style={{ margin: 0, fontSize: '1.05rem', color: '#f0f6fc', fontWeight: 600 }}>
                Enterprise Knowledge Assistant
              </h2>
              <span style={{
                background: 'rgba(56, 189, 248, 0.12)',
                color: '#38bdf8',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                padding: '0.15rem 0.5rem',
                borderRadius: '999px',
                fontSize: '0.7rem',
                fontWeight: 700
              }}>
                {activeModel}
              </span>
            </div>
            <div style={{ fontSize: '0.75rem', color: '#8b949e', marginTop: '0.1rem' }}>
              Dual-Stage Firewall Protection (Input Scanner • RAG Quarantine • Risk Engine • Output Presidio)
            </div>
          </div>
        </div>

        {/* Action buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <button
            onClick={() => setIsSettingsOpen(true)}
            style={{
              background: 'rgba(33, 38, 45, 0.8)',
              border: '1px solid #30363d',
              color: '#c9d1d9',
              padding: '0.4rem 0.75rem',
              borderRadius: '8px',
              fontSize: '0.75rem',
              fontWeight: 500,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem'
            }}
            title="Configure LLM Provider (OpenAI, Ollama, Custom)"
          >
            <Settings size={14} color="#38bdf8" />
            <span>LLM Config</span>
          </button>

          <button
            onClick={onNavigateToKnowledge}
            style={{
              background: 'rgba(33, 38, 45, 0.8)',
              border: '1px solid #30363d',
              color: '#c9d1d9',
              padding: '0.4rem 0.75rem',
              borderRadius: '8px',
              fontSize: '0.75rem',
              fontWeight: 500,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem'
            }}
          >
            <FileText size={14} color="#58a6ff" />
            <span>Knowledge Base</span>
          </button>

          <button
            onClick={clearChat}
            style={{
              background: 'rgba(33, 38, 45, 0.8)',
              border: '1px solid #30363d',
              color: '#8b949e',
              padding: '0.4rem 0.6rem',
              borderRadius: '8px',
              fontSize: '0.75rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.35rem'
            }}
            title="Clear Chat History"
          >
            <RefreshCw size={13} />
            <span>Reset</span>
          </button>
        </div>
      </div>

      {/* Message Stream */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        padding: '1.5rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1.25rem'
      }}>
        {messages.map(msg => {
          const isUser = msg.role === 'user';
          const isBlocked = msg.isBlocked;
          const hasQuarantine = (msg.quarantinedCount || 0) > 0;

          return (
            <div
              key={msg.id}
              style={{
                display: 'flex',
                gap: '0.85rem',
                alignSelf: isUser ? 'flex-end' : 'flex-start',
                maxWidth: isUser ? '80%' : '88%',
                animation: 'fadeIn 0.2s ease-out'
              }}
            >
              {!isUser && (
                <div style={{
                  width: '34px',
                  height: '34px',
                  borderRadius: '10px',
                  background: isBlocked
                    ? 'rgba(239, 68, 68, 0.2)'
                    : hasQuarantine
                    ? 'rgba(245, 158, 11, 0.2)'
                    : 'rgba(56, 189, 248, 0.15)',
                  border: `1px solid ${isBlocked ? '#ef4444' : hasQuarantine ? '#f59e0b' : '#38bdf8'}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: isBlocked ? '#ef4444' : hasQuarantine ? '#f59e0b' : '#38bdf8',
                  flexShrink: 0
                }}>
                  {isBlocked ? <ShieldAlert size={18} /> : hasQuarantine ? <AlertTriangle size={18} /> : <Bot size={18} />}
                </div>
              )}

              <div style={{
                display: 'flex',
                flexDirection: 'column',
                gap: '0.4rem',
                alignItems: isUser ? 'flex-end' : 'flex-start'
              }}>
                <div style={{
                  padding: '0.9rem 1.15rem',
                  borderRadius: isUser ? '16px 16px 4px 16px' : '16px 16px 16px 4px',
                  background: isUser
                    ? '#1f6feb'
                    : isBlocked
                    ? 'rgba(239, 68, 68, 0.12)'
                    : 'rgba(22, 27, 34, 0.95)',
                  border: `1px solid ${isUser ? '#388bfd' : isBlocked ? 'rgba(239, 68, 68, 0.4)' : '#30363d'}`,
                  color: '#f0f6fc',
                  fontSize: '0.9rem',
                  lineHeight: '1.55',
                  whiteSpace: 'pre-wrap',
                  boxShadow: '0 4px 12px rgba(0,0,0,0.2)'
                }}>
                  {msg.content}
                </div>

                {/* Sources Card Accordion */}
                {!isUser && msg.sources && msg.sources.length > 0 && (
                  <div style={{
                    width: '100%',
                    background: 'rgba(22, 27, 34, 0.6)',
                    border: '1px solid #30363d',
                    borderRadius: '10px',
                    overflow: 'hidden',
                    marginTop: '0.2rem'
                  }}>
                    <button
                      onClick={() => toggleSourceExpand(msg.id)}
                      style={{
                        width: '100%',
                        padding: '0.45rem 0.8rem',
                        background: 'transparent',
                        border: 'none',
                        color: '#8b949e',
                        fontSize: '0.75rem',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'space-between',
                        cursor: 'pointer'
                      }}
                    >
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                        <FileText size={13} color="#58a6ff" />
                        <span>Referenced Sources ({msg.sources.length})</span>
                        {hasQuarantine && (
                          <span style={{
                            background: 'rgba(239, 68, 68, 0.2)',
                            color: '#f87171',
                            padding: '0.1rem 0.4rem',
                            borderRadius: '4px',
                            fontSize: '0.68rem',
                            fontWeight: 600
                          }}>
                            {msg.quarantinedCount} Malicious Doc Quarantined
                          </span>
                        )}
                      </div>
                      {expandedSources[msg.id] ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                    </button>

                    {expandedSources[msg.id] && (
                      <div style={{ padding: '0.6rem 0.8rem', borderTop: '1px solid #30363d', display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        {msg.sources.map((src, sIdx) => (
                          <div
                            key={sIdx}
                            style={{
                              padding: '0.5rem 0.65rem',
                              borderRadius: '6px',
                              background: src.is_safe ? 'rgba(33, 38, 45, 0.6)' : 'rgba(239, 68, 68, 0.1)',
                              border: `1px solid ${src.is_safe ? '#30363d' : 'rgba(239, 68, 68, 0.4)'}`,
                              fontSize: '0.75rem'
                            }}
                          >
                            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.2rem' }}>
                              <strong style={{ color: src.is_safe ? '#58a6ff' : '#f87171' }}>
                                {src.title}
                              </strong>
                              <span style={{
                                padding: '0.1rem 0.4rem',
                                borderRadius: '4px',
                                fontSize: '0.65rem',
                                fontWeight: 700,
                                background: src.is_safe ? 'rgba(46, 160, 67, 0.2)' : 'rgba(239, 68, 68, 0.2)',
                                color: src.is_safe ? '#3fb950' : '#f87171'
                              }}>
                                {src.is_safe ? 'VERIFIED SAFE' : 'QUARANTINED'}
                              </span>
                            </div>
                            <div style={{ color: '#8b949e', fontSize: '0.72rem', fontStyle: 'italic' }}>
                              {src.snippet}
                            </div>
                            {src.quarantine_reason && (
                              <div style={{ color: '#f87171', fontSize: '0.7rem', marginTop: '0.25rem', fontWeight: 600 }}>
                                Violation: {src.quarantine_reason}
                              </div>
                            )}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                <div style={{ fontSize: '0.7rem', color: '#6e7681', margin: '0 0.3rem' }}>
                  {msg.timestamp}
                </div>
              </div>

              {isUser && (
                <div style={{
                  width: '34px',
                  height: '34px',
                  borderRadius: '10px',
                  background: 'rgba(31, 111, 235, 0.2)',
                  border: '1px solid #1f6feb',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  color: '#58a6ff',
                  flexShrink: 0
                }}>
                  <User size={18} />
                </div>
              )}
            </div>
          );
        })}

        {isLoading && (
          <div style={{ display: 'flex', gap: '0.85rem', alignItems: 'center', animation: 'pulse 1.5s infinite' }}>
            <div style={{
              width: '34px',
              height: '34px',
              borderRadius: '10px',
              background: 'rgba(56, 189, 248, 0.15)',
              border: '1px solid #38bdf8',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: '#38bdf8'
            }}>
              <Bot size={18} />
            </div>
            <div style={{
              padding: '0.75rem 1.1rem',
              borderRadius: '16px',
              background: 'rgba(22, 27, 34, 0.8)',
              border: '1px solid #30363d',
              color: '#8b949e',
              fontSize: '0.85rem',
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem'
            }}>
              <RefreshCw size={14} className="spin" />
              Retrieving indexed documents & running 7-stage firewall scans...
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      {/* Input Form Bar */}
      <div style={{
        padding: '1rem 1.5rem',
        background: 'rgba(22, 27, 34, 0.95)',
        borderTop: '1px solid #30363d'
      }}>
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSend();
          }}
          style={{ display: 'flex', gap: '0.75rem', alignItems: 'center' }}
        >
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            style={{
              background: 'rgba(33, 38, 45, 0.8)',
              border: '1px solid #30363d',
              borderRadius: '10px',
              padding: '0.75rem',
              color: '#8b949e',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              transition: 'color 0.15s'
            }}
            title="Upload and index a text document (.txt, .md, .json)"
          >
            <Paperclip size={18} />
          </button>

          <input
            type="text"
            value={inputValue}
            onChange={(e) => setInputValue(e.target.value)}
            placeholder="Ask a question grounded in knowledge documents, or test a prompt..."
            disabled={isLoading}
            style={{
              flex: 1,
              padding: '0.75rem 1.1rem',
              borderRadius: '10px',
              background: '#090d13',
              border: '1px solid #30363d',
              color: '#f0f6fc',
              fontSize: '0.88rem',
              outline: 'none',
              transition: 'border-color 0.15s'
            }}
          />

          <button
            type="submit"
            disabled={isLoading || !inputValue.trim()}
            style={{
              padding: '0.75rem 1.3rem',
              borderRadius: '10px',
              background: inputValue.trim() && !isLoading ? '#238636' : 'rgba(35, 134, 54, 0.3)',
              color: '#ffffff',
              border: 'none',
              fontSize: '0.88rem',
              fontWeight: 600,
              cursor: inputValue.trim() && !isLoading ? 'pointer' : 'not-allowed',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              transition: 'all 0.15s'
            }}
          >
            <span>Send</span>
            <Send size={15} />
          </button>
        </form>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '0.4rem', fontSize: '0.7rem', color: '#6e7681' }}>
          <span>Protected by Multi-Layer LLM Firewall (Input Scanner • RAG Quarantine • Risk Engine • Output Presidio)</span>
          <span style={{ color: '#38bdf8', cursor: 'pointer' }} onClick={onNavigateToTelemetry}>
            Inspect Firewall Telemetry →
          </span>
        </div>
      </div>
    </div>
  );
};