'use client';

import React, { useState, useEffect, useRef } from 'react';
import {
  FileText,
  Plus,
  Trash2,
  AlertTriangle,
  RefreshCw,
  Search,
  CheckCircle,
  Database,
  UploadCloud,
  FileWarning,
  Eye,
  X
} from 'lucide-react';

interface KBDocument {
  id: string;
  title: string;
  category: string;
  tags: string[];
  created_at?: string;
  content_length: number;
  snippet: string;
  is_trojan: boolean;
  chunks_count: number;
}

export const KnowledgeBaseManager: React.FC = () => {
  const [documents, setDocuments] = useState<KBDocument[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [searchQuery, setSearchQuery] = useState('');
  const [showAddForm, setShowAddForm] = useState(false);
  const [selectedDoc, setSelectedDoc] = useState<KBDocument | null>(null);

  const [newTitle, setNewTitle] = useState('');
  const [newCategory, setNewCategory] = useState('General');
  const [newContent, setNewContent] = useState('');
  const [newTags, setNewTags] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const filePickerRef = useRef<HTMLInputElement>(null);

  const fetchDocuments = async () => {
    setIsLoading(true);
    try {
      const res = await fetch('/api/rag/documents');
      if (res.ok) {
        const data = await res.json();
        setDocuments(data.documents || []);
      }
    } catch (err) {
      console.error('Failed to fetch documents', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchDocuments();
  }, []);

  const handleAddDocument = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newTitle.trim() || !newContent.trim()) return;

    setIsSubmitting(true);
    setStatusMessage(null);

    try {
      const tagsArray = newTags
        .split(',')
        .map(t => t.trim())
        .filter(Boolean);

      const res = await fetch('/api/rag/documents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          title: newTitle,
          category: newCategory,
          content: newContent,
          tags: tagsArray,
          is_trojan: false,
        }),
      });

      if (res.ok) {
        setStatusMessage({ type: 'success', text: 'Document indexed successfully into RAG knowledge base.' });
        setNewTitle('');
        setNewCategory('General');
        setNewContent('');
        setNewTags('');
        setShowAddForm(false);
        fetchDocuments();
      } else {
        throw new Error('Failed to save document');
      }
    } catch (err: any) {
      setStatusMessage({ type: 'error', text: err.message });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleFilePicked = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (event) => {
      const text = event.target?.result as string;
      if (text) {
        setIsLoading(true);
        try {
          const res = await fetch('/api/rag/documents', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              title: file.name,
              category: 'Uploaded Document',
              content: text,
              tags: ['file-upload', file.name.split('.').pop() || 'text'],
              is_trojan: false,
            }),
          });
          if (res.ok) {
            setStatusMessage({ type: 'success', text: `Uploaded and indexed "${file.name}" successfully.` });
            fetchDocuments();
          }
        } catch (err: any) {
          setStatusMessage({ type: 'error', text: err.message });
        } finally {
          setIsLoading(false);
        }
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const handleDelete = async (docId: string) => {
    if (!confirm('Are you sure you want to delete this document from the knowledge base?')) return;

    try {
      const res = await fetch(`/api/rag/documents/${docId}`, { method: 'DELETE' });
      if (res.ok) {
        setDocuments(prev => prev.filter(d => d.id !== docId));
        setStatusMessage({ type: 'success', text: 'Document removed from knowledge base.' });
      }
    } catch (err) {
      console.error('Delete error', err);
    }
  };

  const handleInjectTrojan = async () => {
    setIsLoading(true);
    setStatusMessage(null);
    try {
      const res = await fetch('/api/rag/documents/sample-poison', { method: 'POST' });
      if (res.ok) {
        setStatusMessage({
          type: 'success',
          text: 'Sample poisoned document injected. You can test RAG indirect injection defense in the AI Assistant.'
        });
        fetchDocuments();
      }
    } catch (err) {
      console.error('Trojan injection error', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleResetDefaults = async () => {
    if (!confirm('Reset knowledge base back to corporate default baseline?')) return;
    setIsLoading(true);
    setStatusMessage(null);
    try {
      const res = await fetch('/api/rag/documents/reset', { method: 'POST' });
      if (res.ok) {
        setStatusMessage({ type: 'success', text: 'Knowledge base reset to corporate baseline.' });
        fetchDocuments();
      }
    } catch (err) {
      console.error('Reset error', err);
    } finally {
      setIsLoading(false);
    }
  };

  const filteredDocs = documents.filter(d =>
    d.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
    d.category.toLowerCase().includes(searchQuery.toLowerCase()) ||
    d.snippet.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div style={{ maxWidth: '1200px', margin: '0 auto', display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      <input
        type="file"
        ref={filePickerRef}
        onChange={handleFilePicked}
        accept=".txt,.md,.json,.csv"
        style={{ display: 'none' }}
      />

      {/* Full Document View Modal */}
      {selectedDoc && (
        <div style={{
          position: 'fixed',
          inset: 0,
          zIndex: 9999,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          background: 'rgba(5, 8, 14, 0.8)',
          backdropFilter: 'blur(8px)',
          padding: '1.5rem'
        }}>
          <div style={{
            background: '#0d1117',
            border: '1px solid #30363d',
            borderRadius: '16px',
            width: '100%',
            maxWidth: '650px',
            maxHeight: '80vh',
            display: 'flex',
            flexDirection: 'column',
            overflow: 'hidden'
          }}>
            <div style={{
              padding: '1.25rem 1.5rem',
              background: 'rgba(22, 27, 34, 0.95)',
              borderBottom: '1px solid #30363d',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between'
            }}>
              <div>
                <span style={{
                  padding: '0.15rem 0.5rem',
                  borderRadius: '4px',
                  fontSize: '0.7rem',
                  fontWeight: 700,
                  background: 'rgba(56, 189, 248, 0.15)',
                  color: '#38bdf8'
                }}>
                  {selectedDoc.category}
                </span>
                <h3 style={{ margin: '0.4rem 0 0 0', fontSize: '1.1rem', color: '#f0f6fc' }}>
                  {selectedDoc.title}
                </h3>
              </div>
              <button
                onClick={() => setSelectedDoc(null)}
                style={{ background: 'transparent', border: 'none', color: '#8b949e', cursor: 'pointer', padding: '0.4rem' }}
              >
                <X size={20} />
              </button>
            </div>
            <div style={{ padding: '1.5rem', overflowY: 'auto', flex: 1 }}>
              <pre style={{
                margin: 0,
                whiteSpace: 'pre-wrap',
                fontFamily: 'monospace',
                fontSize: '0.85rem',
                color: '#e6edf3',
                lineHeight: '1.6'
              }}>
                {selectedDoc.snippet}
              </pre>
            </div>
            <div style={{ padding: '1rem 1.5rem', borderTop: '1px solid #30363d', background: 'rgba(22, 27, 34, 0.9)', display: 'flex', justifyContent: 'flex-end' }}>
              <button
                onClick={() => setSelectedDoc(null)}
                style={{
                  background: 'rgba(33, 38, 45, 0.8)',
                  color: '#c9d1d9',
                  border: '1px solid #30363d',
                  padding: '0.5rem 1.2rem',
                  borderRadius: '8px',
                  fontSize: '0.82rem',
                  cursor: 'pointer'
                }}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Top Banner & Actions */}
      <div style={{
        background: '#0d1117',
        border: '1px solid #30363d',
        borderRadius: '16px',
        padding: '1.5rem',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
          <div style={{
            width: '42px',
            height: '42px',
            borderRadius: '12px',
            background: 'rgba(56, 189, 248, 0.15)',
            border: '1px solid rgba(56, 189, 248, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: '#38bdf8'
          }}>
            <Database size={22} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <h2 style={{ margin: 0, fontSize: '1.2rem', color: '#f0f6fc', fontWeight: 600 }}>
                RAG Knowledge Base
              </h2>
              <span style={{
                background: 'rgba(56, 189, 248, 0.12)',
                color: '#38bdf8',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                padding: '0.15rem 0.6rem',
                borderRadius: '999px',
                fontSize: '0.72rem',
                fontWeight: 700
              }}>
                {documents.length} Articles Indexed
              </span>
            </div>
            <div style={{ fontSize: '0.78rem', color: '#8b949e', marginTop: '0.2rem' }}>
              Persistent document repository • Scanned by RAG Poisoning Detector on retrieval
            </div>
          </div>
        </div>

        {/* Action Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <button
            onClick={() => filePickerRef.current?.click()}
            style={{
              background: 'rgba(56, 189, 248, 0.12)',
              color: '#38bdf8',
              border: '1px solid rgba(56, 189, 248, 0.4)',
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
            title="Upload and index any text file (.txt, .md, .json, .csv)"
          >
            <UploadCloud size={16} />
            Upload File
          </button>

          <button
            onClick={() => setShowAddForm(!showAddForm)}
            style={{
              background: '#238636',
              color: '#ffffff',
              border: 'none',
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
            <Plus size={16} />
            Add Text
          </button>

          <button
            onClick={handleInjectTrojan}
            style={{
              background: 'rgba(239, 68, 68, 0.12)',
              color: '#f87171',
              border: '1px solid rgba(239, 68, 68, 0.4)',
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
            title="Inject a realistic poisoned document to test RAG indirect injection defense"
          >
            <FileWarning size={16} />
            Inject Test Trojan
          </button>

          <button
            onClick={handleResetDefaults}
            style={{
              background: 'rgba(33, 38, 45, 0.8)',
              color: '#c9d1d9',
              border: '1px solid #30363d',
              padding: '0.55rem 0.9rem',
              borderRadius: '8px',
              fontSize: '0.82rem',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem'
            }}
          >
            <RefreshCw size={14} />
            Reset Baseline
          </button>
        </div>
      </div>

      {/* Status Alert Banner */}
      {statusMessage && (
        <div style={{
          padding: '0.85rem 1.25rem',
          borderRadius: '10px',
          background: statusMessage.type === 'success' ? 'rgba(46, 160, 67, 0.15)' : 'rgba(239, 68, 68, 0.15)',
          border: `1px solid ${statusMessage.type === 'success' ? '#2ea043' : '#ef4444'}`,
          color: statusMessage.type === 'success' ? '#3fb950' : '#f87171',
          fontSize: '0.85rem',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem'
        }}>
          {statusMessage.type === 'success' ? <CheckCircle size={16} /> : <AlertTriangle size={16} />}
          <span>{statusMessage.text}</span>
        </div>
      )}

      {/* Add Document Inline Drawer */}
      {showAddForm && (
        <div style={{
          background: '#0d1117',
          border: '1px solid #388bfd',
          borderRadius: '14px',
          padding: '1.5rem',
          boxShadow: '0 8px 24px rgba(0,0,0,0.4)',
          animation: 'fadeIn 0.2s ease-out'
        }}>
          <h3 style={{ margin: '0 0 1rem 0', fontSize: '1rem', color: '#f0f6fc', fontWeight: 600 }}>
            Index New Document
          </h3>
          <form onSubmit={handleAddDocument} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', color: '#8b949e', marginBottom: '0.3rem' }}>
                  Document Title
                </label>
                <input
                  type="text"
                  required
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="e.g. Employee Cyber Safety Handbook"
                  style={{
                    width: '100%',
                    padding: '0.65rem 0.9rem',
                    background: '#090d13',
                    border: '1px solid #30363d',
                    borderRadius: '8px',
                    color: '#f0f6fc',
                    fontSize: '0.85rem'
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.78rem', color: '#8b949e', marginBottom: '0.3rem' }}>
                  Category
                </label>
                <select
                  value={newCategory}
                  onChange={(e) => setNewCategory(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.65rem 0.9rem',
                    background: '#090d13',
                    border: '1px solid #30363d',
                    borderRadius: '8px',
                    color: '#f0f6fc',
                    fontSize: '0.85rem'
                  }}
                >
                  <option value="IT & Security">IT & Security</option>
                  <option value="Human Resources">Human Resources</option>
                  <option value="Finance">Finance</option>
                  <option value="Engineering">Engineering</option>
                  <option value="Compliance">Compliance</option>
                  <option value="General">General</option>
                </select>
              </div>
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: '#8b949e', marginBottom: '0.3rem' }}>
                Tags (Comma-separated)
              </label>
              <input
                type="text"
                value={newTags}
                onChange={(e) => setNewTags(e.target.value)}
                placeholder="security, password, remote-work"
                style={{
                  width: '100%',
                  padding: '0.65rem 0.9rem',
                  background: '#090d13',
                  border: '1px solid #30363d',
                  borderRadius: '8px',
                  color: '#f0f6fc',
                  fontSize: '0.85rem'
                }}
              />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: '0.78rem', color: '#8b949e', marginBottom: '0.3rem' }}>
                Document Content / Text Body
              </label>
              <textarea
                rows={5}
                required
                value={newContent}
                onChange={(e) => setNewContent(e.target.value)}
                placeholder="Paste knowledge text or policy guidelines here..."
                style={{
                  width: '100%',
                  padding: '0.75rem 0.9rem',
                  background: '#090d13',
                  border: '1px solid #30363d',
                  borderRadius: '8px',
                  color: '#f0f6fc',
                  fontSize: '0.85rem',
                  fontFamily: 'monospace'
                }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={() => setShowAddForm(false)}
                style={{
                  background: 'transparent',
                  color: '#8b949e',
                  border: '1px solid #30363d',
                  padding: '0.55rem 1rem',
                  borderRadius: '8px',
                  fontSize: '0.82rem',
                  cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isSubmitting}
                style={{
                  background: '#238636',
                  color: '#ffffff',
                  border: 'none',
                  padding: '0.55rem 1.25rem',
                  borderRadius: '8px',
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  cursor: isSubmitting ? 'not-allowed' : 'pointer'
                }}
              >
                {isSubmitting ? 'Indexing...' : 'Index Document'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Search Input Bar */}
      <div style={{
        position: 'relative',
        display: 'flex',
        alignItems: 'center'
      }}>
        <Search size={18} color="#8b949e" style={{ position: 'absolute', left: '1rem' }} />
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Filter indexed articles by title, category, or snippet..."
          style={{
            width: '100%',
            padding: '0.75rem 1rem 0.75rem 2.8rem',
            borderRadius: '10px',
            background: '#0d1117',
            border: '1px solid #30363d',
            color: '#f0f6fc',
            fontSize: '0.85rem'
          }}
        />
      </div>

      {/* Document Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '1rem' }}>
        {filteredDocs.map(doc => (
          <div
            key={doc.id}
            style={{
              background: '#0d1117',
              border: `1px solid ${doc.is_trojan ? 'rgba(239, 68, 68, 0.5)' : '#30363d'}`,
              borderRadius: '14px',
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              justifyContent: 'space-between',
              boxShadow: doc.is_trojan ? '0 0 15px rgba(239, 68, 68, 0.15)' : 'none',
              transition: 'all 0.2s'
            }}
          >
            <div>
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '0.5rem', marginBottom: '0.6rem' }}>
                <span style={{
                  padding: '0.2rem 0.55rem',
                  borderRadius: '6px',
                  fontSize: '0.7rem',
                  fontWeight: 700,
                  background: doc.is_trojan ? 'rgba(239, 68, 68, 0.15)' : 'rgba(56, 189, 248, 0.12)',
                  color: doc.is_trojan ? '#f87171' : '#38bdf8',
                  border: `1px solid ${doc.is_trojan ? 'rgba(239, 68, 68, 0.4)' : 'rgba(56, 189, 248, 0.3)'}`
                }}>
                  {doc.category}
                </span>

                {doc.is_trojan && (
                  <span style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.25rem',
                    background: 'rgba(239, 68, 68, 0.2)',
                    color: '#ef4444',
                    padding: '0.2rem 0.5rem',
                    borderRadius: '6px',
                    fontSize: '0.68rem',
                    fontWeight: 700
                  }}>
                    <FileWarning size={13} />
                    POISONED TROJAN
                  </span>
                )}
              </div>

              <h3 style={{ margin: '0 0 0.5rem 0', fontSize: '1rem', color: '#f0f6fc', fontWeight: 600 }}>
                {doc.title}
              </h3>

              <p style={{ margin: '0 0 0.8rem 0', fontSize: '0.8rem', color: '#8b949e', lineHeight: '1.45' }}>
                {doc.snippet}
              </p>

              {doc.tags && doc.tags.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', marginBottom: '0.8rem' }}>
                  {doc.tags.map((t, idx) => (
                    <span key={idx} style={{
                      background: 'rgba(33, 38, 45, 0.8)',
                      color: '#c9d1d9',
                      padding: '0.15rem 0.45rem',
                      borderRadius: '4px',
                      fontSize: '0.68rem'
                    }}>
                      #{t}
                    </span>
                  ))}
                </div>
              )}
            </div>

            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              borderTop: '1px solid #21262d',
              paddingTop: '0.75rem',
              fontSize: '0.75rem',
              color: '#6e7681'
            }}>
              <span>{doc.chunks_count} chunk(s)</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <button
                  onClick={() => setSelectedDoc(doc)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: '#58a6ff',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.2rem',
                    fontSize: '0.75rem'
                  }}
                  title="View document text"
                >
                  <Eye size={13} />
                  View
                </button>

                <button
                  onClick={() => handleDelete(doc.id)}
                  style={{
                    background: 'transparent',
                    border: 'none',
                    color: '#f85149',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.2rem',
                    fontSize: '0.75rem'
                  }}
                  title="Delete document"
                >
                  <Trash2 size={13} />
                  Delete
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};