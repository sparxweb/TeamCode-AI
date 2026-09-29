import React from 'react';
import { Brain, Code2, History, Database, Cpu } from 'lucide-react';
import type { ServiceHealth } from '../types';

interface HeaderProps {
  activeTab: 'review' | 'teach' | 'history';
  setActiveTab: (tab: 'review' | 'teach' | 'history') => void;
  health: ServiceHealth | null;
  onRefreshHealth: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  health,
  onRefreshHealth,
}) => {
  return (
    <header className="app-header" role="banner">
      <div className="header-container">
        {/* Brand Section */}
        <div className="brand-section">
          <div className="brand-icon-wrapper" aria-hidden="true">
            <Brain className="brand-icon" size={20} />
          </div>
          <div className="brand-text">
            <div className="brand-title-row">
              <span className="brand-title">TeamCode AI</span>
              <span className="badge-agent" title="Active AI Review Agent">SaaS Engine</span>
            </div>
            <p className="brand-tagline">
              Memory-powered code review for engineering teams
            </p>
          </div>
        </div>

        {/* Navigation */}
        <nav className="header-nav" role="navigation" aria-label="Main Navigation">
          <button
            type="button"
            className={`nav-tab ${activeTab === 'review' ? 'active' : ''}`}
            onClick={() => setActiveTab('review')}
            aria-selected={activeTab === 'review'}
            role="tab"
          >
            <Code2 size={15} aria-hidden="true" />
            <span>Review</span>
          </button>
          <button
            type="button"
            className={`nav-tab ${activeTab === 'teach' ? 'active' : ''}`}
            onClick={() => setActiveTab('teach')}
            aria-selected={activeTab === 'teach'}
            role="tab"
          >
            <Brain size={15} aria-hidden="true" />
            <span>Team Memory</span>
          </button>
          <button
            type="button"
            className={`nav-tab ${activeTab === 'history' ? 'active' : ''}`}
            onClick={() => setActiveTab('history')}
            aria-selected={activeTab === 'history'}
            role="tab"
          >
            <History size={15} aria-hidden="true" />
            <span>History</span>
          </button>
        </nav>

        {/* Small System Status Indicator */}
        <div 
          className="header-system-status" 
          onClick={onRefreshHealth} 
          title="Click to refresh system status"
          role="button"
          tabIndex={0}
          onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') onRefreshHealth(); }}
          aria-label="System status"
        >
          {/* Hindsight Status */}
          <div className="status-indicator-pill" title={health?.hindsight_configured ? `Hindsight Connected (Bank: ${health.hindsight_bank_id})` : 'Hindsight Disconnected'}>
            <span className={`status-dot ${health?.hindsight_configured ? 'online' : 'offline'}`} aria-hidden="true"></span>
            <Database size={13} className="status-icon" aria-hidden="true" />
            <span className="status-title">Hindsight</span>
            <span className="status-sub">
              {health?.hindsight_configured ? 'Connected' : 'Disconnected'}
            </span>
          </div>

          {/* LLM Status */}
          <div className="status-indicator-pill" title={health?.groq_configured ? `Groq Connected (${health.groq_model})` : 'Groq Disconnected'}>
            <span className={`status-dot ${health?.groq_configured ? 'online' : 'offline'}`} aria-hidden="true"></span>
            <Cpu size={13} className="status-icon" aria-hidden="true" />
            <span className="status-title">Groq</span>
            <span className="status-sub">
              {health?.groq_configured ? 'Connected' : 'Disconnected'}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
};
