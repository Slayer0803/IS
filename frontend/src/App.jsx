import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import ScanInput from './components/ScanInput';
import RiskGauge from './components/RiskGauge';
import AnalysisBreakdown from './components/AnalysisBreakdown';
import ExplainabilityCard from './components/ExplainabilityCard';
import DashboardMetrics from './components/DashboardMetrics';
import RecentScansTable from './components/RecentScansTable';
import { analyzeUrl, fetchScans, fetchScanDetails, deleteScan, fetchDashboardStats } from './services/api';
import { AlertCircle, RefreshCw, Sparkles, Shield, Cpu } from 'lucide-react';

export default function App() {
  const [activeTab, setActiveTab] = useState('scanner');
  const [currentScan, setCurrentScan] = useState(null);
  const [scans, setScans] = useState([]);
  const [stats, setStats] = useState(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);

  // Initial data load
  const loadDashboardData = async () => {
    try {
      const [scansData, statsData] = await Promise.all([
        fetchScans(50, 0).catch(() => []),
        fetchDashboardStats().catch(() => null),
      ]);
      setScans(scansData);
      setStats(statsData);
    } catch (err) {
      console.warn('Initial data load warning:', err);
    }
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  // Handle URL Analysis
  const handleAnalyze = async (url) => {
    setIsLoading(true);
    setError(null);
    try {
      const result = await analyzeUrl(url);
      setCurrentScan(result);
      setActiveTab('scanner');
      await loadDashboardData();
    } catch (err) {
      setError(err.message || 'Failed to complete webpage analysis.');
    } finally {
      setIsLoading(false);
    }
  };

  // Inspect existing scan from history
  const handleSelectScan = async (scanId) => {
    setIsLoading(true);
    setError(null);
    try {
      const details = await fetchScanDetails(scanId);
      setCurrentScan(details);
      setActiveTab('scanner');
      window.scrollTo({ top: 0, behavior: 'smooth' });
    } catch (err) {
      setError(err.message || 'Failed to load scan details.');
    } finally {
      setIsLoading(false);
    }
  };

  // Delete scan from history
  const handleDeleteScan = async (scanId) => {
    try {
      await deleteScan(scanId);
      if (currentScan?.id === scanId) {
        setCurrentScan(null);
      }
      await loadDashboardData();
    } catch (err) {
      setError(err.message || 'Failed to delete scan record.');
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-[#080d1a] text-slate-100">
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
      />

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Error Alert Banner */}
        {error && (
          <div className="mb-6 p-4 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-300 text-sm flex items-center justify-between">
            <div className="flex items-center space-x-2.5">
              <AlertCircle className="w-5 h-5 text-rose-400 flex-shrink-0" />
              <span>{error}</span>
            </div>
            <button
              onClick={() => setError(null)}
              className="text-xs text-rose-400 hover:text-rose-200 underline"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* TAB 1: SCANNER & DETECTOR VIEW */}
        {activeTab === 'scanner' && (
          <div className="space-y-6">
            <ScanInput onAnalyze={handleAnalyze} isLoading={isLoading} />

            {/* Loading Indicator Overlay */}
            {isLoading && (
              <div className="p-12 text-center bg-[#0e162e] border border-slate-800 rounded-2xl shadow-xl">
                <RefreshCw className="w-10 h-10 text-blue-500 animate-spin mx-auto mb-4" />
                <h3 className="text-lg font-bold text-white">
                  Executing Multimodal Inspection Pipeline
                </h3>
                <p className="text-xs sm:text-sm text-slate-400 mt-1 max-w-md mx-auto">
                  Rendering screenshot, extracting DOM forms, analyzing NLP semantic urgency, and evaluating VLM zero-day brand consistency...
                </p>
              </div>
            )}

            {/* Scan Results Display */}
            {!isLoading && currentScan && (
              <div className="space-y-6">
                <RiskGauge
                  classification={currentScan.classification}
                  riskScore={currentScan.risk_score}
                  confidence={currentScan.confidence}
                  isUnreachable={currentScan.is_unreachable}
                />

                <AnalysisBreakdown
                  analysis={currentScan.analysis}
                  subScores={currentScan.sub_scores}
                  screenshotPreview={currentScan.screenshot_preview}
                />

                <ExplainabilityCard
                  explanation={currentScan.explanation}
                  categorizedIndicators={currentScan.categorized_indicators}
                  classification={currentScan.classification}
                />
              </div>
            )}
          </div>
        )}

        {/* TAB 2: ANALYTICS & SCAN HISTORY DASHBOARD */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            <DashboardMetrics stats={stats} />
            <RecentScansTable
              scans={scans}
              onSelectScan={handleSelectScan}
              onDeleteScan={handleDeleteScan}
              isLoading={isLoading}
            />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-[#070b14] py-8 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center space-x-2">
            <Shield className="w-4 h-4 text-blue-400" />
            <span className="font-semibold text-slate-400">
              Vision-Language Model (VLM) for Zero-Day Phishing Detection
            </span>
          </div>
          <p className="text-slate-500">
            Engineered for academic cybersecurity demonstration. Safe sandboxed testing environment.
          </p>
        </div>
      </footer>
    </div>
  );
}

