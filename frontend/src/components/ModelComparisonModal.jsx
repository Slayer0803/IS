import React, { useState, useEffect } from 'react';
import { X, Award, ShieldAlert, GitCompare, Zap, BarChart3, CheckCircle2, RefreshCw } from 'lucide-react';
import { fetchBenchmarkMetrics } from '../services/api';

export default function ModelComparisonModal({ isOpen, onClose }) {
  const [metricsData, setMetricsData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    if (isOpen) {
      setLoading(true);
      fetchBenchmarkMetrics()
        .then((data) => {
          setMetricsData(data);
          setLoading(false);
        })
        .catch((err) => {
          console.error("Failed loading benchmark metrics:", err);
          setError("Failed to load empirical benchmark metrics from server.");
          setLoading(false);
        });
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const modelsList = metricsData?.models ? Object.entries(metricsData.models).map(([name, data]) => ({
    name,
    type: data.type,
    accuracy: (data.metrics.accuracy * 100).toFixed(1) + '%',
    precision: (data.metrics.precision * 100).toFixed(1) + '%',
    recall: (data.metrics.recall * 100).toFixed(1) + '%',
    f1: (data.metrics.f1 * 100).toFixed(1) + '%',
    prAuc: data.metrics.pr_auc.toFixed(2),
    fpr: (data.metrics.fpr * 100).toFixed(1) + '%',
    zeroDayNote: data.zero_day_note,
    highlight: name.includes('Complete Multimodal Fusion') || name.includes('Aegis-VLM')
  })) : [];

  return (
    <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
      <div className="bg-[#0b1329] border border-slate-700/80 rounded-2xl max-w-5xl w-full max-h-[92vh] overflow-y-auto p-6 sm:p-8 shadow-2xl relative">
        {/* Header */}
        <div className="flex items-center justify-between pb-5 border-b border-slate-800">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
              <GitCompare className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
                Empirical Zero-Day Phishing Benchmark Matrix
              </h2>
              <p className="text-xs sm:text-sm text-slate-400">
                Audited Evaluation Across Strictly Unseen Zero-Day Campaigns (Campaign-Aware Partition)
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-xl bg-slate-800/80 text-slate-400 hover:text-white hover:bg-slate-700 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Evaluation Metadata Card */}
        <div className="my-5 p-4 rounded-xl bg-blue-500/10 border border-blue-500/20 text-xs sm:text-sm text-blue-200">
          <div className="flex items-start space-x-2.5">
            <Award className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
            <div className="space-y-1">
              <span className="font-bold text-blue-300 block">
                Zero-Day Partitioning Integrity: No Target Domain Leakage
              </span>
              <p className="text-slate-300">
                Models are evaluated against strictly unseen campaigns on newly registered, previously unencountered domains.
                Metrics are dynamically served from <code className="text-cyan-300">/api/metrics</code> based on the verified benchmark.
              </p>
              {metricsData && (
                <div className="flex flex-wrap gap-4 pt-2 text-xs font-mono text-slate-400 border-t border-blue-500/20 mt-2">
                  <span>Evaluation Samples: <strong className="text-white">{metricsData.sample_count}</strong></span>
                  <span>Unseen Phishing Attacks: <strong className="text-red-400">{metricsData.phishing_count}</strong></span>
                  <span>Unseen Benign Domains: <strong className="text-emerald-400">{metricsData.benign_count}</strong></span>
                  <span>Timestamp: <strong className="text-white">{metricsData.timestamp?.slice(0, 19).replace('T', ' ')} UTC</strong></span>
                </div>
              )}
            </div>
          </div>
        </div>

        {loading ? (
          <div className="py-12 flex flex-col items-center justify-center space-y-3">
            <RefreshCw className="w-8 h-8 text-blue-400 animate-spin" />
            <span className="text-sm text-slate-400">Loading empirical benchmark metrics...</span>
          </div>
        ) : error ? (
          <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
            {error}
          </div>
        ) : (
          <>
            {/* 6-Model/Modality Comparison Table */}
            <div className="overflow-x-auto rounded-xl border border-slate-800 mb-6">
              <table className="w-full text-left text-xs sm:text-sm">
                <thead className="bg-slate-900 text-slate-300 text-[11px] uppercase tracking-wider font-semibold border-b border-slate-800">
                  <tr>
                    <th className="py-3 px-4">Architecture / Modality</th>
                    <th className="py-3 px-3">Accuracy</th>
                    <th className="py-3 px-3">Precision</th>
                    <th className="py-3 px-3 text-cyan-400 font-bold">Zero-Day Recall</th>
                    <th className="py-3 px-3 text-cyan-400 font-bold">Zero-Day F1</th>
                    <th className="py-3 px-3">PR-AUC</th>
                    <th className="py-3 px-3">FPR</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/80">
                  {modelsList.map((m, idx) => (
                    <tr
                      key={idx}
                      className={
                        m.highlight
                          ? 'bg-blue-600/15 border-l-4 border-l-cyan-400 font-medium'
                          : 'hover:bg-slate-800/40 transition'
                      }
                    >
                      <td className="py-3 px-4">
                        <div className="font-semibold text-white flex items-center space-x-1.5">
                          <span>{m.name}</span>
                          {m.highlight && (
                            <span className="px-1.5 py-0.5 rounded text-[10px] bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-bold">
                              Production
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-slate-400">{m.type}</div>
                      </td>
                      <td className="py-3 px-3 font-mono text-slate-300">{m.accuracy}</td>
                      <td className="py-3 px-3 font-mono text-slate-300">{m.precision}</td>
                      <td className="py-3 px-3 font-mono text-cyan-300 font-bold">{m.recall}</td>
                      <td className="py-3 px-3 font-mono text-cyan-300 font-bold">{m.f1}</td>
                      <td className="py-3 px-3 font-mono text-emerald-400">{m.prAuc}</td>
                      <td className="py-3 px-3 font-mono text-slate-400">{m.fpr}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Architectural Zero-Day Analysis Cards */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
              {modelsList.map((m, idx) => (
                <div
                  key={idx}
                  className={`p-3.5 rounded-xl border ${
                    m.highlight
                      ? 'bg-blue-950/40 border-cyan-500/40 text-blue-200'
                      : 'bg-slate-900/60 border-slate-800 text-slate-300'
                  }`}
                >
                  <div className="font-semibold text-white mb-1 flex items-center justify-between">
                    <span>{m.name}</span>
                    <span className="font-mono text-cyan-400 text-xs">F1: {m.f1}</span>
                  </div>
                  <p className="text-[11px] text-slate-400 leading-relaxed">{m.zeroDayNote}</p>
                </div>
              ))}
            </div>
          </>
        )}

        {/* Footer */}
        <div className="mt-6 pt-4 border-t border-slate-800 flex justify-end">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-white font-semibold text-xs sm:text-sm transition"
          >
            Close Matrix
          </button>
        </div>
      </div>
    </div>
  );
}
