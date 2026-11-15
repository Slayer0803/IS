import React from 'react';
import { ShieldCheck, ShieldAlert, AlertTriangle, Layers, Percent, Flame } from 'lucide-react';

export default function DashboardMetrics({ stats }) {
  const total = stats?.total_scans || 0;
  const phishing = stats?.phishing_count || 0;
  const safe = stats?.safe_count || 0;
  const suspicious = stats?.suspicious_count || 0;
  const avgRisk = Math.round((stats?.average_risk_score || 0) * 100);
  const detectionRate = stats?.detection_rate || 0;

  return (
    <div className="grid grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
      {/* Total Scans */}
      <div className="bg-[#0e162e] border border-slate-800 rounded-2xl p-5 shadow-lg relative overflow-hidden">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Total Scans
          </span>
          <div className="p-2 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
            <Layers className="w-4 h-4" />
          </div>
        </div>
        <div className="text-2xl sm:text-3xl font-extrabold text-white">
          {total}
        </div>
        <span className="text-[11px] text-slate-500 mt-1 block">
          Analyzed web artifacts
        </span>
      </div>

      {/* Phishing Detected */}
      <div className="bg-[#0e162e] border border-slate-800 rounded-2xl p-5 shadow-lg relative overflow-hidden">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Zero-Day Phishing
          </span>
          <div className="p-2 rounded-xl bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <ShieldAlert className="w-4 h-4" />
          </div>
        </div>
        <div className="text-2xl sm:text-3xl font-extrabold text-rose-400">
          {phishing}
        </div>
        <span className="text-[11px] text-rose-400/80 mt-1 block">
          {detectionRate}% threat ratio
        </span>
      </div>

      {/* Safe Sites */}
      <div className="bg-[#0e162e] border border-slate-800 rounded-2xl p-5 shadow-lg relative overflow-hidden">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Legitimate Safe
          </span>
          <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
            <ShieldCheck className="w-4 h-4" />
          </div>
        </div>
        <div className="text-2xl sm:text-3xl font-extrabold text-emerald-400">
          {safe}
        </div>
        <span className="text-[11px] text-emerald-400/80 mt-1 block">
          Verified authentic
        </span>
      </div>

      {/* Suspicious Sites */}
      <div className="bg-[#0e162e] border border-slate-800 rounded-2xl p-5 shadow-lg relative overflow-hidden">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Suspicious
          </span>
          <div className="p-2 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/20">
            <AlertTriangle className="w-4 h-4" />
          </div>
        </div>
        <div className="text-2xl sm:text-3xl font-extrabold text-amber-400">
          {suspicious}
        </div>
        <span className="text-[11px] text-amber-400/80 mt-1 block">
          Borderline / Review
        </span>
      </div>

      {/* Average Risk */}
      <div className="bg-[#0e162e] border border-slate-800 rounded-2xl p-5 shadow-lg relative overflow-hidden col-span-2 lg:col-span-1">
        <div className="flex items-center justify-between mb-2">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
            Avg Risk Index
          </span>
          <div className="p-2 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <Percent className="w-4 h-4" />
          </div>
        </div>
        <div className="text-2xl sm:text-3xl font-extrabold text-indigo-400">
          {avgRisk}%
        </div>
        <span className="text-[11px] text-slate-500 mt-1 block">
          Aggregated scan severity
        </span>
      </div>
    </div>
  );
}

