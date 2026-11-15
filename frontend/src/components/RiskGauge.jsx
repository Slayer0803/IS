import React from 'react';
import { AlertTriangle, CheckCircle2, ShieldAlert } from 'lucide-react';

export default function RiskGauge({ classification, riskScore, confidence, isUnreachable }) {
  const percentage = Math.round(riskScore * 100);
  const confidencePercent = Math.round(confidence * 100);

  let badgeColor = 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30';
  let barGradient = 'from-emerald-500 to-teal-400';
  let icon = <CheckCircle2 className="w-5 h-5 text-emerald-400" />;
  let label = 'SAFE / LEGITIMATE';

  if (isUnreachable || classification === 'UNREACHABLE') {
    badgeColor = 'bg-amber-500/15 text-amber-400 border-amber-500/30';
    barGradient = 'from-slate-600 via-amber-500 to-orange-500';
    icon = <AlertTriangle className="w-5 h-5 text-amber-400" />;
    label = 'HOST OFFLINE / UNREACHABLE';
  } else if (classification === 'PHISHING') {
    badgeColor = 'bg-rose-500/10 text-rose-400 border-rose-500/30 animate-pulse';
    barGradient = 'from-orange-500 via-rose-500 to-red-600';
    icon = <ShieldAlert className="w-5 h-5 text-rose-400" />;
    label = 'ZERO-DAY PHISHING';
  } else if (classification === 'SUSPICIOUS') {
    badgeColor = 'bg-amber-500/10 text-amber-400 border-amber-500/30';
    barGradient = 'from-amber-400 to-orange-500';
    icon = <AlertTriangle className="w-5 h-5 text-amber-400" />;
    label = 'SUSPICIOUS ANOMALY';
  }

  return (
    <div className="bg-[#0e162e] border border-slate-800 rounded-2xl p-6 shadow-xl relative overflow-hidden">
      {/* Background ambient glow */}
      <div className={`absolute -right-16 -top-16 w-48 h-48 rounded-full blur-3xl opacity-20 pointer-events-none ${
        classification === 'PHISHING' ? 'bg-red-500' : classification === 'SUSPICIOUS' ? 'bg-amber-500' : 'bg-emerald-500'
      }`} />

      <div className="flex flex-col md:flex-row items-center justify-between gap-6">
        {/* Classification Status */}
        <div className="flex items-center space-x-4">
          <div className="p-3 rounded-2xl bg-slate-900 border border-slate-800 shadow-inner">
            {icon}
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
                Predicted Verdict
              </span>
            </div>
            <div className="flex items-center space-x-3 mt-1">
              <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white">
                {classification}
              </h2>
              <span className={`text-xs px-2.5 py-1 rounded-full border font-semibold tracking-wide ${badgeColor}`}>
                {label}
              </span>
            </div>
          </div>
        </div>

        {/* Confidence & Score Metrics */}
        <div className="flex items-center space-x-8">
          <div className="text-right">
            <span className="text-xs text-slate-400 uppercase tracking-wider block font-medium">
              VLM Confidence
            </span>
            <span className="text-2xl font-bold text-slate-200">
              {confidencePercent}%
            </span>
          </div>

          <div className="text-right">
            <span className="text-xs text-slate-400 uppercase tracking-wider block font-medium">
              Risk Score
            </span>
            <span className={`text-3xl font-extrabold ${
              classification === 'PHISHING' ? 'text-rose-400' : classification === 'SUSPICIOUS' ? 'text-amber-400' : 'text-emerald-400'
            }`}>
              {percentage}%
            </span>
          </div>
        </div>
      </div>

      {/* Visual Risk Gauge Progress Bar */}
      <div className="mt-6">
        <div className="flex justify-between text-xs text-slate-400 mb-1.5 font-medium">
          <span>0% Safe</span>
          <span>30% Threshold</span>
          <span>65% Phishing Threshold</span>
          <span>100% Critical Risk</span>
        </div>
        <div className="w-full bg-slate-900 h-3 rounded-full overflow-hidden p-0.5 border border-slate-800">
          <div
            className={`h-full rounded-full transition-all duration-1000 ease-out bg-gradient-to-r ${barGradient}`}
            style={{ width: `${Math.max(4, Math.min(100, percentage))}%` }}
          />
        </div>
      </div>

      {/* Host Unreachable Warning Banner */}
      {isUnreachable && (
        <div className="mt-5 p-3.5 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-200 text-xs flex items-center space-x-2.5">
          <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0" />
          <span>
            <strong>Offline Host Warning:</strong> Unreachable does NOT mean safe. Automated inspection cannot certify an offline host as legitimate. Attackers frequently dismantle zero-day phishing campaigns shortly after credential harvesting. Confidence is intentionally reduced to reflect inspection uncertainty.
          </span>
        </div>
      )}
    </div>
  );
}

