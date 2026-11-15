import React, { useState } from 'react';
import { Eye, FileText, Link2, Code2, AlertCircle, CheckCircle, ShieldCheck, Maximize2 } from 'lucide-react';

export default function AnalysisBreakdown({ analysis, subScores, screenshotPreview }) {
  const [showModal, setShowModal] = useState(false);

  const urlRisk = Math.round((subScores?.url_score || 0) * 100);
  const visualRisk = Math.round((subScores?.visual_score || 0) * 100);
  const textRisk = Math.round((subScores?.text_score || 0) * 100);
  const htmlRisk = Math.round((subScores?.html_score || 0) * 100);

  const urlData = analysis?.url || {};
  const visualData = analysis?.visual || {};
  const textData = analysis?.text || {};
  const htmlData = analysis?.html || {};

  const getScoreColor = (score) => {
    if (score >= 65) return 'text-rose-400 border-rose-500/30 bg-rose-500/10';
    if (score >= 30) return 'text-amber-400 border-amber-500/30 bg-amber-500/10';
    return 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
  };

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
      {/* 1. VISUAL / VLM ANALYSIS CARD */}
      <div className="bg-[#0e162e] border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-xl bg-purple-500/10 text-purple-400 border border-purple-500/20">
                <Eye className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-bold text-white text-base">Visual (VLM) Analysis</h3>
                <span className="text-xs text-slate-400">Layout, Branding & Appearance</span>
              </div>
            </div>
            <span className={`text-xs px-2.5 py-1 rounded-full border font-bold ${getScoreColor(visualRisk)}`}>
              {visualRisk}% Risk
            </span>
          </div>

          {/* Screenshot Preview */}
          {screenshotPreview && (
            <div className="relative group mb-4 rounded-xl overflow-hidden border border-slate-800 bg-slate-900 cursor-pointer"
                 onClick={() => setShowModal(true)}>
              <img
                src={screenshotPreview}
                alt="Webpage Render Preview"
                className="w-full h-40 object-cover object-top transition duration-300 group-hover:scale-105"
              />
              <div className="absolute inset-0 bg-slate-950/40 opacity-0 group-hover:opacity-100 transition flex items-center justify-center">
                <span className="text-xs bg-slate-900/90 text-white px-3 py-1.5 rounded-lg border border-slate-700 flex items-center space-x-1">
                  <Maximize2 className="w-3.5 h-3.5" />
                  <span>Enlarge Screenshot</span>
                </span>
              </div>
            </div>
          )}

          {/* Key Visual Findings Badges */}
          <div className="flex flex-wrap gap-2 mb-3">
            {visualData.brand_impersonation && (
              <span className="text-[11px] font-semibold px-2.5 py-1 rounded-md bg-rose-500/15 text-rose-400 border border-rose-500/30">
                ⚠️ Impersonating {visualData.impersonated_brand || 'Target Brand'}
              </span>
            )}
            {visualData.credential_harvesting && (
              <span className="text-[11px] font-semibold px-2.5 py-1 rounded-md bg-rose-500/15 text-rose-400 border border-rose-500/30">
                Password Collection Form
              </span>
            )}
            {visualData.suspicious_login_form && (
              <span className="text-[11px] font-semibold px-2.5 py-1 rounded-md bg-amber-500/15 text-amber-400 border border-amber-500/30">
                Authentication Modal
              </span>
            )}
          </div>

          {/* Visual Indicators */}
          <ul className="space-y-1.5">
            {(visualData.visual_indicators || []).map((ind, idx) => (
              <li key={idx} className="text-xs text-slate-300 flex items-start space-x-2">
                <span className="text-purple-400 mt-0.5">•</span>
                <span>{ind}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* 2. TEXT & SEMANTIC ANALYSIS CARD */}
      <div className="bg-[#0e162e] border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-xl bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                <FileText className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-bold text-white text-base">Semantic NLP Analysis</h3>
                <span className="text-xs text-slate-400">Psychological Triggers & Intent</span>
              </div>
            </div>
            <span className={`text-xs px-2.5 py-1 rounded-full border font-bold ${getScoreColor(textRisk)}`}>
              {textRisk}% Risk
            </span>
          </div>

          {/* Semantic Threat Badges */}
          <div className="grid grid-cols-2 gap-2 mb-4">
            <div className={`p-2.5 rounded-xl border text-xs ${
              textData.urgency ? 'bg-rose-500/10 border-rose-500/30 text-rose-300' : 'bg-slate-900/60 border-slate-800 text-slate-400'
            }`}>
              <div className="font-semibold">Urgency Pressure</div>
              <div className="text-[11px] opacity-80">{textData.urgency ? 'Detected (High Pressure)' : 'None detected'}</div>
            </div>

            <div className={`p-2.5 rounded-xl border text-xs ${
              textData.threatening_language ? 'bg-rose-500/10 border-rose-500/30 text-rose-300' : 'bg-slate-900/60 border-slate-800 text-slate-400'
            }`}>
              <div className="font-semibold">Account Threat</div>
              <div className="text-[11px] opacity-80">{textData.threatening_language ? 'Suspension threat' : 'None detected'}</div>
            </div>

            <div className={`p-2.5 rounded-xl border text-xs ${
              textData.credential_request ? 'bg-rose-500/10 border-rose-500/30 text-rose-300' : 'bg-slate-900/60 border-slate-800 text-slate-400'
            }`}>
              <div className="font-semibold">Credential Ask</div>
              <div className="text-[11px] opacity-80">{textData.credential_request ? 'Password requested' : 'None detected'}</div>
            </div>

            <div className={`p-2.5 rounded-xl border text-xs ${
              textData.social_engineering ? 'bg-amber-500/10 border-amber-500/30 text-amber-300' : 'bg-slate-900/60 border-slate-800 text-slate-400'
            }`}>
              <div className="font-semibold">Social Engineering</div>
              <div className="text-[11px] opacity-80">{textData.social_engineering ? 'Detected' : 'Standard tone'}</div>
            </div>
          </div>

          {/* Indicators list */}
          <ul className="space-y-1.5">
            {(textData.indicators || []).map((ind, idx) => (
              <li key={idx} className="text-xs text-slate-300 flex items-start space-x-2">
                <span className="text-cyan-400 mt-0.5">•</span>
                <span>{ind}</span>
              </li>
            ))}
            {(!textData.indicators || textData.indicators.length === 0) && (
              <li className="text-xs text-slate-500 italic">No psychological or threatening semantic cues found.</li>
            )}
          </ul>
        </div>
      </div>

      {/* 3. URL LEXICAL & DOMAIN ANALYSIS CARD */}
      <div className="bg-[#0e162e] border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
                <Link2 className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-bold text-white text-base">URL & Domain Heuristics</h3>
                <span className="text-xs text-slate-400">Lexical Structure & Entropy</span>
              </div>
            </div>
            <span className={`text-xs px-2.5 py-1 rounded-full border font-bold ${getScoreColor(urlRisk)}`}>
              {urlRisk}% Risk
            </span>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mb-4 text-xs">
            <div className="bg-slate-900/80 p-2 rounded-lg border border-slate-800">
              <span className="text-slate-400 block text-[10px]">Apex Domain</span>
              <span className="font-semibold text-slate-200 truncate block">{urlData.features?.apex_domain || 'N/A'}</span>
            </div>
            <div className="bg-slate-900/80 p-2 rounded-lg border border-slate-800">
              <span className="text-slate-400 block text-[10px]">TLD</span>
              <span className="font-semibold text-slate-200">.{urlData.features?.tld || 'com'}</span>
            </div>
            <div className="bg-slate-900/80 p-2 rounded-lg border border-slate-800">
              <span className="text-slate-400 block text-[10px]">Entropy</span>
              <span className="font-semibold text-slate-200">{urlData.features?.domain_entropy || '0.00'}</span>
            </div>
            <div className="bg-slate-900/80 p-2 rounded-lg border border-slate-800">
              <span className="text-slate-400 block text-[10px]">Subdomains</span>
              <span className="font-semibold text-slate-200">{urlData.features?.num_subdomains || 0}</span>
            </div>
            <div className="bg-slate-900/80 p-2 rounded-lg border border-slate-800">
              <span className="text-slate-400 block text-[10px]">HTTPS</span>
              <span className={`font-semibold ${urlData.features?.uses_https ? 'text-emerald-400' : 'text-rose-400'}`}>
                {urlData.features?.uses_https ? 'Active' : 'Missing'}
              </span>
            </div>
            <div className="bg-slate-900/80 p-2 rounded-lg border border-slate-800">
              <span className="text-slate-400 block text-[10px]">Raw IP Host</span>
              <span className="font-semibold text-slate-200">{urlData.features?.has_ip_address ? 'Yes (High Risk)' : 'No'}</span>
            </div>
          </div>

          <ul className="space-y-1.5">
            {(urlData.indicators || []).map((ind, idx) => (
              <li key={idx} className="text-xs text-slate-300 flex items-start space-x-2">
                <span className="text-blue-400 mt-0.5">•</span>
                <span>{ind}</span>
              </li>
            ))}
            {(!urlData.indicators || urlData.indicators.length === 0) && (
              <li className="text-xs text-slate-500 italic">URL conforms to normal legitimate structure.</li>
            )}
          </ul>
        </div>
      </div>

      {/* 4. HTML & TECHNICAL DOM ANALYSIS CARD */}
      <div className="bg-[#0e162e] border border-slate-800 rounded-2xl p-6 shadow-xl flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <Code2 className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-bold text-white text-base">HTML & Technical DOM</h3>
                <span className="text-xs text-slate-400">Forms, Targets & Evasion Checks</span>
              </div>
            </div>
            <span className={`text-xs px-2.5 py-1 rounded-full border font-bold ${getScoreColor(htmlRisk)}`}>
              {htmlRisk}% Risk
            </span>
          </div>

          <div className="grid grid-cols-2 gap-2 mb-4 text-xs">
            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
              <span className="text-slate-400 block text-[10px]">Password Inputs</span>
              <span className={`font-bold ${htmlData.has_password_field ? 'text-rose-400' : 'text-slate-300'}`}>
                {htmlData.has_password_field ? 'Detected' : 'None'}
              </span>
            </div>
            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
              <span className="text-slate-400 block text-[10px]">Cross-Domain Form Actions</span>
              <span className={`font-bold ${(htmlData.cross_domain_forms?.length || 0) > 0 ? 'text-rose-400' : 'text-slate-300'}`}>
                {(htmlData.cross_domain_forms?.length || 0) > 0 ? `${htmlData.cross_domain_forms.length} External Posts` : 'None'}
              </span>
            </div>
            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
              <span className="text-slate-400 block text-[10px]">Total Forms</span>
              <span className="font-semibold text-slate-200">{htmlData.num_forms || 0}</span>
            </div>
            <div className="bg-slate-900/80 p-2.5 rounded-lg border border-slate-800">
              <span className="text-slate-400 block text-[10px]">Dummy Links Ratio</span>
              <span className="font-semibold text-slate-200">{Math.round((htmlData.empty_link_ratio || 0) * 100)}%</span>
            </div>
          </div>

          <ul className="space-y-1.5">
            {(htmlData.indicators || []).map((ind, idx) => (
              <li key={idx} className="text-xs text-slate-300 flex items-start space-x-2">
                <span className="text-emerald-400 mt-0.5">•</span>
                <span>{ind}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* Enlarged Screenshot Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4" onClick={() => setShowModal(false)}>
          <div className="bg-slate-900 border border-slate-700 rounded-2xl max-w-4xl max-h-[90vh] overflow-hidden p-4 shadow-2xl relative" onClick={(e) => e.stopPropagation()}>
            <div className="flex justify-between items-center mb-3">
              <h3 className="text-sm font-bold text-white">Full Captured Webpage Screenshot</h3>
              <button onClick={() => setShowModal(false)} className="text-slate-400 hover:text-white text-xs px-2 py-1 rounded bg-slate-800">
                Close (ESC)
              </button>
            </div>
            <img src={screenshotPreview} alt="Screenshot" className="w-full max-h-[75vh] object-contain rounded-lg border border-slate-800" />
          </div>
        </div>
      )}
    </div>
  );
}

