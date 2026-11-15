import React from 'react';
import { HelpCircle, AlertOctagon, CheckCircle2, ChevronRight, Info } from 'lucide-react';

export default function ExplainabilityCard({ explanation, categorizedIndicators, classification }) {
  const urlInd = categorizedIndicators?.url_indicators || [];
  const visInd = categorizedIndicators?.visual_indicators || [];
  const txtInd = categorizedIndicators?.text_indicators || [];
  const techInd = categorizedIndicators?.technical_indicators || [];

  const totalIndicators = urlInd.length + visInd.length + txtInd.length + techInd.length;

  return (
    <div className="bg-[#0e162e] border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xl mt-6">
      <div className="flex items-center space-x-3 mb-6">
        <div className="p-2.5 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
          <HelpCircle className="w-6 h-6" />
        </div>
        <div>
          <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            Why Was This Flagged?
          </h2>
          <p className="text-xs sm:text-sm text-slate-400">
            Explainable multimodal reasoning and concise detection factors
          </p>
        </div>
      </div>

      {/* Human-Readable Summary Banner */}
      <div className="p-4 sm:p-5 rounded-xl bg-slate-900/90 border border-slate-700/80 mb-6">
        <div className="flex items-start space-x-3">
          <Info className="w-5 h-5 text-indigo-400 mt-0.5 flex-shrink-0" />
          <div>
            <span className="text-xs font-bold text-indigo-400 uppercase tracking-wider block mb-1">
              Executive Assessment
            </span>
            <div className="space-y-1.5">
              {(explanation || []).map((point, idx) => (
                <p key={idx} className="text-sm text-slate-200 font-medium leading-relaxed">
                  {point}
                </p>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Categorized Detection Evidence Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* Visual Indicators */}
        <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-bold text-purple-400 uppercase tracking-wider">
              Visual Signals
            </span>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/20 font-semibold">
              {visInd.length}
            </span>
          </div>
          {visInd.length > 0 ? (
            <ul className="space-y-2">
              {visInd.map((item, i) => (
                <li key={i} className="text-xs text-slate-300 flex items-start space-x-1.5">
                  <ChevronRight className="w-3.5 h-3.5 text-purple-400 mt-0.5 flex-shrink-0" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500 italic">No visual anomalies detected.</p>
          )}
        </div>

        {/* Text/Semantic Indicators */}
        <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-bold text-cyan-400 uppercase tracking-wider">
              Semantic Signals
            </span>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-semibold">
              {txtInd.length}
            </span>
          </div>
          {txtInd.length > 0 ? (
            <ul className="space-y-2">
              {txtInd.map((item, i) => (
                <li key={i} className="text-xs text-slate-300 flex items-start space-x-1.5">
                  <ChevronRight className="w-3.5 h-3.5 text-cyan-400 mt-0.5 flex-shrink-0" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500 italic">No semantic manipulation cues found.</p>
          )}
        </div>

        {/* URL Indicators */}
        <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-bold text-blue-400 uppercase tracking-wider">
              URL Signals
            </span>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-500/10 text-blue-400 border border-blue-500/20 font-semibold">
              {urlInd.length}
            </span>
          </div>
          {urlInd.length > 0 ? (
            <ul className="space-y-2">
              {urlInd.map((item, i) => (
                <li key={i} className="text-xs text-slate-300 flex items-start space-x-1.5">
                  <ChevronRight className="w-3.5 h-3.5 text-blue-400 mt-0.5 flex-shrink-0" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500 italic">No lexical anomalies observed.</p>
          )}
        </div>

        {/* Technical/DOM Indicators */}
        <div className="bg-slate-900/50 border border-slate-800/80 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-bold text-emerald-400 uppercase tracking-wider">
              Technical Signals
            </span>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold">
              {techInd.length}
            </span>
          </div>
          {techInd.length > 0 ? (
            <ul className="space-y-2">
              {techInd.map((item, i) => (
                <li key={i} className="text-xs text-slate-300 flex items-start space-x-1.5">
                  <ChevronRight className="w-3.5 h-3.5 text-emerald-400 mt-0.5 flex-shrink-0" />
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-slate-500 italic">Clean DOM structure.</p>
          )}
        </div>
      </div>
    </div>
  );
}

