import React, { useState } from 'react';
import { Search, Globe, Shield, RefreshCw, Sparkles, ExternalLink, ShieldCheck } from 'lucide-react';

export default function ScanInput({ onAnalyze, isLoading }) {
  const [url, setUrl] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (url.trim()) {
      onAnalyze(url.trim());
    }
  };

  const handleSelectExample = (exampleUrl) => {
    setUrl(exampleUrl);
    onAnalyze(exampleUrl);
  };

  return (
    <div className="bg-[#0e162e] border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-2xl relative">
      <div className="max-w-3xl mx-auto text-center mb-6">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-blue-500/10 border border-blue-500/20 text-blue-400 text-xs font-semibold mb-3">
          <Sparkles className="w-3.5 h-3.5" />
          <span>Live External Webpage Inspection</span>
        </div>
        <h1 className="text-2xl sm:text-4xl font-extrabold text-white tracking-tight">
          Scan Any Live Website on the Internet
        </h1>
        <p className="mt-2 text-sm sm:text-base text-slate-400">
          Enter any external website URL or suspected phishing link. The VLM engine fetches the live webpage, renders its visual interface, parses DOM forms, and analyzes semantic intent in real time.
        </p>
      </div>

      {/* Main Input Form */}
      <form onSubmit={handleSubmit} className="max-w-3xl mx-auto">
        <div className="relative flex items-center shadow-lg">
          <div className="absolute left-4 text-slate-400 pointer-events-none">
            <Globe className="w-5 h-5" />
          </div>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Paste any live website URL (e.g., https://login.target-brand.com...)"
            disabled={isLoading}
            className="w-full bg-slate-900 border border-slate-700/80 rounded-xl py-3.5 pl-12 pr-32 text-sm sm:text-base text-white placeholder-slate-500 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-500/20 transition disabled:opacity-50"
          />
          <button
            type="submit"
            disabled={isLoading || !url.trim()}
            className="absolute right-2 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white font-semibold text-xs sm:text-sm px-5 py-2.5 rounded-lg shadow-md hover:shadow-blue-500/25 transition disabled:opacity-50 disabled:pointer-events-none flex items-center space-x-2"
          >
            {isLoading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Scanning...</span>
              </>
            ) : (
              <>
                <Search className="w-4 h-4" />
                <span>Analyze</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* Example public websites for quick baseline testing */}
      <div className="max-w-3xl mx-auto mt-6 pt-5 border-t border-slate-800/80">
        <div className="flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400 mb-2">
          <span className="font-semibold text-slate-400 flex items-center space-x-1.5">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <span>Try testing known legitimate websites for baseline comparison:</span>
          </span>
          <span className="text-[11px] text-slate-500">
            Paste any external link above
          </span>
        </div>

        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={() => handleSelectExample('https://en.wikipedia.org/wiki/Phishing')}
            disabled={isLoading}
            className="px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 hover:border-slate-700 text-slate-300 text-xs transition flex items-center space-x-1.5 hover:text-white"
          >
            <ExternalLink className="w-3 h-3 text-slate-400" />
            <span>Wikipedia (Phishing Article)</span>
          </button>

          <button
            type="button"
            onClick={() => handleSelectExample('https://github.com')}
            disabled={isLoading}
            className="px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 hover:border-slate-700 text-slate-300 text-xs transition flex items-center space-x-1.5 hover:text-white"
          >
            <ExternalLink className="w-3 h-3 text-slate-400" />
            <span>GitHub.com</span>
          </button>

          <button
            type="button"
            onClick={() => handleSelectExample('https://news.ycombinator.com')}
            disabled={isLoading}
            className="px-3 py-1.5 rounded-lg bg-slate-900/80 border border-slate-800 hover:border-slate-700 text-slate-300 text-xs transition flex items-center space-x-1.5 hover:text-white"
          >
            <ExternalLink className="w-3 h-3 text-slate-400" />
            <span>Hacker News</span>
          </button>
        </div>
      </div>
    </div>
  );
}
