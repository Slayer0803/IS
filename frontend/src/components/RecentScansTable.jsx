import React, { useState } from 'react';
import { Trash2, ExternalLink, Search, Clock, ArrowUpRight, ShieldCheck, ShieldAlert, AlertTriangle } from 'lucide-react';

export default function RecentScansTable({ scans = [], onSelectScan, onDeleteScan, isLoading }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterClass, setFilterClass] = useState('ALL');

  const filteredScans = scans.filter((scan) => {
    const matchesSearch = scan.url.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          scan.hostname.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesClass = filterClass === 'ALL' || scan.classification === filterClass;
    return matchesSearch && matchesClass;
  });

  const getBadge = (cls) => {
    if (cls === 'PHISHING') {
      return (
        <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>PHISHING</span>
        </span>
      );
    }
    if (cls === 'SUSPICIOUS') {
      return (
        <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
          <AlertTriangle className="w-3.5 h-3.5" />
          <span>SUSPICIOUS</span>
        </span>
      );
    }
    return (
      <span className="inline-flex items-center space-x-1 px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
        <ShieldCheck className="w-3.5 h-3.5" />
        <span>SAFE</span>
      </span>
    );
  };

  return (
    <div className="bg-[#0e162e] border border-slate-800 rounded-2xl p-6 sm:p-8 shadow-xl">
      <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6">
        <div>
          <h2 className="text-xl sm:text-2xl font-bold text-white tracking-tight">
            Recent Scans History
          </h2>
          <p className="text-xs sm:text-sm text-slate-400">
            Persistent audit log stored in local SQLite database
          </p>
        </div>

        {/* Search & Filters */}
        <div className="flex items-center space-x-2 w-full sm:w-auto">
          <div className="relative flex-1 sm:w-64">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              placeholder="Search domain or URL..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-3 py-1.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
          </div>

          <select
            value={filterClass}
            onChange={(e) => setFilterClass(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Classes</option>
            <option value="PHISHING">Phishing</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="SAFE">Safe</option>
          </select>
        </div>
      </div>

      {/* Scans Table */}
      <div className="overflow-x-auto rounded-xl border border-slate-800">
        <table className="w-full text-left text-xs sm:text-sm">
          <thead className="bg-slate-900/90 text-slate-400 border-b border-slate-800 text-[11px] uppercase tracking-wider font-semibold">
            <tr>
              <th className="py-3 px-4">Target Host / URL</th>
              <th className="py-3 px-4">Verdict</th>
              <th className="py-3 px-4">Risk Score</th>
              <th className="py-3 px-4">Confidence</th>
              <th className="py-3 px-4 hidden md:table-cell">Sub-Scores (V / T / U / H)</th>
              <th className="py-3 px-4">Scanned</th>
              <th className="py-3 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {filteredScans.map((scan) => {
              const riskPct = Math.round(scan.risk_score * 100);
              const confPct = Math.round(scan.confidence * 100);
              const vScore = Math.round(scan.visual_score * 100);
              const tScore = Math.round(scan.text_score * 100);
              const uScore = Math.round(scan.url_score * 100);
              const hScore = Math.round(scan.html_score * 100);

              const timeDisplay = scan.timestamp ? new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Recent';

              return (
                <tr key={scan.id} className="hover:bg-slate-800/30 transition">
                  {/* URL */}
                  <td className="py-3.5 px-4 max-w-xs">
                    <div className="font-semibold text-slate-200 truncate">
                      {scan.hostname || 'Host'}
                    </div>
                    <div className="text-[11px] text-slate-400 truncate opacity-80" title={scan.url}>
                      {scan.url}
                    </div>
                  </td>

                  {/* Verdict */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    {getBadge(scan.classification)}
                  </td>

                  {/* Risk Score */}
                  <td className="py-3.5 px-4 whitespace-nowrap font-bold text-slate-200">
                    <div className="flex items-center space-x-2">
                      <div className="w-16 bg-slate-800 h-2 rounded-full overflow-hidden">
                        <div
                          className={`h-full ${
                            riskPct >= 65 ? 'bg-rose-500' : riskPct >= 30 ? 'bg-amber-400' : 'bg-emerald-500'
                          }`}
                          style={{ width: `${riskPct}%` }}
                        />
                      </div>
                      <span>{riskPct}%</span>
                    </div>
                  </td>

                  {/* Confidence */}
                  <td className="py-3.5 px-4 whitespace-nowrap text-slate-300">
                    {confPct}%
                  </td>

                  {/* Modality breakdown */}
                  <td className="py-3.5 px-4 whitespace-nowrap text-[11px] text-slate-400 hidden md:table-cell">
                    <span className="text-purple-400">{vScore}%</span> /{' '}
                    <span className="text-cyan-400">{tScore}%</span> /{' '}
                    <span className="text-blue-400">{uScore}%</span> /{' '}
                    <span className="text-emerald-400">{hScore}%</span>
                  </td>

                  {/* Timestamp */}
                  <td className="py-3.5 px-4 whitespace-nowrap text-xs text-slate-400 flex items-center space-x-1 mt-2 sm:mt-0">
                    <Clock className="w-3.5 h-3.5 opacity-60" />
                    <span>{timeDisplay}</span>
                  </td>

                  {/* Actions */}
                  <td className="py-3.5 px-4 whitespace-nowrap text-right">
                    <div className="flex items-center justify-end space-x-1.5">
                      <button
                        onClick={() => onSelectScan(scan.id)}
                        title="Load Full Analysis"
                        className="p-1.5 rounded-lg bg-blue-500/10 text-blue-400 hover:bg-blue-500/20 transition"
                      >
                        <ArrowUpRight className="w-4 h-4" />
                      </button>
                      <button
                        onClick={() => onDeleteScan(scan.id)}
                        title="Delete Scan"
                        className="p-1.5 rounded-lg bg-rose-500/10 text-rose-400 hover:bg-rose-500/20 transition"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              );
            })}

            {filteredScans.length === 0 && (
              <tr>
                <td colSpan="7" className="text-center py-8 text-slate-500 text-xs sm:text-sm">
                  No scan records found matching query.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

