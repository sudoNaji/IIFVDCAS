import React, { useState, useEffect, useCallback, useRef } from 'react';
import { cveApi, sbomApi } from '../utils/api';
import { useWebSocket } from '../hooks/useWebSocket';
import {
  ShieldAlert, Bug, Zap, AlertTriangle, RefreshCw,
  ChevronDown, ChevronUp, ExternalLink, Search, Filter
} from 'lucide-react';

// ─── Helpers ──────────────────────────────────────────────────────────────────
function severityColor(sev) {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'bg-red-950 text-red-400 border border-red-800';
    case 'HIGH':     return 'bg-orange-950 text-orange-400 border border-orange-800';
    case 'MEDIUM':   return 'bg-amber-950 text-amber-400 border border-amber-800';
    case 'LOW':      return 'bg-blue-950 text-blue-400 border border-blue-800';
    default:         return 'bg-gray-800 text-gray-400 border border-gray-700';
  }
}

function severityRowBg(sev, isKev) {
  if (isKev) return 'bg-red-950/20';
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'bg-red-950/10';
    case 'HIGH':     return 'bg-orange-950/10';
    case 'MEDIUM':   return 'bg-amber-950/10';
    case 'LOW':      return 'bg-blue-950/10';
    default:         return '';
  }
}

// ─── Progress bar ─────────────────────────────────────────────────────────────
function ProgressBar({ progress, step }) {
  return (
    <div className="card mb-4">
      <div className="flex justify-between text-xs mb-2">
        <span className="text-gray-400">{step || 'Running CVE mapping…'}</span>
        <span className="text-indigo-400 font-medium">{Math.round(progress)}%</span>
      </div>
      <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
        <div
          className="h-full bg-indigo-600 rounded-full transition-all duration-500"
          style={{ width: `${progress}%` }}
        />
      </div>
    </div>
  );
}

// ─── Stat card ────────────────────────────────────────────────────────────────
function StatCard({ icon: Icon, label, value, color = 'text-white' }) {
  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-1">
        <Icon size={13} className="text-gray-500" />
        <span className="text-xs text-gray-500">{label}</span>
      </div>
      <div className={`text-2xl font-bold ${color}`}>{value ?? 0}</div>
    </div>
  );
}

// ─── Detail panel ─────────────────────────────────────────────────────────────
import { useAI } from '../hooks/useAI';

function FindingDetail({ finding, onClose }) {
  if (!finding) return null;
  const { callAI, isConfigured } = useAI();
  const [explanation, setExplanation] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  // Reset explanation when target CVE changes
  useEffect(() => {
    setExplanation('');
    setError('');
  }, [finding.cve_id]);

  const handleExplain = async () => {
    setLoading(true);
    setError('');
    try {
      const resp = await callAI('explain-cve', {
        cve_id: finding.cve_id,
        description: finding.description,
        firmware_context: {
          cvss_score: finding.cvss_score,
          cvss_severity: finding.cvss_severity,
          component: finding.component,
          version: finding.version,
        }
      });
      setExplanation(resp.explanation);
    } catch (err) {
      setError(err.message || 'Failed to generate explanation');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card border border-gray-700 mt-2 mb-4">
      <div className="flex items-start justify-between mb-3">
        <div>
          <h3 className="text-base font-bold text-white font-mono">{finding.cve_id}</h3>
          <p className="text-xs text-gray-400 mt-0.5">{finding.component} @ {finding.version}</p>
        </div>
        <button onClick={onClose} className="text-gray-600 hover:text-gray-400 text-lg leading-none">×</button>
      </div>
      <p className="text-sm text-gray-300 mb-3">{finding.description || 'No description available.'}</p>
      <div className="grid grid-cols-3 gap-3 text-xs mb-3">
        <div>
          <span className="text-gray-500 block mb-1">CVSS Score</span>
          <span className={`px-2 py-0.5 rounded-full text-[11px] font-semibold ${severityColor(finding.cvss_severity)}`}>
            {finding.cvss_score?.toFixed(1) ?? 'N/A'} {finding.cvss_severity}
          </span>
        </div>
        <div>
          <span className="text-gray-500 block mb-1">EPSS</span>
          <span className="text-white font-medium">
            {finding.epss_score ? `${(finding.epss_score * 100).toFixed(1)}%` : 'N/A'}
          </span>
        </div>
        <div>
          <span className="text-gray-500 block mb-1">Published</span>
          <span className="text-gray-300">{finding.published?.substring(0, 10) || '—'}</span>
        </div>
      </div>
      {finding.cvss_vector && (
        <div className="mb-3">
          <span className="text-gray-500 text-xs block mb-1">CVSS Vector</span>
          <code className="text-[11px] text-indigo-300 bg-gray-950 px-2 py-1 rounded font-mono break-all">
            {finding.cvss_vector}
          </code>
        </div>
      )}
      {finding.cwe_ids?.length > 0 && (
        <div className="mb-3">
          <span className="text-gray-500 text-xs block mb-1">CWE IDs</span>
          <div className="flex gap-1 flex-wrap">
            {finding.cwe_ids.map(cwe => (
              <span key={cwe} className="text-[11px] px-2 py-0.5 rounded bg-gray-800 text-gray-300 font-mono">
                {cwe}
              </span>
            ))}
          </div>
        </div>
      )}
      
      {/* AI Explanation Area */}
      {explanation && (
        <div className="mt-4 p-3 bg-indigo-950/20 border border-indigo-850 rounded-lg space-y-2">
          <div className="flex items-center gap-1.5 text-indigo-400 text-xs font-semibold">
            <Zap size={12} className="fill-indigo-400" />
            <span>AI Impact Analysis</span>
          </div>
          <div className="text-xs text-gray-300 leading-relaxed whitespace-pre-wrap">{explanation}</div>
        </div>
      )}

      {error && (
        <div className="mt-3 p-3 bg-red-950/20 border border-red-900/30 rounded-lg text-red-400 text-xs flex items-center gap-2">
          <AlertTriangle size={14} className="flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="flex justify-between items-center gap-2 mt-3 pt-3 border-t border-gray-800">
        <div className="flex gap-2">
          <a
            href={`https://nvd.nist.gov/vuln/detail/${finding.cve_id}`}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-secondary text-xs flex items-center gap-1"
          >
            <ExternalLink size={11} /> NVD
          </a>
          <a
            href={`https://www.cvedetails.com/cve/${finding.cve_id}/`}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-secondary text-xs flex items-center gap-1"
          >
            <ExternalLink size={11} /> CVE Details
          </a>
        </div>

        <button
          onClick={handleExplain}
          disabled={loading}
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all border ${
            loading
              ? 'bg-indigo-950 text-indigo-400 border-indigo-900 cursor-not-allowed'
              : 'bg-indigo-600 text-white border-indigo-500 hover:bg-indigo-500 shadow-md shadow-indigo-600/10'
          }`}
        >
          <Zap size={11} className={loading ? 'animate-spin' : ''} />
          {loading ? 'Analyzing Impact...' : 'Explain with AI'}
        </button>
      </div>
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────
export default function CvePage() {
  const [sbomJobs,    setSbomJobs]    = useState([]);
  const [selectedSbomJobId, setSelectedSbomJobId] = useState('');

  const [running,      setRunning]      = useState(false);
  const [progress,     setProgress]     = useState(0);
  const [progressStep, setProgressStep] = useState('');
  const [cveJobId,     setCveJobId]     = useState(null);
  const [error,        setError]        = useState('');

  const [summary,   setSummary]   = useState(null);
  const [findings,  setFindings]  = useState([]);
  const [totalCves, setTotalCves] = useState(0);

  const [search,    setSearch]    = useState('');
  const [severity,  setSeverity]  = useState('');
  const [kevOnly,   setKevOnly]   = useState(false);
  const [offset,    setOffset]    = useState(0);
  const LIMIT = 100;

  const [selected, setSelected] = useState(null);  // clicked finding for detail panel

  const [pastJobs, setPastJobs] = useState([]);

  const pollRef = useRef(null);
  const { subscribe } = useWebSocket('ws://localhost:8000/ws');

  // Load SBOM jobs for dropdown + past CVE jobs
  useEffect(() => {
    sbomApi.getJob && Promise.resolve();  // keep import alive
    fetch('/api/v1/sbom/jobs/list')
      .then(r => r.json())
      .then(d => setSbomJobs(d.jobs || []))
      .catch(() => {});
    cveApi.listJobs()
      .then(r => setPastJobs(r.data.jobs || []))
      .catch(() => {});
  }, []);

  // ── WebSocket live progress ──────────────────────────────────────────────
  useEffect(() => {
    return subscribe(ev => {
      if (ev.phase !== 'phase5') return;
      if (ev.event === 'progress') {
        setProgress(ev.percent ?? 0);
        setProgressStep(ev.step ?? '');
      }
      if (ev.event === 'cve_mapping_complete' || ev.event === 'cve_mapping_result') {
        setRunning(false);
        setProgress(100);
        setProgressStep('CVE mapping complete!');
        if (ev.job_id) loadResults(ev.job_id);
      }
    });
  }, [subscribe]);

  // ── Polling fallback ─────────────────────────────────────────────────────
  useEffect(() => {
    if (!running || !cveJobId) return;
    pollRef.current = setInterval(async () => {
      try {
        const r = await cveApi.getSummary(cveJobId);
        const { status, total_cves } = r.data;
        if (status === 'completed' || status === 'failed') {
          clearInterval(pollRef.current);
          setRunning(false);
          setProgress(100);
          if (status === 'failed') {
            setError('CVE mapping failed');
          } else {
            await loadResults(cveJobId);
          }
        } else if (total_cves > 0) {
          // Animate progress while running
          setProgress(p => Math.min(p + 2, 95));
        }
      } catch (_) {}
    }, 2000);
    return () => clearInterval(pollRef.current);
  }, [running, cveJobId]);

  const loadResults = useCallback(async (jobId) => {
    try {
      const [sumR, findR] = await Promise.all([
        cveApi.getSummary(jobId),
        cveApi.getFindings(jobId, { limit: LIMIT, offset: 0 }),
      ]);
      setSummary(sumR.data);
      setFindings(findR.data.findings || []);
      setTotalCves(findR.data.total || 0);
      // Refresh past jobs list
      cveApi.listJobs().then(r => setPastJobs(r.data.jobs || [])).catch(() => {});
    } catch (e) {
      setError('Failed to load CVE results: ' + e.message);
    }
  }, []);

  const applyFilters = useCallback(async (jobId) => {
    try {
      const r = await cveApi.getFindings(jobId, {
        limit: LIMIT,
        offset,
        severity: severity || undefined,
        kev_only: kevOnly || undefined,
      });
      let filtered = r.data.findings || [];
      if (search) {
        const q = search.toLowerCase();
        filtered = filtered.filter(f =>
          f.cve_id?.toLowerCase().includes(q) ||
          f.component?.toLowerCase().includes(q) ||
          f.description?.toLowerCase().includes(q)
        );
      }
      setFindings(filtered);
      setTotalCves(r.data.total || 0);
    } catch (e) {
      console.error('Filter failed', e);
    }
  }, [offset, severity, kevOnly, search]);

  useEffect(() => {
    if (cveJobId && summary) applyFilters(cveJobId);
  }, [severity, kevOnly, offset, cveJobId]);

  const handleStart = useCallback(async () => {
    if (!selectedSbomJobId) {
      setError('Select a SBOM job first');
      return;
    }
    setRunning(true);
    setError('');
    setSummary(null);
    setFindings([]);
    setProgress(2);
    setProgressStep('Submitting CVE mapping job…');
    try {
      const r = await cveApi.startScan({ sbom_job_id: selectedSbomJobId });
      setCveJobId(r.data.job_id);
    } catch (err) {
      setRunning(false);
      setProgress(0);
      setError(err.response?.data?.detail || err.message);
    }
  }, [selectedSbomJobId]);

  const handleLoadPast = useCallback(async (jobId) => {
    setCveJobId(jobId);
    setSummary(null);
    setFindings([]);
    setError('');
    await loadResults(jobId);
  }, [loadResults]);

  const handleReset = () => {
    clearInterval(pollRef.current);
    setRunning(false); setProgress(0); setProgressStep('');
    setError(''); setCveJobId(null);
    setSummary(null); setFindings([]); setTotalCves(0);
    setSelected(null); setSearch(''); setSeverity(''); setKevOnly(false);
  };

  return (
    <div className="p-6">
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="badge badge-blue text-[10px]">Phase 5</span>
            <span className="text-gray-600 text-xs font-mono">NVD · EPSS · CISA KEV · CVSS v3</span>
          </div>
          <h1 className="text-2xl font-bold text-white">CVE Mapping</h1>
          <p className="text-gray-400 text-sm mt-1">
            Component vulnerabilities from NVD, scored with EPSS and CISA KEV
          </p>
        </div>
        {(summary || error) && (
          <button onClick={handleReset} className="btn-secondary text-sm">
            <RefreshCw size={14} /> Reset
          </button>
        )}
      </div>

      {/* Input form */}
      {!running && !summary && (
        <div className="card mb-6">
          <div className="grid grid-cols-2 gap-4 mb-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1.5 font-medium">SBOM Job</label>
              <select
                value={selectedSbomJobId}
                onChange={e => setSelectedSbomJobId(e.target.value)}
                className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-sm text-gray-300 font-mono"
              >
                <option value="">— Select SBOM job —</option>
                {sbomJobs.map(j => (
                  <option key={j.job_id} value={j.job_id}>
                    {j.job_id.substring(0, 16)}… — {j.component_count ?? 0} components
                  </option>
                ))}
              </select>
            </div>
            {pastJobs.length > 0 && (
              <div>
                <label className="block text-xs text-gray-400 mb-1.5 font-medium">
                  Or load past scan
                </label>
                <select
                  onChange={e => e.target.value && handleLoadPast(e.target.value)}
                  className="w-full bg-gray-950 border border-gray-800 rounded px-3 py-2 text-sm text-gray-300 font-mono"
                >
                  <option value="">— Past CVE scans —</option>
                  {pastJobs.map(j => (
                    <option key={j.job_id} value={j.job_id}>
                      {j.job_id.substring(0, 12)} — {j.total_cves ?? 0} CVEs / {j.status}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>
          {error && (
            <div className="bg-red-950 border border-red-800 rounded-lg p-3 mb-4 flex gap-2">
              <AlertTriangle size={14} className="text-red-400 flex-shrink-0 mt-0.5" />
              <span className="text-xs text-red-300">{error}</span>
            </div>
          )}
          <button onClick={handleStart} className="btn-primary">
            <Zap size={14} /> Start CVE Mapping
          </button>
        </div>
      )}

      {/* Progress */}
      {running && <ProgressBar progress={progress} step={progressStep} />}

      {/* Results */}
      {summary && (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-5 gap-3 mb-6">
            <StatCard icon={Bug}         label="Total CVEs"  value={summary.total_cves}    color="text-white" />
            <StatCard icon={ShieldAlert} label="Critical"    value={summary.critical_count} color="text-red-400" />
            <StatCard icon={AlertTriangle} label="High"      value={summary.high_count}     color="text-orange-400" />
            <StatCard icon={AlertTriangle} label="KEV"       value={summary.kev_count}      color="text-red-400" />
            <StatCard icon={Zap}         label="Medium"      value={summary.medium_count}   color="text-amber-400" />
          </div>

          {/* Filter bar */}
          <div className="card mb-4 flex flex-wrap gap-3 items-center">
            <div className="flex items-center gap-1.5 flex-1 min-w-48">
              <Search size={13} className="text-gray-600" />
              <input
                type="text"
                placeholder="Search CVE ID, component, description…"
                value={search}
                onChange={e => { setSearch(e.target.value); if (cveJobId && summary) applyFilters(cveJobId); }}
                className="flex-1 bg-gray-950 border border-gray-800 rounded px-2 py-1 text-xs text-gray-300 placeholder-gray-700"
              />
            </div>
            <select
              value={severity}
              onChange={e => setSeverity(e.target.value)}
              className="bg-gray-950 border border-gray-800 rounded px-2 py-1 text-xs text-gray-300"
            >
              <option value="">All severities</option>
              <option value="CRITICAL">Critical</option>
              <option value="HIGH">High</option>
              <option value="MEDIUM">Medium</option>
              <option value="LOW">Low</option>
            </select>
            <label className="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer">
              <input
                type="checkbox"
                checked={kevOnly}
                onChange={e => setKevOnly(e.target.checked)}
                className="rounded border-gray-700 bg-gray-950 text-indigo-600"
              />
              KEV only
            </label>
          </div>

          {/* Detail panel */}
          {selected && (
            <FindingDetail finding={selected} onClose={() => setSelected(null)} />
          )}

          {/* CVE Table */}
          <div className="card overflow-x-auto p-0">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-gray-500 border-b border-gray-800">
                  {['CVE ID', 'Component', 'Version', 'CVSS', 'EPSS', 'KEV', 'Description'].map(h => (
                    <th key={h} className="text-left py-2 px-3 font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {findings.map((f, i) => (
                  <tr
                    key={f.cve_id + i}
                    onClick={() => setSelected(selected?.cve_id === f.cve_id ? null : f)}
                    className={`border-b border-gray-900 cursor-pointer hover:bg-gray-800/50 transition-colors ${severityRowBg(f.cvss_severity, f.is_kev)}`}
                  >
                    <td className="py-2 px-3 font-mono text-indigo-400 whitespace-nowrap">
                      {f.cve_id}
                    </td>
                    <td className="py-2 px-3 text-gray-200 max-w-28 truncate" title={f.component}>
                      {f.component}
                    </td>
                    <td className="py-2 px-3 text-gray-400 font-mono">{f.version || '—'}</td>
                    <td className="py-2 px-3 whitespace-nowrap">
                      <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${severityColor(f.cvss_severity)}`}>
                        {f.cvss_score?.toFixed(1) ?? 'N/A'}
                      </span>
                    </td>
                    <td className="py-2 px-3 text-gray-400 whitespace-nowrap">
                      {f.epss_score ? `${(f.epss_score * 100).toFixed(0)}%` : '—'}
                    </td>
                    <td className="py-2 px-3">
                      {f.is_kev
                        ? <span className="text-[10px] px-2 py-0.5 rounded-full bg-red-600 text-white font-bold">KEV</span>
                        : <span className="text-gray-700">—</span>}
                    </td>
                    <td className="py-2 px-3 text-gray-500 max-w-64 truncate" title={f.description}>
                      {f.description || '—'}
                    </td>
                  </tr>
                ))}
                {findings.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-6 py-8 text-center text-gray-500">
                      {summary.total_cves === 0
                        ? 'No CVEs found for the components in this SBOM.'
                        : 'No CVEs match the current filters.'}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalCves > LIMIT && (
            <div className="flex justify-between items-center mt-3 text-xs text-gray-500">
              <span>Showing {Math.min(offset + LIMIT, totalCves)} of {totalCves} CVEs</span>
              <div className="flex gap-2">
                <button
                  disabled={offset === 0}
                  onClick={() => setOffset(o => Math.max(0, o - LIMIT))}
                  className="btn-secondary text-xs disabled:opacity-40"
                >
                  ← Prev
                </button>
                <button
                  disabled={offset + LIMIT >= totalCves}
                  onClick={() => setOffset(o => o + LIMIT)}
                  className="btn-secondary text-xs disabled:opacity-40"
                >
                  Next →
                </button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
