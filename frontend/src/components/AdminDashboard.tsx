'use client';
import { useState, useEffect, useCallback } from 'react';
import AnalyticsChart from './AnalyticsChart';
import TrustScore from './TrustScore';
import LeakReporter from './LeakReporter';
import OfflineTokenManager from './OfflineTokenManager';
import ContentVault from './ContentVault';
import AnomalyDashboard from './AnomalyDashboard';
import { useAdminEvents } from '../hooks/useAdminEvents';

interface ViewSession {
  id: number;
  content_id: string;
  duration_seconds: number;
  start_time: string;
  ip_address: string;
  is_bot_suspect: boolean;
}

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001';

// ── Auth header builder — supports raw X-Admin-Key or Bearer JWT ──────────────
function buildHeaders(key: string): Record<string, string> {
  if (key.startsWith('jwt:')) return { Authorization: `Bearer ${key.slice(4)}` };
  return { 'X-Admin-Key': key };
}

export default function AdminDashboard() {
  const [adminKey, setAdminKey]     = useState('');
  const [keyInput, setKeyInput]     = useState('');
  const [totpInput, setTotpInput]   = useState('');
  const [useTotp, setUseTotp]       = useState(false);
  const [loginError, setLoginError] = useState('');
  const [licenses, setLicenses]     = useState([]);
  const [newInvoice, setNewInvoice] = useState({ id: '', owner: '', countries: '' });
  const [generatedKey, setGeneratedKey] = useState('');
  const [logs, setLogs]       = useState([]);
  const [analytics, setAnalytics] = useState<ViewSession[]>([]);
  const [liveCount, setLiveCount] = useState<number | null>(null);
  // P4.1 — dark / light theme (default dark, persisted in localStorage)
  const [isDark, setIsDark] = useState(true);
  // P4.4 — confirm before bulk-revoke
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);

  // ── Theme init from localStorage ────────────────────────────────────────────
  useEffect(() => {
    const saved = localStorage.getItem('drm_theme');
    if (saved === 'light') setIsDark(false);
  }, []);

  useEffect(() => {
    localStorage.setItem('drm_theme', isDark ? 'dark' : 'light');
  }, [isDark]);

  // ── Theme token map ──────────────────────────────────────────────────────────
  const t = {
    page:    isDark ? 'bg-slate-950 text-slate-200' : 'bg-gray-100 text-gray-900',
    card:    isDark ? 'bg-slate-900 border-slate-800' : 'bg-white border-gray-200 shadow-sm',
    header:  isDark ? 'border-slate-800' : 'border-gray-300',
    input:   isDark
      ? 'bg-slate-950 border-slate-700 text-slate-200 placeholder-slate-600'
      : 'bg-white border-gray-300 text-gray-900 placeholder-gray-400',
    th:      isDark ? 'bg-slate-800 text-slate-400' : 'bg-gray-200 text-gray-500',
    tr:      isDark ? 'hover:bg-slate-800/50' : 'hover:bg-gray-50',
    div:     isDark ? 'divide-slate-800' : 'divide-gray-200',
    border:  isDark ? 'border-slate-800' : 'border-gray-200',
    muted:   isDark ? 'text-slate-500' : 'text-gray-400',
    dim:     isDark ? 'text-slate-600' : 'text-gray-400',
    sub:     isDark ? 'text-slate-400' : 'text-gray-600',
    logrow:  isDark ? 'border-slate-800' : 'border-gray-200',
  };

  // ── Data fetchers ────────────────────────────────────────────────────────────
  const fetchAll = useCallback(async (key: string) => {
    const h = buildHeaders(key);
    const [licRes, logRes, anaRes] = await Promise.all([
      fetch(`${API}/admin/licenses`,  { headers: h }),
      fetch(`${API}/admin/audit-log`, { headers: h }),
      fetch(`${API}/admin/analytics`, { headers: h }),
    ]);
    if (licRes.status === 401) { setAdminKey(''); return; }
    setLicenses(await licRes.json());
    setLogs(await logRes.json());
    setAnalytics(await anaRes.json());
  }, []);

  const fetchLiveCount = useCallback(async (key: string) => {
    const res = await fetch(`${API}/admin/sessions/live`, { headers: buildHeaders(key) });
    if (res.ok) setLiveCount((await res.json()).length);
  }, []);

  // ── Restore key from sessionStorage on mount ─────────────────────────────────
  useEffect(() => {
    const saved = sessionStorage.getItem('admin_key');
    if (saved) { setAdminKey(saved); fetchAll(saved); fetchLiveCount(saved); }
  }, [fetchAll, fetchLiveCount]);

  // ── P4.3 — live refresh every 30 s ──────────────────────────────────────────
  useEffect(() => {
    if (!adminKey) return;
    const id = setInterval(() => {
      fetchAll(adminKey);
      fetchLiveCount(adminKey);
    }, 30_000);
    return () => clearInterval(id);
  }, [adminKey, fetchAll, fetchLiveCount]);

  // ── Real-time SSE ────────────────────────────────────────────────────────────
  useAdminEvents(adminKey, (event) => {
    if (event.action === 'revoked' && event.session_id !== undefined) {
      setAnalytics((prev) => prev.filter((s) => s.id !== event.session_id));
      setLiveCount((prev) => (prev !== null ? Math.max(0, prev - 1) : null));
    }
  });

  // ── Login (P3.3 — tries /admin/login for JWT, falls back to raw key) ─────────
  const handleLogin = async () => {
    setLoginError('');
    let authKey = keyInput;
    try {
      const params = new URLSearchParams({ api_key: keyInput });
      if (useTotp && totpInput) params.append('totp_code', totpInput);
      const res = await fetch(`${API}/admin/login?${params}`, { method: 'POST' });
      if (res.ok) {
        const { token } = await res.json();
        authKey = `jwt:${token}`;
      } else if (useTotp) {
        // If TOTP was provided but login failed, show the error
        const { detail } = await res.json().catch(() => ({ detail: 'Login failed' }));
        setLoginError(detail);
        return;
      }
      // If /admin/login returns 401 without TOTP, fall through to raw key
    } catch {
      // /admin/login endpoint unavailable — use raw key
    }
    sessionStorage.setItem('admin_key', authKey);
    setAdminKey(authKey);
    fetchAll(authKey);
    fetchLiveCount(authKey);
  };

  const handlePayment = async (invoiceId: string) => {
    const res = await fetch(`${API}/create-checkout-session?invoice_id=${invoiceId}`, {
      method: 'POST',
    });
    const { url } = await res.json();
    window.location.href = url;
  };

  const handleRevoke = async (sessionId: number) => {
    await fetch(`${API}/admin/analytics/${sessionId}`, {
      method: 'DELETE',
      headers: buildHeaders(adminKey),
    });
    setAnalytics((prev) => prev.filter((s) => s.id !== sessionId));
  };

  const handleRevokeAll = async (invoiceId: string) => {
    await fetch(`${API}/admin/sessions/revoke-all/${invoiceId}`, {
      method: 'POST',
      headers: buildHeaders(adminKey),
    });
    setConfirmRevoke(null);
    fetchAll(adminKey);
    fetchLiveCount(adminKey);
  };

  const handleCreate = async () => {
    const params = new URLSearchParams({
      invoice_id: newInvoice.id,
      owner_id:   newInvoice.owner,
      ...(newInvoice.countries ? { allowed_countries: newInvoice.countries.toUpperCase() } : {}),
    });
    const res = await fetch(`${API}/admin/create-license?${params}`, {
      method: 'POST',
      headers: buildHeaders(adminKey),
    });
    const data = await res.json();
    setGeneratedKey(data.plain_key_to_copy);
    fetchAll(adminKey);
  };

  // ── Admin key gate (login screen) ─────────────────────────────────────────────
  if (!adminKey) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="bg-slate-900 p-8 rounded-2xl border border-slate-800 w-full max-w-sm space-y-4">
          <h2 className="text-white font-bold text-lg">Admin Access</h2>

          <input
            type="password"
            placeholder="X-Admin-Key"
            className="w-full bg-slate-950 border border-slate-700 p-3 rounded-lg outline-none focus:border-blue-500 transition text-sm font-mono"
            value={keyInput}
            onChange={(e) => setKeyInput(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !useTotp && handleLogin()}
          />

          {/* P3.3 — TOTP toggle */}
          <label className="flex items-center gap-2 text-xs text-slate-400 cursor-pointer select-none">
            <input
              type="checkbox"
              className="accent-blue-500"
              checked={useTotp}
              onChange={(e) => setUseTotp(e.target.checked)}
            />
            Use 2FA (TOTP code)
          </label>

          {useTotp && (
            <input
              type="text"
              inputMode="numeric"
              maxLength={6}
              placeholder="6-digit TOTP code"
              className="w-full bg-slate-950 border border-slate-700 p-3 rounded-lg outline-none focus:border-blue-500 transition text-sm font-mono tracking-widest"
              value={totpInput}
              onChange={(e) => setTotpInput(e.target.value.replace(/\D/g, '').slice(0, 6))}
              onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
            />
          )}

          {loginError && (
            <p className="text-red-400 text-xs font-mono">{loginError}</p>
          )}

          <button
            onClick={handleLogin}
            className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 rounded-lg transition"
          >
            Authenticate
          </button>
        </div>
      </div>
    );
  }

  // ── Main dashboard ─────────────────────────────────────────────────────────────
  return (
    <div className={`p-8 min-h-screen font-sans transition-colors duration-200 ${t.page}`}>
      <header className={`mb-10 flex justify-between items-center border-b pb-5 ${t.header}`}>
        <h1 className="text-2xl font-bold tracking-tight">
          DRM <span className="text-blue-500">Master Console</span>
        </h1>
        <div className="flex items-center gap-4">
          {/* Live session counter */}
          <div className="flex items-center gap-1.5 text-xs font-mono">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-emerald-400">
              {liveCount !== null ? `${liveCount} live` : 'Redis'}
            </span>
          </div>

          <div className={`text-xs font-mono ${t.muted}`}>PostgreSQL + Redis</div>

          {/* P4.3 — polling indicator */}
          <div className={`text-[10px] font-mono ${t.dim}`} title="Data refreshes every 30 s">
            ⟳ 30s
          </div>

          {/* P4.1 — dark / light toggle */}
          <button
            onClick={() => setIsDark((v) => !v)}
            className={`text-xs border px-2 py-1 rounded font-mono transition ${
              isDark
                ? 'border-slate-700 text-slate-400 hover:text-slate-200'
                : 'border-gray-300 text-gray-500 hover:text-gray-800'
            }`}
            title="Toggle dark / light theme"
          >
            {isDark ? '☀ Light' : '☾ Dark'}
          </button>

          <button
            onClick={() => { sessionStorage.removeItem('admin_key'); setAdminKey(''); }}
            className="text-xs text-red-500 hover:text-red-400 font-mono"
          >
            Logout
          </button>
        </div>
      </header>

      {/* Trust Score + Analytics chart */}
      <div className="mb-10 space-y-4">
        <TrustScore
          score={
            analytics.length === 0
              ? 100
              : Math.round(
                  ((analytics.length - analytics.filter((s) => s.is_bot_suspect).length) /
                    analytics.length) *
                    100
                )
          }
          total={analytics.length}
          suspicious={analytics.filter((s) => s.is_bot_suspect).length}
        />
        <AnalyticsChart data={analytics} onRevoke={handleRevoke} />
      </div>

      {/* Create license form */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-10">
        <div className={`p-6 rounded-xl border ${t.card}`}>
          <h2 className="text-lg font-semibold mb-4 text-blue-400">Generate New License</h2>
          <div className="space-y-4">
            <input
              placeholder="Invoice ID (e.g. INV-2026-001)"
              className={`w-full p-3 rounded-lg outline-none focus:border-blue-500 transition border ${t.input}`}
              onChange={(e) => setNewInvoice({ ...newInvoice, id: e.target.value })}
            />
            <input
              placeholder="Owner ID / Employee Name"
              className={`w-full p-3 rounded-lg outline-none focus:border-blue-500 transition border ${t.input}`}
              onChange={(e) => setNewInvoice({ ...newInvoice, owner: e.target.value })}
            />
            <input
              placeholder="Allowed Regions (e.g. US,GB,DE — leave blank for unrestricted)"
              className={`w-full p-3 rounded-lg outline-none focus:border-blue-500 transition text-xs font-mono uppercase border ${t.input}`}
              onChange={(e) => setNewInvoice({ ...newInvoice, countries: e.target.value })}
            />
            <button
              onClick={handleCreate}
              className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 rounded-lg transition-transform active:scale-95"
            >
              Generate & Hash Key
            </button>
          </div>
        </div>

        <div className={`p-6 rounded-xl border border-dashed flex flex-col justify-center items-center text-center ${isDark ? 'border-slate-700' : 'border-gray-300'}`}>
          {generatedKey ? (
            <>
              <p className={`text-xs uppercase ${t.muted} mb-2`}>Generated License Key (Plaintext)</p>
              <code className="bg-black text-green-400 p-3 rounded block w-full break-all border border-green-900/30">
                {generatedKey}
              </code>
              <p className="text-[10px] text-red-400 mt-4 italic">This key will never be shown again.</p>
            </>
          ) : (
            <p className={`italic ${t.dim}`}>Enter details to generate access credentials</p>
          )}
        </div>
      </div>

      {/* Licenses table */}
      <div className={`rounded-xl border overflow-hidden shadow-2xl mb-10 ${t.card}`}>
        <table className="w-full text-left border-collapse">
          <thead className={`text-xs uppercase tracking-wider ${t.th}`}>
            <tr>
              <th className="p-4">Invoice</th>
              <th className="p-4">Owner</th>
              <th className="p-4">Sessions</th>
              <th className="p-4">Region</th>
              <th className="p-4">Status</th>
              <th className="p-4">Hashed Key (Prefix)</th>
              <th className="p-4">Action</th>
            </tr>
          </thead>
          <tbody className={`divide-y ${t.div}`}>
            {licenses.map((lic: any) => (
              <tr key={lic.id} className={`transition ${t.tr}`}>
                <td className="p-4 font-mono text-blue-400">{lic.invoice_id}</td>
                <td className="p-4">{lic.owner_id}</td>
                <td className={`p-4 text-center font-mono ${t.sub}`}>{lic.max_sessions ?? 1}</td>
                <td className="p-4">
                  {lic.allowed_countries ? (
                    <div className="flex flex-wrap gap-1">
                      {lic.allowed_countries.split(',').map((cc: string) => (
                        <span key={cc} className="px-1.5 py-0.5 rounded text-[9px] font-bold font-mono bg-blue-900/30 text-blue-400 border border-blue-800/40">
                          {cc.trim()}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className={`text-[10px] italic ${t.dim}`}>Unrestricted</span>
                  )}
                </td>
                <td className="p-4">
                  <span className={`px-2 py-1 rounded-full text-[10px] font-bold ${lic.is_paid ? 'bg-green-900/30 text-green-500' : 'bg-red-900/30 text-red-500'}`}>
                    {lic.is_paid ? 'PAID' : 'PENDING'}
                  </span>
                </td>
                <td className={`p-4 text-xs font-mono ${t.muted}`}>{lic.license_key.substring(0, 15)}...</td>
                <td className="p-4 flex items-center gap-2 flex-wrap">
                  {!lic.is_paid && (
                    <button
                      onClick={() => handlePayment(lic.invoice_id)}
                      className="text-xs bg-green-600 hover:bg-green-500 text-white px-2 py-1 rounded"
                    >
                      Pay Now
                    </button>
                  )}
                  {/* P4.4 — confirm before bulk revoke */}
                  {confirmRevoke === lic.invoice_id ? (
                    <span className="flex items-center gap-1.5">
                      <span className="text-[9px] text-red-400">Revoke all sessions?</span>
                      <button
                        onClick={() => handleRevokeAll(lic.invoice_id)}
                        className="text-[9px] bg-red-600 text-white px-1.5 py-0.5 rounded font-bold"
                      >
                        Yes
                      </button>
                      <button
                        onClick={() => setConfirmRevoke(null)}
                        className={`text-[9px] px-1.5 py-0.5 rounded ${t.muted} hover:text-slate-300`}
                      >
                        No
                      </button>
                    </span>
                  ) : (
                    <button
                      onClick={() => setConfirmRevoke(lic.invoice_id)}
                      className="text-xs bg-red-900/40 hover:bg-red-800/60 text-red-400 hover:text-red-300 border border-red-900/40 px-2 py-1 rounded font-mono transition"
                      title="Revoke all active sessions for this license"
                    >
                      Revoke All
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* AI Anomaly Pattern Discovery */}
      <div className={`mt-10 rounded-xl border border-purple-900/30 p-6 ${isDark ? 'bg-slate-900' : 'bg-white shadow-sm'}`}>
        <AnomalyDashboard adminKey={adminKey} />
      </div>

      {/* Security Audit Trail */}
      <div className={`mt-10 rounded-xl border border-red-900/20 p-6 ${isDark ? 'bg-slate-900' : 'bg-white shadow-sm'}`}>
        <h2 className="text-lg font-bold text-red-500 mb-4 flex items-center gap-2">
          <span className="relative flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
          </span>
          Security Audit Trail
        </h2>
        <div className="space-y-2">
          {logs.map((log: any) => (
            <div key={log.id} className={`flex justify-between text-xs font-mono p-2 border-b ${t.logrow}`}>
              <span className={t.muted}>{new Date(log.timestamp).toLocaleString()}</span>
              <span className="text-blue-400">{log.invoice_id}</span>
              <span className={t.sub}>{log.ip_address}</span>
              <span className={log.is_success ? 'text-green-500' : 'text-red-500'}>
                {log.is_success ? 'SUCCESS' : 'FAILED'}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Proof of Leak — Legal Evidence Generator */}
      <div className="mt-10">
        <LeakReporter adminKey={adminKey} />
      </div>

      {/* Zero-Knowledge Offline Viewing Tokens */}
      <div className="mt-10">
        <OfflineTokenManager adminKey={adminKey} />
      </div>

      {/* Content Vault — Encrypted S3 Storage */}
      <div className={`mt-10 rounded-xl border p-6 ${t.card}`}>
        <ContentVault adminKey={adminKey} />
      </div>
    </div>
  );
}
