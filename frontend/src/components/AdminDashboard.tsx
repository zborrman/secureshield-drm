'use client';
import { useState, useEffect, useCallback } from 'react';
import AnalyticsChart from './AnalyticsChart';
import TrustScore from './TrustScore';
import LeakReporter from './LeakReporter';
import OfflineTokenManager from './OfflineTokenManager';
import ContentVault from './ContentVault';
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

export default function AdminDashboard() {
  const [adminKey, setAdminKey] = useState('');
  const [keyInput, setKeyInput] = useState('');
  const [licenses, setLicenses] = useState([]);
  const [newInvoice, setNewInvoice] = useState({ id: '', owner: '', countries: '' });
  const [generatedKey, setGeneratedKey] = useState('');
  const [logs, setLogs] = useState([]);
  const [analytics, setAnalytics] = useState<ViewSession[]>([]);
  const [liveCount, setLiveCount] = useState<number | null>(null);

  const fetchAll = useCallback(async (key: string) => {
    const h = { 'X-Admin-Key': key };
    const [licRes, logRes, anaRes] = await Promise.all([
      fetch(`${API}/admin/licenses`, { headers: h }),
      fetch(`${API}/admin/audit-log`, { headers: h }),
      fetch(`${API}/admin/analytics`, { headers: h }),
    ]);
    if (licRes.status === 401) { setAdminKey(''); return; }
    setLicenses(await licRes.json());
    setLogs(await logRes.json());
    setAnalytics(await anaRes.json());
  }, []);

  const fetchLiveCount = useCallback(async (key: string) => {
    const res = await fetch(`${API}/admin/sessions/live`, {
      headers: { 'X-Admin-Key': key },
    });
    if (res.ok) setLiveCount((await res.json()).length);
  }, []);

  // Restore key from sessionStorage on mount
  useEffect(() => {
    const saved = sessionStorage.getItem('admin_key');
    if (saved) { setAdminKey(saved); fetchAll(saved); fetchLiveCount(saved); }
  }, [fetchAll, fetchLiveCount]);

  // Real-time SSE: remove the revoked session from local state immediately
  // and refresh the live-sessions counter — no full refetch needed.
  useAdminEvents(adminKey, (event) => {
    if (event.action === 'revoked' && event.session_id !== undefined) {
      setAnalytics((prev) => prev.filter((s) => s.id !== event.session_id));
      setLiveCount((prev) => (prev !== null ? Math.max(0, prev - 1) : null));
    }
  });

  const handleLogin = () => {
    sessionStorage.setItem('admin_key', keyInput);
    setAdminKey(keyInput);
    fetchAll(keyInput);
    fetchLiveCount(keyInput);
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
      headers: { 'X-Admin-Key': adminKey },
    });
    // Optimistic update — SSE will confirm the removal
    setAnalytics((prev) => prev.filter((s) => s.id !== sessionId));
  };

  const handleRevokeAll = async (invoiceId: string) => {
    await fetch(`${API}/admin/sessions/revoke-all/${invoiceId}`, {
      method: 'POST',
      headers: { 'X-Admin-Key': adminKey },
    });
    // Refresh full list after bulk revocation
    fetchAll(adminKey);
    fetchLiveCount(adminKey);
  };

  const handleCreate = async () => {
    const params = new URLSearchParams({
      invoice_id: newInvoice.id,
      owner_id: newInvoice.owner,
      ...(newInvoice.countries ? { allowed_countries: newInvoice.countries.toUpperCase() } : {}),
    });
    const res = await fetch(`${API}/admin/create-license?${params}`, {
      method: 'POST',
      headers: { 'X-Admin-Key': adminKey },
    });
    const data = await res.json();
    setGeneratedKey(data.plain_key_to_copy);
    fetchAll(adminKey);
  };

  // ── Admin key gate ────────────────────────────────────────────
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
            onKeyDown={(e) => e.key === 'Enter' && handleLogin()}
          />
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

  return (
    <div className="p-8 bg-slate-950 text-slate-200 min-h-screen font-sans">
      <header className="mb-10 flex justify-between items-center border-b border-slate-800 pb-5">
        <h1 className="text-2xl font-bold tracking-tight text-white">
          DRM <span className="text-blue-500">Master Console</span>
        </h1>
        <div className="flex items-center gap-4">
          {/* Live session counter — updated via SSE */}
          <div className="flex items-center gap-1.5 text-xs font-mono">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
            </span>
            <span className="text-emerald-400">
              {liveCount !== null ? `${liveCount} live` : 'Redis'}
            </span>
          </div>
          <div className="text-xs text-slate-500 font-mono">PostgreSQL + Redis</div>
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
        <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 shadow-lg">
          <h2 className="text-lg font-semibold mb-4 text-blue-400">Generate New License</h2>
          <div className="space-y-4">
            <input
              placeholder="Invoice ID (e.g. INV-2026-001)"
              className="w-full bg-slate-950 border border-slate-700 p-3 rounded-lg outline-none focus:border-blue-500 transition"
              onChange={(e) => setNewInvoice({ ...newInvoice, id: e.target.value })}
            />
            <input
              placeholder="Owner ID / Employee Name"
              className="w-full bg-slate-950 border border-slate-700 p-3 rounded-lg outline-none focus:border-blue-500 transition"
              onChange={(e) => setNewInvoice({ ...newInvoice, owner: e.target.value })}
            />
            <input
              placeholder="Allowed Regions (e.g. US,GB,DE — leave blank for unrestricted)"
              className="w-full bg-slate-950 border border-slate-700 p-3 rounded-lg outline-none focus:border-blue-500 transition text-xs font-mono uppercase"
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

        <div className="bg-slate-900 p-6 rounded-xl border border-dashed border-slate-700 flex flex-col justify-center items-center text-center">
          {generatedKey ? (
            <>
              <p className="text-xs uppercase text-slate-500 mb-2">Generated License Key (Plaintext)</p>
              <code className="bg-black text-green-400 p-3 rounded block w-full break-all border border-green-900/30">
                {generatedKey}
              </code>
              <p className="text-[10px] text-red-400 mt-4 italic">This key will never be shown again.</p>
            </>
          ) : (
            <p className="text-slate-600 italic">Enter details to generate access credentials</p>
          )}
        </div>
      </div>

      {/* Licenses table */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden shadow-2xl mb-10">
        <table className="w-full text-left border-collapse">
          <thead className="bg-slate-800 text-slate-400 text-xs uppercase tracking-wider">
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
          <tbody className="divide-y divide-slate-800">
            {licenses.map((lic: any) => (
              <tr key={lic.id} className="hover:bg-slate-800/50 transition">
                <td className="p-4 font-mono text-blue-400">{lic.invoice_id}</td>
                <td className="p-4">{lic.owner_id}</td>
                <td className="p-4 text-center font-mono text-slate-400">{lic.max_sessions ?? 1}</td>
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
                    <span className="text-[10px] text-slate-600 italic">Unrestricted</span>
                  )}
                </td>
                <td className="p-4">
                  <span className={`px-2 py-1 rounded-full text-[10px] font-bold ${lic.is_paid ? 'bg-green-900/30 text-green-500' : 'bg-red-900/30 text-red-500'}`}>
                    {lic.is_paid ? 'PAID' : 'PENDING'}
                  </span>
                </td>
                <td className="p-4 text-xs text-slate-500 font-mono">{lic.license_key.substring(0, 15)}...</td>
                <td className="p-4 flex items-center gap-2 flex-wrap">
                  {!lic.is_paid && (
                    <button
                      onClick={() => handlePayment(lic.invoice_id)}
                      className="text-xs bg-green-600 hover:bg-green-500 text-white px-2 py-1 rounded"
                    >
                      Pay Now
                    </button>
                  )}
                  <button
                    onClick={() => handleRevokeAll(lic.invoice_id)}
                    className="text-xs bg-red-900/40 hover:bg-red-800/60 text-red-400 hover:text-red-300 border border-red-900/40 px-2 py-1 rounded font-mono transition"
                    title="Instantly revoke all active sessions for this license"
                  >
                    Revoke All
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Security Audit Trail */}
      <div className="mt-10 bg-slate-900 rounded-xl border border-red-900/20 p-6">
        <h2 className="text-lg font-bold text-red-500 mb-4 flex items-center gap-2">
          <span className="relative flex h-3 w-3">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3 w-3 bg-red-500"></span>
          </span>
          Security Audit Trail
        </h2>
        <div className="space-y-2">
          {logs.map((log: any) => (
            <div key={log.id} className="flex justify-between text-xs font-mono p-2 border-b border-slate-800">
              <span className="text-slate-500">{new Date(log.timestamp).toLocaleString()}</span>
              <span className="text-blue-400">{log.invoice_id}</span>
              <span className="text-slate-400">{log.ip_address}</span>
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
      <div className="mt-10 bg-slate-900 rounded-xl border border-slate-800 p-6">
        <ContentVault adminKey={adminKey} />
      </div>
    </div>
  );
}
