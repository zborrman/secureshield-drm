"use client";

import { useState, useEffect, useCallback } from "react";
import ContentVault from "./ContentVault";
import AnomalyDashboard from "./AnomalyDashboard";

const API = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8001";

interface TenantAuth {
  slug: string;
  adminKey: string;
}

interface Props {
  auth: TenantAuth;
  onLogout: () => void;
}

export default function TenantDashboard({ auth, onLogout }: Props) {
  const [licenses, setLicenses] = useState<any[]>([]);
  const [auditLog, setAuditLog] = useState<any[]>([]);
  const [generatedKey, setGeneratedKey] = useState("");
  const [newInvoice, setNewInvoice] = useState({ id: "", owner: "", countries: "" });
  const [error, setError] = useState("");

  const tenantHeaders = {
    "X-Tenant-ID": auth.slug,
    "X-Admin-Key": auth.adminKey,
  };

  const fetchAll = useCallback(async () => {
    try {
      const [licRes, logRes] = await Promise.all([
        fetch(`${API}/tenant/licenses`, { headers: tenantHeaders }),
        fetch(`${API}/tenant/audit-log`, { headers: tenantHeaders }),
      ]);
      if (!licRes.ok) {
        setError(`API error: ${licRes.status}`);
        return;
      }
      setLicenses(await licRes.json());
      setAuditLog(await logRes.json());
    } catch {
      setError("Network error");
    }
  }, [auth.slug, auth.adminKey]);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  async function handleCreate() {
    const params = new URLSearchParams({
      invoice_id: newInvoice.id,
      owner_id: newInvoice.owner,
      ...(newInvoice.countries ? { allowed_countries: newInvoice.countries.toUpperCase() } : {}),
    });
    const res = await fetch(`${API}/tenant/licenses?${params}`, {
      method: "POST",
      headers: tenantHeaders,
    });
    if (!res.ok) {
      const d = await res.json();
      setError(d.detail ?? "Failed to create license");
      return;
    }
    const data = await res.json();
    setGeneratedKey(data.plain_key_to_copy);
    fetchAll();
  }

  return (
    <div className="p-8 bg-slate-950 text-slate-200 min-h-screen font-sans">
      <header className="mb-10 flex justify-between items-center border-b border-slate-800 pb-5">
        <div>
          <h1 className="text-2xl font-bold text-white">
            Tenant Console{" "}
            <span className="text-blue-400 font-mono text-lg">{auth.slug}</span>
          </h1>
          <p className="text-slate-500 text-xs mt-1">
            Scoped to your organisation only
          </p>
        </div>
        <button
          onClick={onLogout}
          className="text-xs text-red-500 hover:text-red-400 font-mono border border-red-900/40 px-3 py-1.5 rounded"
        >
          Logout
        </button>
      </header>

      {error && (
        <div className="mb-6 bg-red-900/30 border border-red-800 text-red-400 rounded-lg px-4 py-3 text-sm">
          {error}
        </div>
      )}

      {/* Create license */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-10">
        <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 shadow-lg">
          <h2 className="text-lg font-semibold mb-4 text-blue-400">
            Generate New License
          </h2>
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
              placeholder="Allowed Regions (e.g. US,GB — blank = unrestricted)"
              className="w-full bg-slate-950 border border-slate-700 p-3 rounded-lg outline-none focus:border-blue-500 transition text-xs font-mono uppercase"
              onChange={(e) => setNewInvoice({ ...newInvoice, countries: e.target.value })}
            />
            <button
              onClick={handleCreate}
              className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 rounded-lg transition"
            >
              Generate & Hash Key
            </button>
          </div>
        </div>

        <div className="bg-slate-900 p-6 rounded-xl border border-dashed border-slate-700 flex flex-col justify-center items-center text-center">
          {generatedKey ? (
            <>
              <p className="text-xs uppercase text-slate-500 mb-2">
                Generated License Key (Plaintext)
              </p>
              <code className="bg-black text-green-400 p-3 rounded block w-full break-all border border-green-900/30">
                {generatedKey}
              </code>
              <p className="text-[10px] text-red-400 mt-4 italic">
                This key will never be shown again.
              </p>
            </>
          ) : (
            <p className="text-slate-600 italic">
              Enter details to generate access credentials
            </p>
          )}
        </div>
      </div>

      {/* Licenses table */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden shadow-2xl mb-10">
        <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider px-4 pt-4 pb-2">
          Licenses ({licenses.length} / plan limit)
        </h2>
        <table className="w-full text-left">
          <thead className="bg-slate-800 text-slate-400 text-xs uppercase">
            <tr>
              <th className="p-4">Invoice</th>
              <th className="p-4">Owner</th>
              <th className="p-4">Region</th>
              <th className="p-4">Status</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {licenses.map((lic: any) => (
              <tr key={lic.id} className="hover:bg-slate-800/50 transition">
                <td className="p-4 font-mono text-blue-400">{lic.invoice_id}</td>
                <td className="p-4">{lic.owner_id}</td>
                <td className="p-4 text-xs">
                  {lic.allowed_countries ?? (
                    <span className="text-slate-600 italic">Unrestricted</span>
                  )}
                </td>
                <td className="p-4">
                  <span
                    className={`px-2 py-1 rounded-full text-[10px] font-bold ${
                      lic.is_paid
                        ? "bg-green-900/30 text-green-500"
                        : "bg-red-900/30 text-red-500"
                    }`}
                  >
                    {lic.is_paid ? "PAID" : "PENDING"}
                  </span>
                </td>
              </tr>
            ))}
            {licenses.length === 0 && (
              <tr>
                <td colSpan={4} className="p-6 text-center text-slate-600 italic text-sm">
                  No licenses yet — create one above.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* Audit log */}
      <div className="bg-slate-900 rounded-xl border border-red-900/20 p-6 mb-10">
        <h2 className="text-lg font-bold text-red-500 mb-4">Audit Trail</h2>
        <div className="space-y-2">
          {auditLog.slice(0, 20).map((log: any) => (
            <div
              key={log.id}
              className="flex justify-between text-xs font-mono p-2 border-b border-slate-800"
            >
              <span className="text-slate-500">
                {new Date(log.timestamp).toLocaleString()}
              </span>
              <span className="text-blue-400">{log.invoice_id}</span>
              <span className="text-slate-400">{log.ip_address}</span>
              <span className={log.is_success ? "text-green-500" : "text-red-500"}>
                {log.is_success ? "SUCCESS" : "FAILED"}
              </span>
            </div>
          ))}
          {auditLog.length === 0 && (
            <p className="text-slate-600 text-sm italic">No audit events yet.</p>
          )}
        </div>
      </div>

      {/* AI Anomaly Pattern Discovery */}
      <div className="bg-slate-900 rounded-xl border border-purple-900/30 p-6 mb-10">
        <AnomalyDashboard adminKey={auth.adminKey} tenantSlug={auth.slug} />
      </div>

      {/* Vault — uses the same ContentVault but with tenant headers */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 p-6">
        <ContentVault
          adminKey={auth.adminKey}
          tenantSlug={auth.slug}
        />
      </div>
    </div>
  );
}
