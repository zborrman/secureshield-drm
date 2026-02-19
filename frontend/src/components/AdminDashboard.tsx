'use client';
import { useState, useEffect } from 'react';

export default function AdminDashboard() {
  const [licenses, setLicenses] = useState([]);
  const [newInvoice, setNewInvoice] = useState({ id: '', owner: '' });
  const [generatedKey, setGeneratedKey] = useState('');
  const [logs, setLogs] = useState([]);

  const fetchLicenses = async () => {
    const res = await fetch('http://localhost:8000/admin/licenses');
    const data = await res.json();
    setLicenses(data);
  };

  const fetchLogs = async () => {
    const res = await fetch('http://localhost:8000/admin/audit-log');
    const data = await res.json();
    setLogs(data);
  };

  const handlePayment = async (invoiceId: string) => {
    const res = await fetch(`http://localhost:8000/create-checkout-session?invoice_id=${invoiceId}`, {
      method: 'POST'
    });
    const { url } = await res.json();

    // Перенаправляем пользователя на защищенную страницу оплаты Stripe
    window.location.href = url;
  };

  const handleCreate = async () => {
    const res = await fetch(`http://localhost:8000/admin/create-license?invoice_id=${newInvoice.id}&owner_id=${newInvoice.owner}`, {
      method: 'POST'
    });
    const data = await res.json();
    setGeneratedKey(data.plain_key_to_copy);
    fetchLicenses();
  };

  useEffect(() => {
    fetchLicenses();
    fetchLogs();
  }, []);

  return (
    <div className="p-8 bg-slate-950 text-slate-200 min-h-screen font-sans">
      <header className="mb-10 flex justify-between items-center border-b border-slate-800 pb-5">
        <h1 className="text-2xl font-bold tracking-tight text-white">DRM <span className="text-blue-500">Master Console</span></h1>
        <div className="text-xs text-slate-500 font-mono">Status: Connected to PostgreSQL (asyncpg)</div>
      </header>

      {/* Форма создания */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-8 mb-10">
        <div className="bg-slate-900 p-6 rounded-xl border border-slate-800 shadow-lg">
          <h2 className="text-lg font-semibold mb-4 text-blue-400">Generate New License</h2>
          <div className="space-y-4">
            <input
              placeholder="Invoice ID (e.g. INV-2026-001)"
              className="w-full bg-slate-950 border border-slate-700 p-3 rounded-lg outline-none focus:border-blue-500 transition"
              onChange={(e) => setNewInvoice({...newInvoice, id: e.target.value})}
            />
            <input
              placeholder="Owner ID / Employee Name"
              className="w-full bg-slate-950 border border-slate-700 p-3 rounded-lg outline-none focus:border-blue-500 transition"
              onChange={(e) => setNewInvoice({...newInvoice, owner: e.target.value})}
            />
            <button
              onClick={handleCreate}
              className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 rounded-lg transition-transform active:scale-95"
            >
              Generate & Hash Key
            </button>
          </div>
        </div>

        {/* Слот для ключа */}
        <div className="bg-slate-900 p-6 rounded-xl border border-dashed border-slate-700 flex flex-col justify-center items-center text-center">
          {generatedKey ? (
            <>
              <p className="text-xs uppercase text-slate-500 mb-2">Generated License Key (Plaintext)</p>
              <code className="bg-black text-green-400 p-3 rounded block w-full break-all border border-green-900/30">{generatedKey}</code>
              <p className="text-[10px] text-red-400 mt-4 italic">⚠️ This key will never be shown again.</p>
            </>
          ) : (
            <p className="text-slate-600 italic">Enter details to generate access credentials</p>
          )}
        </div>
      </div>

      {/* Таблица лицензий */}
      <div className="bg-slate-900 rounded-xl border border-slate-800 overflow-hidden shadow-2xl mb-10">
        <table className="w-full text-left border-collapse">
          <thead className="bg-slate-800 text-slate-400 text-xs uppercase tracking-wider">
            <tr>
              <th className="p-4">Invoice</th>
              <th className="p-4">Owner</th>
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
                <td className="p-4">
                  <span className={`px-2 py-1 rounded-full text-[10px] font-bold ${lic.is_paid ? 'bg-green-900/30 text-green-500' : 'bg-red-900/30 text-red-500'}`}>
                    {lic.is_paid ? 'PAID' : 'PENDING'}
                  </span>
                </td>
                <td className="p-4 text-xs text-slate-500 font-mono">{lic.license_key.substring(0, 15)}...</td>
                <td className="p-4">
                  {!lic.is_paid && (
                    <button
                      onClick={() => handlePayment(lic.invoice_id)}
                      className="text-xs bg-green-600 hover:bg-green-500 text-white px-2 py-1 rounded"
                    >
                      💳 Pay Now
                    </button>
                  )}
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
              <span className={log.is_success ? "text-green-500" : "text-red-500"}>
                {log.is_success ? "SUCCESS" : "FAILED_ATTEMPT"}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
