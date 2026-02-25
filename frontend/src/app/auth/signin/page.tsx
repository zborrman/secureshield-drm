'use client';
import { useState } from 'react';
import { useRouter } from 'next/navigation';

export default function SignIn() {
  const [invoice, setInvoice] = useState('');
  const [key, setKey] = useState('');
  const router = useRouter();

  const handleSignIn = async (e: React.FormEvent) => {
    e.preventDefault();
    const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001';
    const res = await fetch(`${API}/verify-license`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ invoice_id: invoice, input_key: key }),
    });

    if (res.ok) {
      const data = await res.json();
      const token = String(data.session_token ?? data.fingerprint ?? 'authenticated');
      // Cookie — для middleware (server-side); localStorage — для client reads
      document.cookie = `auth_token=${token}; path=/; SameSite=Strict`;
      localStorage.setItem('auth_token', token);
      localStorage.setItem('invoice_id', invoice);
      router.push('/dashboard');
    } else {
      alert("Ошибка доступа. Проверьте инвойс и ключ.");
    }
  };

  return (
    <div className="min-h-screen bg-[#0F172A] flex items-center justify-center p-4 font-sans">
      <div className="max-w-md w-full bg-[#1E293B] rounded-2xl p-8 shadow-2xl border border-slate-800">
        <div className="flex flex-col items-center mb-8">
          <div className="w-12 h-12 bg-blue-500/10 rounded-xl flex items-center justify-center mb-4">
            <svg className="w-6 h-6 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Access Portal</h1>
          <p className="text-slate-400 text-sm mt-2 text-center">Введите данные лицензии для активации защищенного сеанса.</p>
        </div>

        <form onSubmit={handleSignIn} className="space-y-6">
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Invoice ID</label>
            <input
              required
              className="w-full bg-[#0F172A] border border-slate-700 rounded-lg p-3 text-white focus:border-blue-500 outline-none font-mono text-sm transition"
              placeholder="INV-2026-XYS"
              onChange={(e) => setInvoice(e.target.value)}
            />
          </div>
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">License Key</label>
            <input
              required
              type="password"
              className="w-full bg-[#0F172A] border border-slate-700 rounded-lg p-3 text-white focus:border-blue-500 outline-none transition"
              placeholder="••••••••••••••••"
              onChange={(e) => setKey(e.target.value)}
            />
          </div>
          <button className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3 rounded-lg shadow-lg shadow-blue-500/20 transition-all active:scale-[0.98]">
            Activate Secure Session
          </button>
        </form>
      </div>
    </div>
  );
}
