'use client';

import { useState, useEffect, useCallback } from 'react';
import { storeOfflineToken } from '../hooks/useOfflineToken';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001';

interface TokenRow {
    token_id: string;
    invoice_id: string;
    issued_at: string;
    valid_until: string;
    max_offline_hours: number;
    device_hint: string | null;
    is_revoked: boolean;
    is_expired: boolean;
    hours_remaining: number;
}

export default function OfflineTokenManager({ adminKey }: { adminKey: string }) {
    const [tokens, setTokens] = useState<TokenRow[]>([]);
    const [invoiceId, setInvoiceId] = useState('');
    const [hours, setHours] = useState(24);
    const [deviceHint, setDeviceHint] = useState('');
    const [issuedToken, setIssuedToken] = useState('');
    const [issuedForInvoice, setIssuedForInvoice] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [copied, setCopied] = useState(false);

    const h = { 'X-Admin-Key': adminKey };

    const fetchTokens = useCallback(async () => {
        const res = await fetch(`${API}/admin/offline-tokens`, { headers: h });
        if (res.ok) setTokens(await res.json());
    }, [adminKey]);

    useEffect(() => { fetchTokens(); }, [fetchTokens]);

    const handleIssue = async () => {
        if (!invoiceId.trim()) return;
        setLoading(true);
        setError('');
        setIssuedToken('');
        try {
            const params = new URLSearchParams({
                invoice_id: invoiceId.trim(),
                hours: String(hours),
                ...(deviceHint.trim() ? { device_hint: deviceHint.trim() } : {}),
            });
            const res = await fetch(`${API}/admin/offline-token?${params}`, {
                method: 'POST',
                headers: h,
            });
            const data = await res.json();
            if (!res.ok) {
                setError(data.detail ?? 'Unknown error');
            } else {
                setIssuedToken(data.token);
                setIssuedForInvoice(data.invoice_id);
                fetchTokens();
            }
        } catch {
            setError('Network error — is the backend running?');
        } finally {
            setLoading(false);
        }
    };

    const handleRevoke = async (tokenId: string) => {
        await fetch(`${API}/admin/offline-token/${tokenId}`, {
            method: 'DELETE',
            headers: h,
        });
        fetchTokens();
    };

    const handleCopy = () => {
        if (!issuedToken) return;
        navigator.clipboard.writeText(issuedToken);
        // Also persist into localStorage under the invoiceId so the viewer
        // can use it immediately on this machine
        storeOfflineToken(issuedForInvoice, issuedToken);
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    const statusChip = (t: TokenRow) => {
        if (t.is_revoked)
            return <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-red-900/30 text-red-400">REVOKED</span>;
        if (t.is_expired)
            return <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-slate-700 text-slate-500">EXPIRED</span>;
        return (
            <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-green-900/30 text-green-400">
                {t.hours_remaining}h left
            </span>
        );
    };

    return (
        <div className="bg-slate-900 rounded-xl border border-indigo-900/30 p-6 shadow-xl">
            {/* Header */}
            <h2 className="text-lg font-bold text-indigo-400 mb-1 flex items-center gap-2">
                <span className="text-indigo-500">&#x1F511;</span> Offline Viewing Tokens
                <span className="text-[10px] font-normal text-slate-500 ml-1">Zero-Knowledge</span>
            </h2>
            <p className="text-[11px] text-slate-500 mb-5">
                Issue time-limited JWT tokens for offline access. The viewer verifies expiry
                locally without a server call — the signing secret never leaves the backend.
            </p>

            {/* Issue form */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 mb-4">
                <input
                    placeholder="Invoice ID"
                    className="bg-slate-950 border border-slate-700 p-2.5 rounded-lg text-sm font-mono outline-none focus:border-indigo-500 transition"
                    value={invoiceId}
                    onChange={(e) => setInvoiceId(e.target.value)}
                />
                <div className="flex items-center gap-2">
                    <label className="text-[10px] text-slate-500 whitespace-nowrap">Hours:</label>
                    <input
                        type="number"
                        min={1}
                        max={720}
                        className="flex-1 bg-slate-950 border border-slate-700 p-2.5 rounded-lg text-sm font-mono outline-none focus:border-indigo-500 transition"
                        value={hours}
                        onChange={(e) => setHours(Number(e.target.value))}
                    />
                </div>
                <input
                    placeholder="Device hint (e.g. Alice Laptop)"
                    className="bg-slate-950 border border-slate-700 p-2.5 rounded-lg text-sm outline-none focus:border-indigo-500 transition"
                    value={deviceHint}
                    onChange={(e) => setDeviceHint(e.target.value)}
                />
            </div>

            <button
                onClick={handleIssue}
                disabled={loading || !invoiceId.trim()}
                className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 text-white font-bold py-2.5 rounded-lg text-sm transition active:scale-95 mb-4"
            >
                {loading ? 'Issuing…' : 'Issue Offline Token'}
            </button>

            {error && (
                <div className="p-3 rounded-lg bg-red-900/20 border border-red-800/40 text-red-400 text-xs mb-4">
                    {error}
                </div>
            )}

            {/* Newly issued token */}
            {issuedToken && (
                <div className="mb-6 p-4 rounded-lg bg-indigo-900/10 border border-indigo-900/30 space-y-2">
                    <p className="text-[9px] uppercase tracking-wider text-slate-500 font-bold">
                        New Token — copy and deliver to the licensee
                    </p>
                    <code className="block bg-black text-indigo-300 p-3 rounded text-[10px] font-mono break-all border border-indigo-900/30">
                        {issuedToken}
                    </code>
                    <div className="flex gap-2">
                        <button
                            onClick={handleCopy}
                            className="text-xs font-bold text-indigo-400 border border-indigo-900/40 px-3 py-1.5 rounded hover:bg-indigo-900/20 transition"
                        >
                            {copied ? '✓ Copied & saved locally' : '⎘ Copy + save to localStorage'}
                        </button>
                    </div>
                    <p className="text-[9px] text-slate-600 italic">
                        Saving to localStorage allows the viewer on this machine to use it offline immediately.
                    </p>
                </div>
            )}

            {/* Token table */}
            {tokens.length > 0 && (
                <div className="overflow-x-auto">
                    <table className="w-full text-left border-collapse text-xs">
                        <thead className="text-[9px] uppercase tracking-wider text-slate-500 border-b border-slate-800">
                            <tr>
                                <th className="pb-2 pr-4">Invoice</th>
                                <th className="pb-2 pr-4">Device</th>
                                <th className="pb-2 pr-4">Issued</th>
                                <th className="pb-2 pr-4">Expires</th>
                                <th className="pb-2 pr-4">Status</th>
                                <th className="pb-2"></th>
                            </tr>
                        </thead>
                        <tbody className="divide-y divide-slate-800/50">
                            {tokens.map((t) => (
                                <tr key={t.token_id} className="hover:bg-slate-800/30 transition">
                                    <td className="py-2 pr-4 font-mono text-blue-400">{t.invoice_id}</td>
                                    <td className="py-2 pr-4 text-slate-400">{t.device_hint ?? <span className="text-slate-600 italic">—</span>}</td>
                                    <td className="py-2 pr-4 text-slate-500 font-mono">
                                        {new Date(t.issued_at).toLocaleDateString()}
                                    </td>
                                    <td className="py-2 pr-4 text-slate-500 font-mono">
                                        {new Date(t.valid_until).toLocaleString()}
                                    </td>
                                    <td className="py-2 pr-4">{statusChip(t)}</td>
                                    <td className="py-2">
                                        {!t.is_revoked && !t.is_expired && (
                                            <button
                                                onClick={() => handleRevoke(t.token_id)}
                                                className="text-[10px] text-red-500 hover:text-red-400 font-mono transition"
                                            >
                                                Revoke
                                            </button>
                                        )}
                                    </td>
                                </tr>
                            ))}
                        </tbody>
                    </table>
                </div>
            )}
        </div>
    );
}
