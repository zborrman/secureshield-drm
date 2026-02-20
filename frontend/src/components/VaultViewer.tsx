'use client';

import { useEffect, useState } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001';

interface VaultItem {
    content_id: string;
    filename: string;
    content_type: string;
    size_bytes: number;
    description: string | null;
    uploaded_at: string;
}

interface AccessInfo {
    access_token: string;
    session_id: number;
    filename: string;
    content_type: string;
    size_bytes: number;
    expires_in_seconds: number;
}

function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/** Renders the decrypted content based on its MIME type. */
function ContentRenderer({ url, contentType, filename }: { url: string; contentType: string; filename: string }) {
    if (contentType.startsWith('image/')) {
        return (
            <img
                src={url}
                alt={filename}
                className="max-w-full rounded border border-slate-700"
                onContextMenu={(e) => e.preventDefault()}
                draggable={false}
            />
        );
    }
    if (contentType === 'application/pdf') {
        return (
            <iframe
                src={url}
                title={filename}
                className="w-full h-[70vh] rounded border border-slate-700"
            />
        );
    }
    if (contentType.startsWith('video/')) {
        return (
            <video
                controls
                className="w-full rounded border border-slate-700"
                controlsList="nodownload"
                onContextMenu={(e) => e.preventDefault()}
            >
                <source src={url} type={contentType} />
                Your browser does not support video playback.
            </video>
        );
    }
    if (contentType.startsWith('text/')) {
        return (
            <a
                href={url}
                download={filename}
                className="inline-block bg-blue-600 hover:bg-blue-500 px-4 py-2 rounded text-sm font-bold transition-all active:scale-95"
            >
                Download {filename}
            </a>
        );
    }
    // Generic binary download
    return (
        <a
            href={url}
            download={filename}
            className="inline-block bg-slate-700 hover:bg-slate-600 px-4 py-2 rounded text-sm font-bold transition-all active:scale-95"
        >
            Download {filename} ({formatBytes(0)})
        </a>
    );
}

export default function VaultViewer({ invoiceId, licenseKey }: { invoiceId: string; licenseKey: string }) {
    const [items, setItems] = useState<VaultItem[]>([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [activeAccess, setActiveAccess] = useState<{ info: AccessInfo; blobUrl: string } | null>(null);

    // Load public vault listing on mount
    useEffect(() => {
        const load = async () => {
            try {
                const res = await fetch(`${API}/vault/contents`);
                if (res.ok) setItems(await res.json());
            } catch {
                // ignore — empty list is fine
            }
        };
        load();
    }, []);

    const handleView = async (contentId: string) => {
        if (!invoiceId || !licenseKey) {
            setError('Enter your Invoice ID and License Key first.');
            return;
        }
        setLoading(true);
        setError(null);

        try {
            // Step 1: obtain a short-lived access token
            const accessRes = await fetch(
                `${API}/vault/access/${contentId}?invoice_id=${encodeURIComponent(invoiceId)}&license_key=${encodeURIComponent(licenseKey)}`,
                { method: 'POST' },
            );
            if (accessRes.status === 409) {
                setError('Session limit reached. Contact your administrator.');
                return;
            }
            if (!accessRes.ok) {
                const err = await accessRes.json().catch(() => ({ detail: 'Access denied' }));
                setError(err.detail ?? 'Access denied');
                return;
            }
            const accessInfo: AccessInfo = await accessRes.json();

            // Step 2: stream the decrypted content into a Blob URL
            const streamRes = await fetch(`${API}/vault/stream/${accessInfo.access_token}`);
            if (!streamRes.ok) {
                setError('Failed to stream content — the access token may have expired.');
                return;
            }
            const blob = await streamRes.blob();
            const blobUrl = URL.createObjectURL(blob);

            // Revoke previous Blob URL to free memory
            if (activeAccess?.blobUrl) URL.revokeObjectURL(activeAccess.blobUrl);
            setActiveAccess({ info: accessInfo, blobUrl });
        } catch {
            setError('Network error — could not reach the vault.');
        } finally {
            setLoading(false);
        }
    };

    const handleClose = () => {
        if (activeAccess?.blobUrl) URL.revokeObjectURL(activeAccess.blobUrl);
        setActiveAccess(null);
    };

    return (
        <div className="space-y-4">
            <h2 className="text-lg font-semibold text-white">Vault Contents</h2>

            {error && (
                <div className="bg-red-900/30 border border-red-700 rounded px-4 py-2 text-red-300 text-sm">
                    {error}
                </div>
            )}

            {/* Active content viewer */}
            {activeAccess && (
                <div className="bg-slate-800 rounded-xl border border-slate-700 p-4 space-y-3">
                    <div className="flex items-center justify-between">
                        <p className="text-sm font-medium text-slate-200">{activeAccess.info.filename}</p>
                        <button
                            onClick={handleClose}
                            className="text-xs text-slate-400 hover:text-slate-200 transition"
                        >
                            ✕ Close
                        </button>
                    </div>
                    <ContentRenderer
                        url={activeAccess.blobUrl}
                        contentType={activeAccess.info.content_type}
                        filename={activeAccess.info.filename}
                    />
                    <p className="text-[10px] text-slate-500 font-mono">
                        session #{activeAccess.info.session_id} · {formatBytes(activeAccess.info.size_bytes)} ·{' '}
                        {activeAccess.info.content_type}
                    </p>
                </div>
            )}

            {/* Item list */}
            <div className="overflow-x-auto rounded-xl border border-slate-700">
                <table className="w-full text-sm">
                    <thead className="bg-slate-800 text-slate-400 text-xs uppercase tracking-wide">
                        <tr>
                            <th className="px-4 py-2 text-left">Filename</th>
                            <th className="px-4 py-2 text-left">Type</th>
                            <th className="px-4 py-2 text-left">Size</th>
                            <th className="px-4 py-2 text-left">Description</th>
                            <th className="px-4 py-2 text-left">Action</th>
                        </tr>
                    </thead>
                    <tbody>
                        {items.length === 0 && (
                            <tr>
                                <td colSpan={5} className="px-4 py-6 text-center text-slate-500 text-xs">
                                    No content in the vault yet.
                                </td>
                            </tr>
                        )}
                        {items.map((item) => (
                            <tr key={item.content_id} className="border-t border-slate-800 hover:bg-slate-800/40 transition">
                                <td className="px-4 py-2 font-mono text-xs text-slate-200">{item.filename}</td>
                                <td className="px-4 py-2 text-slate-400 text-xs">{item.content_type}</td>
                                <td className="px-4 py-2 text-slate-400 text-xs whitespace-nowrap">
                                    {formatBytes(item.size_bytes)}
                                </td>
                                <td className="px-4 py-2 text-slate-400 text-xs max-w-[160px] truncate">
                                    {item.description ?? <span className="text-slate-600">—</span>}
                                </td>
                                <td className="px-4 py-2">
                                    <button
                                        onClick={() => handleView(item.content_id)}
                                        disabled={loading}
                                        className="text-xs bg-blue-600 hover:bg-blue-500 disabled:opacity-50 px-3 py-1 rounded font-bold transition-all active:scale-95"
                                    >
                                        {loading ? '…' : 'View'}
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
