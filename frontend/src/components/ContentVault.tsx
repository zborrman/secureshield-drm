'use client';

import { useEffect, useRef, useState } from 'react';

const API = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8001';

interface VaultItem {
    content_id: string;
    filename: string;
    content_type: string;
    size_bytes: number;
    description: string | null;
    uploaded_at: string;
    linked_licenses?: LinkedLicense[];
}

interface LinkedLicense {
    invoice_id: string;
    owner_id: string;
    is_paid: boolean;
    granted_at: string;
}

function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

interface ContentVaultProps {
    adminKey: string;
    /** When set, uses /tenant/vault/* endpoints scoped to this tenant slug. */
    tenantSlug?: string;
}

export default function ContentVault({ adminKey, tenantSlug }: ContentVaultProps) {
    const [items, setItems] = useState<VaultItem[]>([]);
    const [uploading, setUploading] = useState(false);
    const [uploadError, setUploadError] = useState<string | null>(null);
    const [description, setDescription] = useState('');
    const fileRef = useRef<HTMLInputElement>(null);

    // Which content_id has the license panel open
    const [openLicensePanel, setOpenLicensePanel] = useState<string | null>(null);
    const [grantInput, setGrantInput] = useState('');
    const [grantError, setGrantError] = useState<string | null>(null);
    const [grantLoading, setGrantLoading] = useState(false);

    // Route prefix: /tenant/vault when a tenantSlug is provided, /admin/vault otherwise
    const vaultBase = tenantSlug ? `${API}/tenant/vault` : `${API}/admin/vault`;
    const headers: Record<string, string> = tenantSlug
        ? { 'X-Tenant-ID': tenantSlug, 'X-Admin-Key': adminKey }
        : { 'X-Admin-Key': adminKey };

    const fetchLinkedLicenses = async (contentId: string): Promise<LinkedLicense[]> => {
        try {
            const res = await fetch(`${API}/admin/vault/${contentId}/licenses`, { headers });
            if (res.ok) return await res.json();
        } catch { /* ignore */ }
        return [];
    };

    const fetchItems = async () => {
        try {
            const listUrl = tenantSlug ? `${API}/tenant/vault/contents` : `${API}/admin/vault/contents`;
            const res = await fetch(listUrl, { headers });
            if (!res.ok) return;
            const raw: VaultItem[] = await res.json();
            // Fetch linked license counts in parallel (admin only — tenant uses open model)
            if (!tenantSlug) {
                const enriched = await Promise.all(
                    raw.map(async (item) => ({
                        ...item,
                        linked_licenses: await fetchLinkedLicenses(item.content_id),
                    }))
                );
                setItems(enriched);
            } else {
                setItems(raw);
            }
        } catch { /* silently fail — list stays stale */ }
    };

    useEffect(() => {
        if (adminKey) fetchItems();
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [adminKey, tenantSlug]);

    const handleUpload = async () => {
        const file = fileRef.current?.files?.[0];
        if (!file) return;
        setUploading(true);
        setUploadError(null);

        const form = new FormData();
        form.append('file', file);

        try {
            const res = await fetch(
                `${vaultBase}/upload?description=${encodeURIComponent(description)}`,
                { method: 'POST', headers, body: form },
            );
            if (!res.ok) {
                const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
                setUploadError(err.detail ?? 'Upload failed');
            } else {
                setDescription('');
                if (fileRef.current) fileRef.current.value = '';
                await fetchItems();
            }
        } catch {
            setUploadError('Network error during upload');
        } finally {
            setUploading(false);
        }
    };

    const handleDelete = async (contentId: string, filename: string) => {
        if (!confirm(`Delete "${filename}" from the vault? This cannot be undone.`)) return;
        try {
            const res = await fetch(`${vaultBase}/${contentId}`, {
                method: 'DELETE',
                headers,
            });
            if (res.ok) {
                setItems((prev) => prev.filter((i) => i.content_id !== contentId));
                if (openLicensePanel === contentId) setOpenLicensePanel(null);
            }
        } catch { /* ignore */ }
    };

    const handleGrantLicense = async (contentId: string) => {
        const invoiceId = grantInput.trim();
        if (!invoiceId) return;
        setGrantLoading(true);
        setGrantError(null);
        try {
            const res = await fetch(
                `${API}/admin/licenses/${encodeURIComponent(invoiceId)}/content/${contentId}`,
                { method: 'POST', headers },
            );
            if (!res.ok) {
                const err = await res.json().catch(() => ({ detail: 'Failed to grant access' }));
                setGrantError(err.detail ?? 'Failed to grant access');
            } else {
                setGrantInput('');
                // Refresh linked licenses for this item
                const updated = await fetchLinkedLicenses(contentId);
                setItems((prev) =>
                    prev.map((i) => i.content_id === contentId ? { ...i, linked_licenses: updated } : i)
                );
            }
        } catch {
            setGrantError('Network error');
        } finally {
            setGrantLoading(false);
        }
    };

    const handleRevokeLicense = async (contentId: string, invoiceId: string) => {
        try {
            const res = await fetch(
                `${API}/admin/licenses/${encodeURIComponent(invoiceId)}/content/${contentId}`,
                { method: 'DELETE', headers },
            );
            if (res.ok) {
                const updated = await fetchLinkedLicenses(contentId);
                setItems((prev) =>
                    prev.map((i) => i.content_id === contentId ? { ...i, linked_licenses: updated } : i)
                );
            }
        } catch { /* ignore */ }
    };

    return (
        <div className="space-y-4">
            <h2 className="text-lg font-semibold text-white">Content Vault</h2>
            <p className="text-xs text-slate-400">
                Files are AES-256-GCM encrypted before reaching S3. Keys are never stored in plaintext.
                Content with no linked licenses is accessible by any valid license. Once a license is
                linked, only those licenses may stream it.
            </p>

            {/* Upload panel */}
            <div className="bg-slate-800 rounded-xl border border-slate-700 p-4 space-y-3">
                <p className="text-sm font-medium text-slate-300">Upload Encrypted File</p>
                <div className="flex flex-col gap-2">
                    <input
                        ref={fileRef}
                        type="file"
                        className="text-sm text-slate-400 file:mr-3 file:py-1 file:px-3 file:rounded file:border-0 file:bg-slate-700 file:text-slate-200 file:text-xs file:cursor-pointer"
                    />
                    <input
                        type="text"
                        placeholder="Description (optional)"
                        value={description}
                        onChange={(e) => setDescription(e.target.value)}
                        className="bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-sm focus:border-blue-500 outline-none transition"
                    />
                    <button
                        onClick={handleUpload}
                        disabled={uploading}
                        className="self-start bg-blue-600 hover:bg-blue-500 disabled:opacity-50 px-4 py-1.5 rounded text-sm font-bold transition-all active:scale-95"
                    >
                        {uploading ? 'Encrypting & Uploading…' : 'Upload to Vault'}
                    </button>
                    {uploadError && (
                        <p className="text-xs text-red-400">{uploadError}</p>
                    )}
                </div>
            </div>

            {/* Vault contents table */}
            <div className="overflow-x-auto rounded-xl border border-slate-700">
                <table className="w-full text-sm">
                    <thead className="bg-slate-800 text-slate-400 text-xs uppercase tracking-wide">
                        <tr>
                            <th className="px-4 py-2 text-left">Filename</th>
                            <th className="px-4 py-2 text-left">Type</th>
                            <th className="px-4 py-2 text-left">Size</th>
                            <th className="px-4 py-2 text-left">Description</th>
                            <th className="px-4 py-2 text-left">Uploaded</th>
                            {!tenantSlug && <th className="px-4 py-2 text-left">Licenses</th>}
                            <th className="px-4 py-2 text-left">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {items.length === 0 && (
                            <tr>
                                <td colSpan={tenantSlug ? 6 : 7} className="px-4 py-6 text-center text-slate-500 text-xs">
                                    Vault is empty — upload the first file above.
                                </td>
                            </tr>
                        )}
                        {items.map((item) => (
                            <>
                                <tr key={item.content_id} className="border-t border-slate-800 hover:bg-slate-800/40 transition">
                                    <td className="px-4 py-2 font-mono text-xs text-slate-200 max-w-[180px] truncate">
                                        {item.filename}
                                    </td>
                                    <td className="px-4 py-2 text-slate-400 text-xs">{item.content_type}</td>
                                    <td className="px-4 py-2 text-slate-400 text-xs whitespace-nowrap">
                                        {formatBytes(item.size_bytes)}
                                    </td>
                                    <td className="px-4 py-2 text-slate-400 text-xs max-w-[160px] truncate">
                                        {item.description ?? <span className="text-slate-600">—</span>}
                                    </td>
                                    <td className="px-4 py-2 text-slate-400 text-xs whitespace-nowrap">
                                        {new Date(item.uploaded_at).toLocaleString()}
                                    </td>
                                    {!tenantSlug && (
                                        <td className="px-4 py-2">
                                            <button
                                                onClick={() => {
                                                    setOpenLicensePanel(
                                                        openLicensePanel === item.content_id ? null : item.content_id
                                                    );
                                                    setGrantInput('');
                                                    setGrantError(null);
                                                }}
                                                className="text-xs text-slate-300 hover:text-white transition"
                                            >
                                                {item.linked_licenses && item.linked_licenses.length > 0 ? (
                                                    <span className="bg-blue-900/60 text-blue-300 px-2 py-0.5 rounded-full">
                                                        {item.linked_licenses.length} linked
                                                    </span>
                                                ) : (
                                                    <span className="bg-slate-700 text-slate-400 px-2 py-0.5 rounded-full">
                                                        open
                                                    </span>
                                                )}
                                            </button>
                                        </td>
                                    )}
                                    <td className="px-4 py-2">
                                        <button
                                            onClick={() => handleDelete(item.content_id, item.filename)}
                                            className="text-xs text-red-400 hover:text-red-300 transition"
                                        >
                                            Delete
                                        </button>
                                    </td>
                                </tr>

                                {/* License management panel — expanded row */}
                                {!tenantSlug && openLicensePanel === item.content_id && (
                                    <tr key={`${item.content_id}-licenses`} className="border-t border-slate-700 bg-slate-900/60">
                                        <td colSpan={7} className="px-6 py-3">
                                            <p className="text-xs font-semibold text-slate-300 mb-2">
                                                License Access Control —{' '}
                                                <span className="font-normal text-slate-400">
                                                    {item.linked_licenses?.length === 0
                                                        ? 'Open (any valid license can stream this file). Add a license below to restrict access.'
                                                        : `${item.linked_licenses?.length} license(s) may stream this file.`}
                                                </span>
                                            </p>

                                            {/* Linked licenses list */}
                                            {item.linked_licenses && item.linked_licenses.length > 0 && (
                                                <ul className="mb-3 space-y-1">
                                                    {item.linked_licenses.map((ll) => (
                                                        <li key={ll.invoice_id} className="flex items-center gap-3 text-xs">
                                                            <span className="font-mono text-slate-200">{ll.invoice_id}</span>
                                                            <span className="text-slate-500">{ll.owner_id}</span>
                                                            <span className={ll.is_paid ? 'text-green-400' : 'text-yellow-400'}>
                                                                {ll.is_paid ? 'paid' : 'unpaid'}
                                                            </span>
                                                            <span className="text-slate-600 text-[10px]">
                                                                granted {new Date(ll.granted_at).toLocaleDateString()}
                                                            </span>
                                                            <button
                                                                onClick={() => handleRevokeLicense(item.content_id, ll.invoice_id)}
                                                                className="text-red-400 hover:text-red-300 transition ml-auto"
                                                            >
                                                                Revoke
                                                            </button>
                                                        </li>
                                                    ))}
                                                </ul>
                                            )}

                                            {/* Grant form */}
                                            <div className="flex items-center gap-2">
                                                <input
                                                    type="text"
                                                    placeholder="Invoice ID to grant access"
                                                    value={grantInput}
                                                    onChange={(e) => setGrantInput(e.target.value)}
                                                    onKeyDown={(e) => e.key === 'Enter' && handleGrantLicense(item.content_id)}
                                                    className="bg-slate-950 border border-slate-700 rounded px-3 py-1 text-xs focus:border-blue-500 outline-none transition w-56"
                                                />
                                                <button
                                                    onClick={() => handleGrantLicense(item.content_id)}
                                                    disabled={grantLoading || !grantInput.trim()}
                                                    className="bg-green-700 hover:bg-green-600 disabled:opacity-50 px-3 py-1 rounded text-xs font-semibold transition"
                                                >
                                                    {grantLoading ? '…' : 'Grant'}
                                                </button>
                                            </div>
                                            {grantError && (
                                                <p className="text-xs text-red-400 mt-1">{grantError}</p>
                                            )}
                                        </td>
                                    </tr>
                                )}
                            </>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
