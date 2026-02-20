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
}

function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function ContentVault({ adminKey }: { adminKey: string }) {
    const [items, setItems] = useState<VaultItem[]>([]);
    const [uploading, setUploading] = useState(false);
    const [uploadError, setUploadError] = useState<string | null>(null);
    const [description, setDescription] = useState('');
    const fileRef = useRef<HTMLInputElement>(null);

    const headers = { 'X-Admin-Key': adminKey };

    const fetchItems = async () => {
        try {
            const res = await fetch(`${API}/admin/vault/contents`, { headers });
            if (res.ok) setItems(await res.json());
        } catch {
            // silently fail — list stays stale
        }
    };

    useEffect(() => {
        if (adminKey) fetchItems();
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [adminKey]);

    const handleUpload = async () => {
        const file = fileRef.current?.files?.[0];
        if (!file) return;
        setUploading(true);
        setUploadError(null);

        const form = new FormData();
        form.append('file', file);

        try {
            const res = await fetch(
                `${API}/admin/vault/upload?description=${encodeURIComponent(description)}`,
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
            const res = await fetch(`${API}/admin/vault/${contentId}`, {
                method: 'DELETE',
                headers,
            });
            if (res.ok) setItems((prev) => prev.filter((i) => i.content_id !== contentId));
        } catch {
            // ignore
        }
    };

    return (
        <div className="space-y-4">
            <h2 className="text-lg font-semibold text-white">Content Vault</h2>
            <p className="text-xs text-slate-400">
                Files are AES-256-GCM encrypted before reaching S3. Keys are never stored in plaintext.
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
                            <th className="px-4 py-2 text-left">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {items.length === 0 && (
                            <tr>
                                <td colSpan={6} className="px-4 py-6 text-center text-slate-500 text-xs">
                                    Vault is empty — upload the first file above.
                                </td>
                            </tr>
                        )}
                        {items.map((item) => (
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
                                <td className="px-4 py-2">
                                    <button
                                        onClick={() => handleDelete(item.content_id, item.filename)}
                                        className="text-xs text-red-400 hover:text-red-300 transition"
                                    >
                                        Delete
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
