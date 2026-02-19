'use client';
import { useEffect, useState } from 'react';
import dynamic from 'next/dynamic';

const SecureContent = dynamic(() => import('@/components/SecureContent'), {
  ssr: false,
  loading: () => (
    <div className="flex items-center justify-center h-64">
      <div className="w-8 h-8 border-2 border-brand-primary border-t-transparent rounded-full animate-spin" />
    </div>
  ),
});

export default function Dashboard() {
  const [invoiceId, setInvoiceId] = useState<string | null>(null);

  useEffect(() => {
    setInvoiceId(localStorage.getItem('invoice_id'));
  }, []);

  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-text-main tracking-tight">Secure Content Viewer</h1>
        <p className="text-text-muted text-sm mt-1">
          Content is protected by forensic watermarking and anti-capture technology.
          {invoiceId && (
            <span className="ml-2 font-mono text-brand-accent">#{invoiceId}</span>
          )}
        </p>
      </div>

      <div className="bg-brand-surface rounded-2xl border border-slate-800 overflow-hidden shadow-2xl">
        <SecureContent />
      </div>
    </div>
  );
}
