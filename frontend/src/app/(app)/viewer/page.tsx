'use client';
import dynamic from 'next/dynamic';

const SecureContent = dynamic(() => import('@/components/SecureContent'), {
  ssr: false,
  loading: () => (
    <div className="flex items-center justify-center h-64">
      <div className="w-8 h-8 border-2 border-brand-accent border-t-transparent rounded-full animate-spin" />
    </div>
  ),
});

export default function ViewerPage() {
  return (
    <div>
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-text-main tracking-tight">Secure Viewer</h1>
        <p className="text-text-muted text-sm mt-1">
          WebAssembly-protected playback with anti-capture noise layer.
        </p>
      </div>
      <div className="bg-brand-surface rounded-2xl border border-slate-800 overflow-hidden shadow-2xl">
        <SecureContent />
      </div>
    </div>
  );
}
